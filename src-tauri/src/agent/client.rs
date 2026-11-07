//! `encra run`: Encra's own binary in command-line mode.
//!
//!   encra run [--name AGENT] [--env-file FILE]... [--env KEY=VALUE]... -- COMMAND [ARGS]...
//!
//! Env values written as `encra://Login#field` are references. They are sent
//! to the running app, a person approves or denies, and on approval this
//! process replaces itself with COMMAND (exec), with the values in its
//! environment. Whoever ran `encra run` sees the command's output, never the
//! values, unless the command prints them.

use std::collections::BTreeSet;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::protocol::{self, Request, Response};
use super::{refs, sock};

const USAGE: &str = "usage: encra run [--name AGENT] [--env-file FILE]... [--env KEY=VALUE]... -- COMMAND [ARGS]...

Values written as encra://Login#field (password, username, url or totp) are
filled in after you approve the request in Encra. A totp code is made at that
moment and lasts until its 30-second window ends.";

/// Exit code when the request is denied, distinct from other failures.
const DENIED: i32 = 77;

struct Args {
    agent: Option<String>,
    env_files: Vec<PathBuf>,
    inline_env: Vec<String>,
    command: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut parsed = Args { agent: None, env_files: Vec::new(), inline_env: Vec::new(), command: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let value = |i: usize| args.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value", args[i]));
        match args[i].as_str() {
            "--" => {
                parsed.command = args[i + 1..].to_vec();
                break;
            }
            "--name" => parsed.agent = Some(value(i)?),
            "--env-file" => parsed.env_files.push(PathBuf::from(value(i)?)),
            "--env" => parsed.inline_env.push(value(i)?),
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown option {other}\n\n{USAGE}")),
        }
        i += 2;
    }
    if parsed.command.is_empty() {
        return Err(USAGE.into());
    }
    Ok(parsed)
}

/// One `KEY=VALUE` line from an env file. Blank lines and `#` comments are
/// skipped; `export ` and matching quotes are allowed.
fn parse_env_line(line: &str) -> Result<Option<(String, String)>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=').ok_or_else(|| format!("not KEY=VALUE: {line}"))?;
    let key = key.trim();
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("invalid variable name: {key}"));
    }
    let value = value.trim();
    let value = value
        .strip_prefix('"').and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
    Ok(Some((key.to_string(), value.to_string())))
}

/// Variables that make a program load or run extra code. An agent could set
/// them to slip its own code into an approved command, which would then read
/// the secret, so they never reach the child.
const CODE_INJECTION_VARS: &[&str] = &[
    "BASH_ENV", "ENV", "ZDOTDIR", "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME",
    "PERL5OPT", "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GIT_SSH_COMMAND",
];

fn is_stripped(key: &str) -> bool {
    key.starts_with("ENCRA_") || key.starts_with("DYLD_") || key.starts_with("LD_") || CODE_INJECTION_VARS.contains(&key)
}

/// The child's environment before references are filled in, and the distinct
/// references it needs. ENCRA_* and code-loading variables never reach the
/// child.
type Env = Vec<(String, String)>;

pub fn build_env(base: Env, files: &[String], inline: &[String]) -> Result<(Env, Vec<String>), String> {
    let mut env: Env = base.into_iter().filter(|(key, _)| !is_stripped(key)).collect();
    let mut set = |key: String, value: String| {
        env.retain(|(k, _)| *k != key);
        env.push((key, value));
    };
    for contents in files {
        for line in contents.lines() {
            if let Some((key, value)) = parse_env_line(line)? {
                set(key, value);
            }
        }
    }
    for entry in inline {
        let (key, value) = parse_env_line(entry)?.ok_or("--env needs KEY=VALUE")?;
        set(key, value);
    }
    if let Some((key, _)) = env.iter().find(|(key, _)| is_stripped(key)) {
        return Err(format!("{key} can't be set through encra run"));
    }
    let mut references = BTreeSet::new();
    for (_, value) in &env {
        if refs::is_reference(value) {
            refs::parse(value)?;
            references.insert(value.trim().to_string());
        }
    }
    Ok((env, references.into_iter().collect()))
}

/// argv[0] as an absolute path with symlinks followed, searching PATH for a
/// bare name, so the dialog shows what will really run.
fn resolve_executable(program: &str, path_var: Option<&str>) -> Result<PathBuf, String> {
    let is_executable = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    };
    let candidate = if program.contains('/') {
        PathBuf::from(program)
    } else {
        path_var
            .unwrap_or_default()
            .split(':')
            .filter(|dir| !dir.is_empty())
            .map(|dir| Path::new(dir).join(program))
            .find(|p| is_executable(p))
            .ok_or_else(|| format!("{program}: command not found"))?
    };
    let real = candidate.canonicalize().map_err(|_| format!("{program}: command not found"))?;
    if !is_executable(&real) {
        return Err(format!("{}: not an executable file", real.display()));
    }
    Ok(real)
}

fn disable_core_dumps() {
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: a valid rlimit struct.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
}

/// Send one request to the app and wait for the answer.
pub fn ask(socket: &Path, request: &Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "Encra isn't running, or Agent access is off (Encra → Settings → Agent access).".to_string())?;
    // The other end must be this same Encra binary, not something that took
    // over the socket path.
    sock::verify_peer(&stream).map_err(|e| format!("refusing to talk to that socket: {e}"))?;
    protocol::write_request(&mut stream, request)?;
    protocol::read_response(&mut stream)
}

fn run(args: &[String]) -> Result<i32, String> {
    disable_core_dumps();
    let args = parse_args(args)?;
    let files = args
        .env_files
        .iter()
        .map(|p| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display())))
        .collect::<Result<Vec<_>, _>>()?;
    let agent = args.agent.clone().or_else(|| std::env::var("ENCRA_AGENT").ok());
    let (mut env, references) = build_env(std::env::vars().collect(), &files, &args.inline_env)?;
    let path_var = env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.clone());
    let executable = resolve_executable(&args.command[0], path_var.as_deref())?;

    if !references.is_empty() {
        let cwd = std::env::current_dir().and_then(|d| d.canonicalize()).map_err(|e| e.to_string())?;
        let agent = agent.unwrap_or_else(|| {
            // SAFETY: getpid cannot fail.
            let me = unsafe { libc::getpid() };
            sock::process_chain(me).first().map(|p| p.split(" (").next().unwrap_or("unknown").to_string()).unwrap_or_else(|| "unknown".into())
        });
        let request = Request {
            agent,
            argv: args.command.clone(),
            executable: executable.display().to_string(),
            cwd: cwd.display().to_string(),
            references,
        };
        eprintln!("encra: waiting for you to approve in Encra…");
        match ask(&sock::socket_path(&sock::default_dir()), &request)? {
            Response::Approved(values) => {
                for (_, value) in env.iter_mut().filter(|(_, v)| refs::is_reference(v)) {
                    let wanted = value.trim().to_string();
                    let (_, secret) = values.iter().find(|(r, _)| *r == wanted).ok_or("Encra's answer is missing a value")?;
                    let text = Zeroizing::new(String::from_utf8(secret.to_vec()).map_err(|_| "a value is not valid text")?);
                    *value = text.as_str().to_owned();
                }
            }
            Response::Denied => {
                eprintln!("encra: request denied");
                return Ok(DENIED);
            }
            Response::Error(message) => return Err(message),
        }
    }

    let error = std::process::Command::new(&executable)
        .arg0(&args.command[0])
        .args(&args.command[1..])
        .env_clear()
        .envs(env)
        .exec();
    Err(format!("{}: {error}", executable.display()))
}

/// Entry point for `encra run ...`. Returns only on failure.
pub fn main(args: &[String]) -> i32 {
    match run(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("encra: {message}");
            if message.starts_with("usage:") { 2 } else { 1 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_files_and_references() {
        let base = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("ENCRA_AGENT".to_string(), "claude".to_string()),
            ("ENCRA_DATA_DIR".to_string(), "/tmp/x".to_string()),
        ];
        let file = "# deploy\nexport TOKEN=\"encra://GitHub#password\"\nUSER=encra://GitHub#username\n\nPLAIN='hello world'\nAGAIN=encra://GitHub#password\n";
        let (env, references) = build_env(base, &[file.to_string()], &["REGION=ap-southeast-1".to_string()]).unwrap();

        assert!(env.iter().all(|(k, _)| !k.starts_with("ENCRA_")), "ENCRA_* must never reach the child");
        assert!(env.contains(&("PLAIN".into(), "hello world".into())));
        assert!(env.contains(&("REGION".into(), "ap-southeast-1".into())));
        assert_eq!(references, ["encra://GitHub#password", "encra://GitHub#username"], "deduplicated");
    }

    #[test]
    fn test_bad_env_input_is_refused() {
        assert!(build_env(vec![], &["NOT A LINE".into()], &[]).is_err());
        assert!(build_env(vec![], &["BAD-NAME=1".into()], &[]).is_err());
        assert!(build_env(vec![], &["X=encra://GitHub#pin".into()], &[]).is_err(), "unknown field");
        assert!(build_env(vec![], &[], &["ENCRA_AGENT=sneaky".into()]).is_err(), "cannot smuggle ENCRA_* in");
        assert!(build_env(vec![], &["DYLD_INSERT_LIBRARIES=/tmp/evil.dylib".into()], &[]).is_err());
        assert!(build_env(vec![], &[], &["NODE_OPTIONS=--require /tmp/evil.js".into()]).is_err());
        // Inherited ones are dropped quietly rather than refused.
        let (env, _) = build_env(vec![("BASH_ENV".into(), "/tmp/x".into()), ("HOME".into(), "/Users/me".into())], &[], &[]).unwrap();
        assert_eq!(env, vec![("HOME".to_string(), "/Users/me".to_string())]);
    }

    #[test]
    fn test_arguments() {
        let args = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let parsed = parse_args(&args(&["--name", "claude", "--env-file", ".env", "--", "./deploy.sh", "--prod"])).unwrap();
        assert_eq!(parsed.agent.as_deref(), Some("claude"));
        assert_eq!(parsed.command, ["./deploy.sh", "--prod"]);
        assert!(parse_args(&args(&["--env-file"])).is_err());
        assert!(parse_args(&args(&["--", ])).is_err());
        assert!(parse_args(&args(&["--wat", "--", "ls"])).is_err());
    }

    #[test]
    fn test_executable_is_resolved_through_path_and_symlinks() {
        let env = resolve_executable("env", Some("/nonexistent:/usr/bin")).unwrap();
        assert_eq!(env, PathBuf::from("/usr/bin/env"));
        assert!(resolve_executable("definitely-not-a-command", Some("/usr/bin")).is_err());
        assert!(resolve_executable("/etc/hosts", None).is_err(), "not executable");
    }
}
