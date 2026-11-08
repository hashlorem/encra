//! Agent access, end to end over a real socket.

use crate::credentials::CopyField;
use crate::paths::*;
use crate::commands::agent::*;
use crate::vault;
use crate::{agent, fields};
use super::support::*;

#[test]
fn test_agent_request_approved_delivers_value_and_logs_without_it() {
    let rig = agent_rig("agent-approve", agent::server::REQUEST_TIMEOUT);
    let client = rig.ask_in_background(&["encra://github.com#password", "encra://github.com#username"]);
    let info = rig.wait_for_pending();
    assert_eq!(info.agent, "test-agent");
    assert!(!info.inline_script);

    decide_agent_request(&rig.db.lock().unwrap(), &rig.dek, &rig.hub, &info.id, true, &Default::default(), false).unwrap();
    let response = client.join().unwrap().unwrap();
    let (password, username) = match &response {
        agent::protocol::Response::Approved(_) => (
            approved_value(client_clone(&response), "encra://github.com#password"),
            approved_value(client_clone(&response), "encra://github.com#username"),
        ),
        other => panic!("{other:?}"),
    };
    assert_eq!(password, "gh_p@$$w0rd");
    assert_eq!(username, "dev@example.com");

    // One decision only: the request is gone.
    assert!(rig.hub.pending().is_empty());
    assert!(decide_agent_request(&rig.db.lock().unwrap(), &rig.dek, &rig.hub, &info.id, true, &Default::default(), false).is_err());

    let actions = rig.actions();
    assert!(actions.contains(&"agent_request".into()) && actions.contains(&"agent_approved".into()));
    // Neither the value nor the login's name is anywhere in the file.
    let path = rig.dir.join(CURRENT_DATABASE_NAME);
    let bytes = std::fs::read(&path).unwrap();
    let contains = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
    assert!(!contains("gh_p@$$w0rd"), "the value must never be written to the vault file");
    assert!(!contains("github.com"), "login names must not survive in the file, free pages included");
    rig.finish();
}

#[test]
fn test_agent_request_denied_sealed_timed_out_or_abandoned_gets_nothing() {
    // Denied.
    let rig = agent_rig("agent-deny", agent::server::REQUEST_TIMEOUT);
    let client = rig.ask_in_background(&["encra://github.com"]);
    let info = rig.wait_for_pending();
    decide_agent_request(&rig.db.lock().unwrap(), &rig.dek, &rig.hub, &info.id, false, &Default::default(), false).unwrap();
    assert!(matches!(client.join().unwrap().unwrap(), agent::protocol::Response::Denied));
    assert!(rig.actions().contains(&"agent_denied".into()));

    // Sealed while waiting: cancelled, nothing sent.
    let client = rig.ask_in_background(&["encra://github.com"]);
    rig.wait_for_pending();
    rig.hub.cancel_all("the vault was sealed");
    assert!(matches!(client.join().unwrap().unwrap(), agent::protocol::Response::Error(m) if m == "the vault was sealed"));
    assert!(rig.hub.pending().is_empty());

    // The caller hangs up before an answer.
    {
        use std::io::Write;
        let mut stream = std::os::unix::net::UnixStream::connect(&rig.socket).unwrap();
        let request = agent::protocol::Request {
            agent: "quitter".into(), argv: vec!["/usr/bin/env".into()], executable: "/usr/bin/env".into(),
            cwd: "/private/tmp".into(), references: vec!["encra://github.com".into()],
        };
        agent::protocol::write_request(&mut stream, &request).unwrap();
        stream.flush().unwrap();
        rig.wait_for_pending();
    }
    for _ in 0..100 {
        if rig.hub.pending().is_empty() { break; }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(rig.hub.pending().is_empty(), "an abandoned request must be dropped");
    assert!(rig.actions().contains(&"agent_cancelled".into()));
    rig.finish();

    // Nobody answers in time.
    let rig = agent_rig("agent-timeout", std::time::Duration::from_millis(300));
    let client = rig.ask_in_background(&["encra://github.com"]);
    assert!(matches!(client.join().unwrap().unwrap(), agent::protocol::Response::Error(m) if m == "no answer in time"));
    assert!(rig.actions().contains(&"agent_timeout".into()));
    rig.finish();
}

#[test]
fn test_agent_references_resolve_exactly_or_not_at_all() {
    let rig = agent_rig("agent-refs", agent::server::REQUEST_TIMEOUT);
    {
        let db = rig.db.lock().unwrap();
        use agent::refs::{login_id, parse, Target};
        assert_eq!(parse("encra://github.com").unwrap().field, CopyField::Password);
        assert_eq!(parse("encra://id/c2#url").unwrap().target, Target::Id("c2".into()));
        assert!(parse("encra://#password").is_err());
        assert!(parse("https://github.com").is_err());
        assert_eq!(login_id(&db, &rig.dek, &Target::Name("aws".into())).unwrap(), "c2");
        assert!(login_id(&db, &rig.dek, &Target::Name("GitHub.com".into())).is_err(), "names match exactly");
        assert!(login_id(&db, &rig.dek, &Target::Name("nope".into())).is_err());

        // Two logins with the same name: refused, and the id form still works.
        let sealed = fields::seal(&rig.dek, "credentials", "c3", "service", "aws").unwrap();
        let password = fields::seal(&rig.dek, "credentials", "c3", "password_encrypted", "second").unwrap();
        db.execute("INSERT INTO credentials (id, service, username, password_encrypted) VALUES ('c3', ?1, '', ?2)", [&sealed, &password]).unwrap();
        assert!(login_id(&db, &rig.dek, &Target::Name("aws".into())).unwrap_err().contains("2 logins"));
        assert_eq!(agent::refs::resolve(&db, &rig.dek, "encra://id/c3", None).unwrap().1.as_str(), "second");

        // The 2FA code is made at resolve time; a login without 2FA is refused.
        assert_eq!(parse("encra://aws#totp").unwrap().field, CopyField::Totp);
        assert!(agent::refs::resolve(&db, &rig.dek, "encra://id/c3#totp", None).unwrap_err().contains("no 2FA"));
        let secret = fields::seal(&rig.dek, "credentials", "c3", "totp_secret", "JBSWY3DPEHPK3PXPJBSWY3DP").unwrap();
        db.execute("UPDATE credentials SET totp_secret = ?1 WHERE id = 'c3'", [&secret]).unwrap();
        let (login, code) = agent::refs::resolve(&db, &rig.dek, "encra://id/c3#totp", None).unwrap();
        assert_eq!(login, "c3");
        assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()), "a six-digit code");
    }

    // An approval that cannot resolve sends an error, never a partial set.
    let client = rig.ask_in_background(&["encra://github.com", "encra://aws"]);
    let info = rig.wait_for_pending();
    assert!(decide_agent_request(&rig.db.lock().unwrap(), &rig.dek, &rig.hub, &info.id, true, &Default::default(), false).is_err());
    assert!(matches!(client.join().unwrap().unwrap(), agent::protocol::Response::Error(_)));
    rig.finish();
}

#[test]
fn test_agent_picked_and_remembered_logins() {
    let rig = agent_rig("agent-pick", agent::server::REQUEST_TIMEOUT);
    let preview = |r: &str| agent::refs::preview(&rig.db.lock().unwrap(), &rig.dek, r);
    assert_eq!(preview("encra://github.com").status, "found");
    assert_eq!(preview("encra://github.com").login.as_deref(), Some("github.com"));
    assert_eq!(preview("encra://GitHub").status, "missing");

    // The approver picks "github.com" for "GitHub" and remembers it.
    let client = rig.ask_in_background(&["encra://GitHub#password"]);
    let info = rig.wait_for_pending();
    let choices = std::collections::HashMap::from([("encra://GitHub#password".to_string(), "c1".to_string())]);
    decide_agent_request(&rig.db.lock().unwrap(), &rig.dek, &rig.hub, &info.id, true, &choices, true).unwrap();
    assert_eq!(approved_value(client.join().unwrap().unwrap(), "encra://GitHub#password"), "gh_p@$$w0rd");

    // Next time "GitHub" resolves on its own, and the saved name is sealed.
    let found = preview("encra://GitHub#username");
    assert_eq!((found.status, found.login_id.as_deref()), ("found", Some("c1")));
    let stored: String = rig.db.lock().unwrap().query_row("SELECT name FROM agent_aliases", [], |r| r.get(0)).unwrap();
    assert!(vault::is_bound(&stored) && !stored.contains("GitHub"));

    // A pick that isn't a real login is refused, and sends nothing.
    let client = rig.ask_in_background(&["encra://nope"]);
    let info = rig.wait_for_pending();
    let bogus = std::collections::HashMap::from([("encra://nope".to_string(), "not-a-login".to_string())]);
    assert!(decide_agent_request(&rig.db.lock().unwrap(), &rig.dek, &rig.hub, &info.id, true, &bogus, true).is_err());
    assert!(matches!(client.join().unwrap().unwrap(), agent::protocol::Response::Error(_)));

    // Deleting the login drops its remembered match.
    {
        let db = rig.db.lock().unwrap();
        db.execute("DELETE FROM credentials WHERE id = 'c1'", []).unwrap();
        agent::refs::forget_login(&db, "c1").unwrap();
        let left: i64 = db.query_row("SELECT COUNT(*) FROM agent_aliases", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 0);
    }
    assert_eq!(preview("encra://GitHub").status, "missing");
    rig.finish();
}

#[test]
fn test_agent_server_refuses_malformed_requests_and_a_second_instance() {
    let rig = agent_rig("agent-malformed", agent::server::REQUEST_TIMEOUT);
    // Garbage instead of a frame: an error back, and nothing queued.
    {
        use std::io::{Read, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(&rig.socket).unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert!(!reply.is_empty());
    }
    // A request with no references, or a bad one, is refused up front.
    for references in [vec![], vec!["encra://github.com#pin".to_string()]] {
        let request = agent::protocol::Request {
            agent: "x".into(), argv: vec!["/usr/bin/env".into()], executable: "/usr/bin/env".into(),
            cwd: "/private/tmp".into(), references,
        };
        assert!(matches!(agent::client::ask(&rig.socket, &request).unwrap(), agent::protocol::Response::Error(_)));
    }
    assert!(rig.hub.pending().is_empty());

    // The socket is owner-only, and a second server cannot take over.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&rig.socket).unwrap().permissions().mode() & 0o777, 0o600);
    let other = agent::server::Hub::new(Box::new(|_, _| {}), Box::new(|_, _| {}), agent::server::REQUEST_TIMEOUT);
    assert!(other.start(rig.socket.parent().unwrap()).is_err());
    drop(other);
    rig.finish();
}
