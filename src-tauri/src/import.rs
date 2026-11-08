//! Importing logins from another password manager's CSV export.
//!
//! The file is read and parsed here; the webview only ever sees names,
//! usernames and counts. Columns are found by their header names, so the
//! common exports work without a per-app parser:
//!
//!   Chrome, Edge, Brave  name, url, username, password, note
//!   Firefox              url, username, password, httpRealm, formActionOrigin, guid, …
//!   Apple Passwords      Title, URL, Username, Password, Notes, OTPAuth
//!   Bitwarden            folder, favorite, type, name, notes, fields, reprompt,
//!                        login_uri, login_username, login_password, login_totp
//!   1Password            Title, Url, Username, Password, OTPAuth, Favorite, Archived, Tags, Notes
//!
//! Anything else with a password column is read as a generic CSV.

use rusqlite::Connection;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::db::{in_transaction, MAX_FIELD_CHARS, MAX_LONG_FIELD_CHARS};
use crate::{credentials, fields, totp};

pub const MAX_IMPORT_BYTES: u64 = 20 * 1024 * 1024;
pub const MAX_ROWS: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Format {
    Chrome,
    Firefox,
    Apple,
    Bitwarden,
    OnePassword,
    Generic,
}

impl Format {
    /// How the preview names where the file came from.
    pub fn label(self) -> &'static str {
        match self {
            Format::Chrome => "Chrome, Edge or Brave",
            Format::Firefox => "Firefox",
            Format::Apple => "Apple Passwords",
            Format::Bitwarden => "Bitwarden",
            Format::OnePassword => "1Password",
            Format::Generic => "a CSV export",
        }
    }
}

/// One login ready to add. Never serialised.
pub struct Login {
    pub service: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub url: String,
    pub notes: String,
    pub totp: Option<totp::Config>,
}

/// Rows left out, by reason. Counts only.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct Skipped {
    pub no_password: usize,
    pub no_name: usize,
    pub too_long: usize,
    pub not_a_login: usize,
    pub duplicate: usize,
}

pub struct Parsed {
    pub format: Format,
    pub logins: Vec<Login>,
    pub skipped: Skipped,
    /// Logins whose 2FA Encra can't use (Steam Guard, HOTP, a damaged key).
    /// They are added without it.
    pub totp_unusable: usize,
}

struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: usize,
    notes: Option<usize>,
    totp: Option<usize>,
    kind: Option<usize>,
}

fn find(headers: &[String], names: &[&str]) -> Option<usize> {
    names.iter().find_map(|name| headers.iter().position(|h| h == name))
}

fn detect(headers: &[String]) -> Result<(Format, Columns), String> {
    let has = |name: &str| headers.iter().any(|h| h == name);
    let password = find(headers, &["password", "login_password"]).ok_or("this file has no password column, so it doesn't look like a password export")?;
    let columns = Columns {
        title: find(headers, &["title", "name"]),
        url: find(headers, &["url", "login_uri", "website", "uri", "origin", "web site", "site"]),
        username: find(headers, &["username", "login_username", "user name", "user", "login", "email"]),
        password,
        notes: find(headers, &["notes", "note", "comments", "extra"]),
        totp: find(headers, &["otpauth", "login_totp", "totp", "otp", "one-time password", "2fa"]),
        kind: find(headers, &["type"]),
    };
    let format = if has("login_password") && has("login_uri") {
        Format::Bitwarden
    } else if has("httprealm") || has("formactionorigin") {
        Format::Firefox
    } else if has("otpauth") && (has("favorite") || has("archived") || has("tags")) {
        Format::OnePassword
    } else if has("otpauth") && has("title") {
        Format::Apple
    } else if has("name") && has("url") && has("username") && !has("title") {
        Format::Chrome
    } else {
        Format::Generic
    };
    Ok((format, columns))
}

/// "github.com" from "https://www.github.com/login?x=1".
pub fn host_of(url: &str) -> String {
    let rest = url.trim();
    let rest = rest.split_once("://").map(|(_, r)| r).unwrap_or(rest);
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = host.split(':').next().unwrap_or_default();
    host.strip_prefix("www.").unwrap_or(host).to_lowercase()
}

/// Parse an export. Rows that can't be imported are counted, not fatal.
pub fn parse(text: &str) -> Result<Parsed, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|_| "this file isn't a readable CSV")?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let (format, columns) = detect(&headers)?;

    let mut parsed = Parsed { format, logins: Vec::new(), skipped: Skipped::default(), totp_unusable: 0 };
    for (index, record) in reader.records().enumerate() {
        if index >= MAX_ROWS {
            return Err(format!("this file has more than {MAX_ROWS} rows"));
        }
        let record = record.map_err(|_| format!("row {} of this file can't be read", index + 2))?;
        let get = |column: Option<usize>| column.and_then(|i| record.get(i)).map(str::trim).unwrap_or_default().to_string();

        if let Some(kind) = columns.kind {
            // Bitwarden exports notes, cards and identities too.
            if format == Format::Bitwarden && !record.get(kind).unwrap_or_default().trim().eq_ignore_ascii_case("login") {
                parsed.skipped.not_a_login += 1;
                continue;
            }
        }
        let password = Zeroizing::new(record.get(columns.password).unwrap_or_default().to_string());
        if password.is_empty() {
            parsed.skipped.no_password += 1;
            continue;
        }
        let url = get(columns.url);
        let username = get(columns.username);
        let mut service = get(columns.title);
        if service.is_empty() {
            service = host_of(&url);
        }
        if service.is_empty() {
            parsed.skipped.no_name += 1;
            continue;
        }
        let notes = get(columns.notes);
        if service.len() > MAX_FIELD_CHARS
            || username.len() > MAX_FIELD_CHARS
            || url.len() > MAX_FIELD_CHARS
            || password.len() > MAX_LONG_FIELD_CHARS
            || notes.len() > MAX_LONG_FIELD_CHARS
        {
            parsed.skipped.too_long += 1;
            continue;
        }
        let otp = get(columns.totp);
        let totp = if otp.is_empty() {
            None
        } else {
            match totp::Config::parse(&otp) {
                Ok(config) => Some(config),
                Err(_) => {
                    parsed.totp_unusable += 1;
                    None
                }
            }
        };
        parsed.logins.push(Login { service, username, password, url, notes, totp });
    }
    Ok(parsed)
}

fn same_login(a: (&str, &str, &str), b: (&str, &str, &str)) -> bool {
    a.0.eq_ignore_ascii_case(b.0) && a.1 == b.1 && a.2 == b.2
}

/// Leave out logins already in the vault (same name, username and password)
/// and repeats within the file.
pub fn drop_duplicates(db: &Connection, key: &[u8; 32], parsed: &mut Parsed) -> Result<(), String> {
    let mut known: Vec<(String, String, Zeroizing<String>)> = Vec::new();
    for summary in credentials::list_summaries(db, key)? {
        let password = credentials::reveal_password(db, key, &summary.id)?;
        known.push((summary.service, summary.username, password));
    }
    let logins = std::mem::take(&mut parsed.logins);
    for login in logins {
        let candidate = (login.service.as_str(), login.username.as_str(), login.password.as_str());
        if known.iter().any(|(s, u, p)| same_login((s, u, p), candidate)) {
            parsed.skipped.duplicate += 1;
            continue;
        }
        known.push((login.service.clone(), login.username.clone(), login.password.clone()));
        parsed.logins.push(login);
    }
    Ok(())
}

/// Add every login in one transaction: all of them, or none.
pub fn commit(db: &Connection, key: &[u8; 32], logins: &[Login]) -> Result<usize, String> {
    in_transaction(db, || {
        for login in logins {
            let id = crate::util::uuid_v4();
            let seal = |column: &str, value: &str| fields::seal(key, "credentials", &id, column, value);
            let totp = match &login.totp {
                Some(config) => Some(seal("totp_secret", &config.to_stored())?),
                None => None,
            };
            db.execute(
                "INSERT INTO credentials (id, service, username, password_encrypted, url, notes, totp_secret) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    id,
                    seal("service", &login.service)?,
                    seal("username", &login.username)?,
                    seal("password_encrypted", &login.password)?,
                    seal("url", &login.url)?,
                    seal("notes", &login.notes)?,
                    totp,
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(logins.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "name,url,username,password,note\r\ngithub.com,https://github.com/login,hashlorem,gh-pass-1,\r\n\"Bank, savings\",https://bank.example.com,lm,\"pa,ss\"\"word\",\"line one\nline two\"\r\n";
    const FIREFOX: &str = "\u{feff}\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://www.tryhackme.com\",\"hashlorem\",\"thm-pass\",,\"https://tryhackme.com\",\"{1}\",\"1\",\"1\",\"1\"\n";
    const APPLE: &str = "Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com,hashlorem,gh-pass-2,personal,otpauth://totp/GitHub:hashlorem?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\nSteam,https://store.steampowered.com,lm,steam-pass,,steam://ABCDEF\nWi-Fi,,,,router,\n";
    const BITWARDEN: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Discord,,,0,https://discord.com,hashlorem,dc-pass,JBSWY3DPEHPK3PXPJBSWY3DP\n,,note,Recovery words,secret words,,0,,,,\n";
    const ONEPASSWORD: &str = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nProton,https://proton.me,hashlorem,pm-pass,,false,false,,\n";

    #[test]
    fn test_each_export_format_is_recognised_and_mapped() {
        let chrome = parse(CHROME).unwrap();
        assert_eq!(chrome.format, Format::Chrome);
        assert_eq!(chrome.logins.len(), 2);
        assert_eq!(chrome.logins[1].service, "Bank, savings");
        assert_eq!(chrome.logins[1].password.as_str(), "pa,ss\"word", "quotes and commas survive");
        assert_eq!(chrome.logins[1].notes, "line one\nline two", "newlines in notes survive");

        let firefox = parse(FIREFOX).unwrap();
        assert_eq!(firefox.format, Format::Firefox);
        assert_eq!(firefox.logins[0].service, "tryhackme.com", "no title: named after the host");

        let apple = parse(APPLE).unwrap();
        assert_eq!(apple.format, Format::Apple);
        assert_eq!(apple.logins.len(), 2);
        assert_eq!(apple.logins[0].totp.as_ref().unwrap().secret, "JBSWY3DPEHPK3PXP");
        assert!(apple.logins[1].totp.is_none(), "Steam Guard can't be used");
        assert_eq!((apple.totp_unusable, apple.skipped.no_password), (1, 1));

        let bitwarden = parse(BITWARDEN).unwrap();
        assert_eq!(bitwarden.format, Format::Bitwarden);
        assert_eq!((bitwarden.logins.len(), bitwarden.skipped.not_a_login), (1, 1));
        assert!(bitwarden.logins[0].totp.is_some(), "a bare key works too");

        assert_eq!(parse(ONEPASSWORD).unwrap().format, Format::OnePassword);
        assert_eq!(parse("site,login,password\nx.com,me,pw\n").unwrap().format, Format::Generic);
    }

    #[test]
    fn test_unusable_files_and_rows_are_refused_or_counted() {
        assert!(parse("name,url,username\na,b,c\n").err().unwrap().contains("no password column"));
        assert!(parse("").is_err());
        let rows = format!("url,username,password\n{}", "https://a.com,u,p\n".repeat(MAX_ROWS + 1));
        assert!(parse(&rows).err().unwrap().contains("more than"));

        let odd = parse("name,url,username,password\n,,,pw\nok,,me,\nlong,,me,pw\n").unwrap();
        assert_eq!((odd.skipped.no_name, odd.skipped.no_password, odd.logins.len()), (1, 1, 1));
        let too_long = format!("name,username,password\n{},me,pw\n", "x".repeat(MAX_FIELD_CHARS + 1));
        assert_eq!(parse(&too_long).unwrap().skipped.too_long, 1);
    }

    #[test]
    fn test_host_of_strips_scheme_www_port_and_path() {
        assert_eq!(host_of("https://www.GitHub.com:443/login?x=1#y"), "github.com");
        assert_eq!(host_of("user@mail.example.com"), "mail.example.com");
        assert_eq!(host_of(""), "");
    }
}
