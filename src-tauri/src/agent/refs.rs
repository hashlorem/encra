//! `encra://` references: which login, which field.
//!
//!   encra://GitHub              the password of the login named "GitHub"
//!   encra://GitHub#username     another field of it
//!   encra://id/<uuid>#password  by id, for names that are not unique
//!
//! Names match exactly. A missing or ambiguous name is refused, never guessed.

use rusqlite::Connection;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::credentials::{self, CopyField};
use crate::fields;

pub const SCHEME: &str = "encra://";

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Name(String),
    Id(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub target: Target,
    pub field: CopyField,
}

pub fn is_reference(value: &str) -> bool {
    value.trim_start().starts_with(SCHEME)
}

pub fn field_name(field: CopyField) -> &'static str {
    match field {
        CopyField::Username => "username",
        CopyField::Password => "password",
        CopyField::Url => "url",
        CopyField::Totp => "totp",
    }
}

pub fn parse(text: &str) -> Result<Reference, String> {
    let rest = text.trim().strip_prefix(SCHEME).ok_or_else(|| format!("not an encra:// reference: {text}"))?;
    let (target, field) = match rest.rsplit_once('#') {
        Some((target, field)) => {
            let field = match field {
                "password" => CopyField::Password,
                "username" => CopyField::Username,
                "url" => CopyField::Url,
                other => return Err(format!("unknown field \"{other}\" (use password, username or url)")),
            };
            (target, field)
        }
        None => (rest, CopyField::Password),
    };
    let target = target.trim();
    if target.is_empty() {
        return Err("reference names no login".into());
    }
    let target = match target.strip_prefix("id/") {
        Some(id) if !id.is_empty() => Target::Id(id.to_string()),
        Some(_) => return Err("reference names no login".into()),
        None => Target::Name(target.to_string()),
    };
    Ok(Reference { target, field })
}

// ===== Remembered matches =====
//
// When a reference's name doesn't match a login ("GitHub" vs "Github h"), the
// approver picks one and can remember it. The name is sealed like any other
// field: which accounts an agent asks for is private too.

const ALIASES: &str = "agent_aliases";

pub fn init_alias_table(db: &Connection) -> Result<(), String> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS agent_aliases (id TEXT PRIMARY KEY, name TEXT NOT NULL, login_id TEXT NOT NULL)")
        .map_err(|e| e.to_string())
}

fn aliases(db: &Connection, key: &[u8; 32]) -> Result<Vec<(String, String, String)>, String> {
    let mut stmt = db.prepare("SELECT id, name, login_id FROM agent_aliases").map_err(|e| e.to_string())?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, name, login)| fields::open_to_string(key, ALIASES, &id, "name", &name).ok().map(|name| (id, name, login)))
        .collect())
}

/// Remember that `name` means `login_id`, replacing any earlier match.
pub fn remember(db: &Connection, key: &[u8; 32], name: &str, login_id: &str) -> Result<(), String> {
    for (id, existing, _) in aliases(db, key)? {
        if existing == name {
            db.execute("DELETE FROM agent_aliases WHERE id = ?1", [&id]).map_err(|e| e.to_string())?;
        }
    }
    let id = crate::util::uuid_v4();
    let sealed = fields::seal(key, ALIASES, &id, "name", name)?;
    db.execute("INSERT INTO agent_aliases (id, name, login_id) VALUES (?1, ?2, ?3)", rusqlite::params![id, sealed, login_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Forget every remembered match that points at a login (it was deleted).
pub fn forget_login(db: &Connection, login_id: &str) -> Result<(), String> {
    db.execute("DELETE FROM agent_aliases WHERE login_id = ?1", [login_id]).map(|_| ()).map_err(|e| e.to_string())
}

/// Find the one login a reference means. A remembered match wins over an
/// exact name, as long as its login still exists.
pub fn login_id(db: &Connection, key: &[u8; 32], target: &Target) -> Result<String, String> {
    let logins = credentials::list_summaries(db, key)?;
    if let Target::Name(name) = target {
        let remembered = aliases(db, key)?.into_iter().find(|(_, alias, _)| alias == name).map(|(_, _, login)| login);
        if let Some(login) = remembered.filter(|login| logins.iter().any(|c| &c.id == login)) {
            return Ok(login);
        }
    }
    let matches: Vec<&credentials::CredentialSummary> = match target {
        Target::Id(id) => logins.iter().filter(|c| &c.id == id).collect(),
        Target::Name(name) => logins.iter().filter(|c| &c.service == name).collect(),
    };
    match (matches.as_slice(), target) {
        ([one], _) => Ok(one.id.clone()),
        ([], Target::Name(name)) => Err(format!("no login is named \"{name}\"")),
        ([], Target::Id(id)) => Err(format!("no login has id {id}")),
        (_, Target::Name(name)) => Err(format!("{} logins are named \"{name}\"; use encra://id/<id> instead", matches.len())),
        (_, Target::Id(_)) => Err("duplicate login ids".into()),
    }
}

/// The value a reference points at, plus the login id it came from (for the
/// log). `chosen` is a login the approver picked in the dialog, which wins.
pub fn resolve(db: &Connection, key: &[u8; 32], text: &str, chosen: Option<&str>) -> Result<(String, Zeroizing<String>), String> {
    let reference = parse(text)?;
    let id = match chosen {
        Some(id) => login_id(db, key, &Target::Id(id.to_string()))?,
        None => login_id(db, key, &reference.target)?,
    };
    let value = credentials::copy_value(db, key, &id, reference.field)?;
    Ok((id, value))
}

/// How a reference resolves right now, for the approval dialog only. The
/// caller never sees this: it names your logins.
#[derive(Debug, Serialize, PartialEq)]
pub struct Match {
    pub reference: String,
    pub field: &'static str,
    /// "found", "missing" or "ambiguous".
    pub status: &'static str,
    pub login_id: Option<String>,
    pub login: Option<String>,
}

pub fn preview(db: &Connection, key: &[u8; 32], text: &str) -> Match {
    let parsed = parse(text);
    let field = parsed.as_ref().map(|r| field_name(r.field)).unwrap_or("?");
    let found = parsed.and_then(|r| login_id(db, key, &r.target));
    let (status, login_id) = match found {
        Ok(id) => ("found", Some(id)),
        Err(error) if error.contains("logins are named") => ("ambiguous", None),
        Err(_) => ("missing", None),
    };
    let login = login_id
        .as_ref()
        .and_then(|id| credentials::list_summaries(db, key).ok()?.into_iter().find(|c| &c.id == id).map(|c| c.service));
    Match { reference: text.to_string(), field, status, login_id, login }
}
