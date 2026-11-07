//! `encra://` references: which login, which field.
//!
//!   encra://GitHub              the password of the login named "GitHub"
//!   encra://GitHub#username     another field of it
//!   encra://id/<uuid>#password  by id, for names that are not unique
//!
//! Names match exactly. A missing or ambiguous name is refused, never guessed.

use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::credentials::{self, CopyField};

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

/// Find the one login a reference means.
pub fn login_id(db: &Connection, key: &[u8; 32], target: &Target) -> Result<String, String> {
    let logins = credentials::list_summaries(db, key)?;
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

/// The value a reference points at, plus the login id it came from (for the log).
pub fn resolve(db: &Connection, key: &[u8; 32], text: &str) -> Result<(String, Zeroizing<String>), String> {
    let reference = parse(text)?;
    let id = login_id(db, key, &reference.target)?;
    let value = credentials::copy_value(db, key, &id, reference.field)?;
    Ok((id, value))
}
