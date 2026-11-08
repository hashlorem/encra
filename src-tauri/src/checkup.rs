//! The vault check-up: which logins share a password, which are weak, which
//! haven't changed in over a year, and which turned up in a breach.
//!
//! Passwords are compared and judged here and never leave Rust. Reuse is
//! found by keyed hashes with a key made for this one check and then
//! dropped, so nothing comparable outlives the call.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rusqlite::Connection;
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::credentials;
use crate::util::fill_random;

/// Under 12 characters, or under 16 with fewer than three kinds of character
/// (lowercase, uppercase, digits, anything else). Long passphrases pass;
/// common passwords show up in the breach check instead.
pub fn is_weak(password: &str) -> bool {
    let length = password.chars().count();
    let kinds = [
        password.chars().any(|c| c.is_lowercase()),
        password.chars().any(|c| c.is_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&k| k)
    .count();
    length < 12 || (length < 16 && kinds < 3)
}

/// Days after which a password counts as old.
pub const OLD_AFTER_DAYS: i64 = 365;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LoginRef {
    pub id: String,
    pub service: String,
    pub username: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct OldLogin {
    pub login: LoginRef,
    /// When the password was last set.
    pub since: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct BreachedLogin {
    pub login: LoginRef,
    pub count: u32,
    pub checked_at: String,
}

/// Flags only: never a password, its length or its makeup.
#[derive(Debug, Serialize, PartialEq)]
pub struct Checkup {
    pub total: usize,
    /// Groups of two or more logins that share one password.
    pub reused: Vec<Vec<LoginRef>>,
    pub weak: Vec<LoginRef>,
    pub old: Vec<OldLogin>,
    pub breached: Vec<BreachedLogin>,
    /// Logins with a password that the breach check hasn't seen yet.
    pub unchecked: usize,
    /// The most recent breach check of any login.
    pub last_checked: Option<String>,
}

pub fn run(db: &Connection, key: &[u8; 32]) -> Result<Checkup, String> {
    let summaries = credentials::list_summaries(db, key)?;
    let mut ages: HashMap<String, (String, bool)> = HashMap::new();
    {
        let mut stmt = db
            .prepare(
                "SELECT id, COALESCE(password_changed_at, created_at),
                        julianday('now') - julianday(COALESCE(password_changed_at, created_at)) > ?1
                 FROM credentials",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([OLD_AFTER_DAYS], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, bool>(2)?)))
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (id, since, old) = row.map_err(|e| e.to_string())?;
            ages.insert(id, (since, old));
        }
    }

    let mut hash_key = Zeroizing::new([0u8; 32]);
    fill_random(hash_key.as_mut());
    let mut groups: HashMap<[u8; 32], Vec<LoginRef>> = HashMap::new();
    let mut checkup = Checkup { total: summaries.len(), reused: Vec::new(), weak: Vec::new(), old: Vec::new(), breached: Vec::new(), unchecked: 0, last_checked: None };

    for summary in summaries {
        let login = LoginRef { id: summary.id.clone(), service: summary.service.clone(), username: summary.username.clone() };
        let password = credentials::reveal_password(db, key, &summary.id)?;
        if password.is_empty() {
            continue;
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hash_key.as_ref()).map_err(|e| e.to_string())?;
        mac.update(password.as_bytes());
        groups.entry(mac.finalize().into_bytes().into()).or_default().push(login.clone());

        if is_weak(&password) {
            checkup.weak.push(login.clone());
        }
        if let Some((since, true)) = ages.get(&summary.id) {
            checkup.old.push(OldLogin { login: login.clone(), since: since.clone() });
        }
        match credentials::detail(db, key, &summary.id)?.breach {
            Some(result) => {
                if checkup.last_checked.as_deref().is_none_or(|last| result.checked_at.as_str() > last) {
                    checkup.last_checked = Some(result.checked_at.clone());
                }
                if result.count > 0 {
                    checkup.breached.push(BreachedLogin { login, count: result.count, checked_at: result.checked_at });
                }
            }
            None => checkup.unchecked += 1,
        }
    }
    checkup.reused = groups.into_values().filter(|g| g.len() > 1).collect();
    checkup.reused.sort_by(|a, b| a[0].service.to_lowercase().cmp(&b[0].service.to_lowercase()));
    checkup.breached.sort_by_key(|b| std::cmp::Reverse(b.count));
    Ok(checkup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_means_short_or_short_and_plain() {
        for weak in ["", "hunter2", "Tr0ub4dor&3", "abcdefghijklmn", "ABCDEFGHIJKL12"] {
            assert!(is_weak(weak), "{weak:?} should be weak");
        }
        for fine in ["Abcdefghijk1", "correct horse battery staple", "abcdefghijklmnop", "xK9!xK9!xK9!"] {
            assert!(!is_weak(fine), "{fine:?} should pass");
        }
    }
}
