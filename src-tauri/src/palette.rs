//! Search for the ⌘K palette: logins, cases, commands, and Encra's own pages,
//! tools and actions, ranked by one matcher.
//!
//! Results carry names and ids only. Copying a password or 2FA code from the
//! palette goes through the same per-field copy as the Vault page.

use rusqlite::Connection;
use serde::Serialize;

use crate::{credentials, fields};

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    Login,
    Case,
    Command,
    Go,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Hit {
    pub group: Group,
    /// A login, case or command id, or the name of a page, tool or action.
    pub id: String,
    pub title: String,
    pub subtitle: String,
    /// Character positions in `title` that matched, for underlining.
    pub matched: Vec<usize>,
    pub has_totp: bool,
    #[serde(skip)]
    score: i64,
}

/// Pages, tools and actions, as (id, title). The page maps ids to what they do.
const GO: &[(&str, &str)] = &[
    ("page:vault", "Vault"),
    ("page:journal", "Case notes"),
    ("page:tools", "Toolbox"),
    ("page:activity", "Activity"),
    ("page:settings", "Settings"),
    ("tool:pwgen", "Password generator"),
    ("tool:nmap", "Nmap parser"),
    ("tool:kb", "Command library"),
    ("action:new-login", "New login"),
    ("action:new-case", "Open a case"),
    ("action:import", "Import passwords"),
    ("action:checkup", "Vault check-up"),
    ("action:seal", "Seal the vault"),
];

const PER_GROUP: usize = 5;

/// Score `text` against `query`: every query character must appear in order.
/// Matches at the start of the text or of a word, and runs of consecutive
/// matches, score higher. None when it doesn't match at all.
pub fn score(query: &str, text: &str) -> Option<(i64, Vec<usize>)> {
    let query: Vec<char> = query.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
    if query.is_empty() {
        return Some((0, Vec::new()));
    }
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.to_lowercase().chars().collect();
    if lower.len() != chars.len() {
        return None; // a case mapping that changes length; rare, and not worth guessing
    }
    // Prefer a contiguous match anywhere: "git" in "GitHub" over g…i…t.
    let joined: String = query.iter().collect();
    let haystack: String = lower.iter().collect();
    if let Some(byte_start) = haystack.find(&joined) {
        let start = haystack[..byte_start].chars().count();
        let at_word = start == 0 || !chars[start - 1].is_alphanumeric();
        let bonus = if start == 0 { 300 } else if at_word { 200 } else { 100 };
        let positions = (start..start + query.len()).collect();
        return Some((bonus + 10 * query.len() as i64 - chars.len() as i64, positions));
    }
    let mut positions = Vec::with_capacity(query.len());
    let mut next = 0;
    let mut points = 0i64;
    for q in &query {
        let found = (next..lower.len()).find(|&i| lower[i] == *q)?;
        let at_word = found == 0 || !chars[found - 1].is_alphanumeric();
        let consecutive = positions.last().is_some_and(|&last| last + 1 == found);
        points += 1 + if at_word { 5 } else { 0 } + if consecutive { 3 } else { 0 };
        positions.push(found);
        next = found + 1;
    }
    Some((points - chars.len() as i64 / 4, positions))
}

fn best(query: &str, title: &str, also: &[&str]) -> Option<(i64, Vec<usize>)> {
    let on_title = score(query, title);
    let on_rest = also.iter().filter_map(|text| score(query, text)).map(|(s, _)| (s / 2, Vec::new())).max_by_key(|(s, _)| *s);
    match (on_title, on_rest) {
        (Some(t), Some(r)) if r.0 > t.0 => Some(r),
        (Some(t), _) => Some(t),
        (None, rest) => rest,
    }
}

fn top(mut hits: Vec<Hit>) -> Vec<Hit> {
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase())));
    hits.truncate(PER_GROUP);
    hits
}

/// Everything matching `query`, grouped (logins, cases, commands, then pages
/// and actions), best first within each group.
pub fn search(db: &Connection, key: &[u8; 32], query: &str) -> Result<Vec<Hit>, String> {
    let query = query.trim();
    let mut results = Vec::new();

    if !query.is_empty() {
        let logins = credentials::list_summaries(db, key)?
            .into_iter()
            .filter_map(|c| {
                let (score, matched) = best(query, &c.service, &[&c.username])?;
                let subtitle = if c.has_totp && !c.username.is_empty() { format!("{} · 2FA", c.username) } else if c.has_totp { "2FA".into() } else { c.username.clone() };
                Some(Hit { group: Group::Login, id: c.id, title: c.service, subtitle, matched, has_totp: c.has_totp, score })
            })
            .collect();
        results.extend(top(logins));

        let mut stmt = db.prepare("SELECT id, name, status FROM projects").map_err(|e| e.to_string())?;
        let cases = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(|e| e.to_string())?
            .filter_map(|row| {
                let (id, name, status) = row.ok()?;
                let name = fields::open_to_string(key, "projects", &id, "name", &name).ok()?;
                let (score, matched) = best(query, &name, &[])?;
                let subtitle = match status.as_str() {
                    "in_progress" => "In progress",
                    "completed" => "Closed",
                    _ => "Planning",
                };
                Some(Hit { group: Group::Case, id, title: name, subtitle: subtitle.into(), matched, has_totp: false, score })
            })
            .collect();
        results.extend(top(cases));

        let mut stmt = db.prepare("SELECT id, title, command FROM kb_entries").map_err(|e| e.to_string())?;
        let commands = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(|e| e.to_string())?
            .filter_map(|row| {
                let (id, title, command) = row.ok()?;
                let title = fields::open_to_string(key, "kb_entries", &id, "title", &title).ok()?;
                let command = fields::open_to_string(key, "kb_entries", &id, "command", &command).unwrap_or_default();
                let (score, matched) = best(query, &title, &[&command])?;
                Some(Hit { group: Group::Command, id, title, subtitle: command, matched, has_totp: false, score })
            })
            .collect();
        results.extend(top(commands));
    }

    let go = GO
        .iter()
        .filter_map(|(id, title)| {
            let (score, matched) = score(query, title)?;
            Some(Hit { group: Group::Go, id: (*id).into(), title: (*title).into(), subtitle: String::new(), matched, has_totp: false, score })
        })
        .collect::<Vec<_>>();
    // With no query, the palette lists the pages in their usual order.
    if query.is_empty() {
        results.extend(go);
    } else {
        results.extend(top(go));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_prefers_prefix_then_word_start_then_scattered() {
        let prefix = score("git", "GitHub").unwrap();
        let word = score("git", "Leaked token in a git repo").unwrap();
        let inside = score("hub", "GitHub").unwrap();
        let scattered = score("gtb", "GitHub").unwrap();
        assert!(prefix.0 > word.0 && word.0 > inside.0, "{prefix:?} {word:?} {inside:?}");
        assert!(inside.0 > scattered.0);
        assert_eq!(prefix.1, [0, 1, 2]);
        assert_eq!(scattered.1, [0, 2, 5]);
        assert!(score("xyz", "GitHub").is_none());
        assert!(score("GITHUB", "github").is_some(), "case doesn't matter");
        assert_eq!(score("", "anything"), Some((0, Vec::new())));
        assert!(score("k ali", "Kali VM").is_some(), "spaces in the query are ignored");
    }
}
