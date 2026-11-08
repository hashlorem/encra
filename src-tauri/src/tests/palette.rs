//! ⌘K palette search over a real vault file.

use rusqlite::Connection;

use crate::commands::lifecycle::*;
use crate::palette::{self, Group};
use crate::{fields, vault};
use super::support::*;

#[test]
fn test_palette_finds_logins_cases_commands_and_pages_without_secrets() {
    let (dir, path) = fresh_vault_file("palette");
    let dek = create_vault_impl(&Connection::open(&path).unwrap(), "a-long-master-password").unwrap();
    let conn = vault::init_db(&path).unwrap();
    crate::journal::init_journal_tables(&conn).unwrap();
    crate::kb::init_kb_tables(&conn).unwrap();
    let seal = |table: &str, id: &str, column: &str, value: &str| fields::seal(&dek, table, id, column, value).unwrap();
    for (id, service, user, password) in [("c1", "GitHub", "hashlorem", "gh-secret"), ("c2", "GitLab, homelab", "root", "gl-secret"), ("c3", "Proton Mail", "hashlorem", "pm-secret")] {
        conn.execute(
            "INSERT INTO credentials (id, service, username, password_encrypted, url, notes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            [id, &seal("credentials", id, "service", service), &seal("credentials", id, "username", user), &seal("credentials", id, "password_encrypted", password), &seal("credentials", id, "url", ""), &seal("credentials", id, "notes", "")],
        )
        .unwrap();
    }
    conn.execute("INSERT INTO projects (id, name) VALUES ('p1', ?1)", [seal("projects", "p1", "name", "Leaked token in a git repo")]).unwrap();
    conn.execute(
        "INSERT INTO kb_entries (id, title, command, description, tags, category) VALUES ('k1', ?1, ?2, '', '', 'recon')",
        [seal("kb_entries", "k1", "title", "Search a repo's history for secrets"), seal("kb_entries", "k1", "command", "git log -p | grep -i token")],
    )
    .unwrap();

    let hits = palette::search(&conn, &dek, "git").unwrap();
    let groups: Vec<(Group, &str)> = hits.iter().map(|h| (h.group, h.title.as_str())).collect();
    assert_eq!(groups[0], (Group::Login, "GitHub"), "a name starting with the query comes first");
    assert!(groups.contains(&(Group::Login, "GitLab, homelab")));
    assert!(groups.contains(&(Group::Case, "Leaked token in a git repo")));
    assert!(groups.contains(&(Group::Command, "Search a repo's history for secrets")), "found by its command text");
    assert!(!groups.iter().any(|(_, t)| *t == "Proton Mail"));
    assert_eq!(hits[0].matched, [0, 1, 2]);

    // Usernames match too, and the page list is always there to jump to.
    assert!(palette::search(&conn, &dek, "hashlorem").unwrap().iter().any(|h| h.title == "Proton Mail"));
    let empty = palette::search(&conn, &dek, "").unwrap();
    assert!(empty.iter().all(|h| h.group == Group::Go) && empty.len() > 5);
    assert_eq!(palette::search(&conn, &dek, "check").unwrap()[0].id, "action:checkup");

    let json = serde_json::to_string(&palette::search(&conn, &dek, "g").unwrap()).unwrap();
    for secret in ["gh-secret", "gl-secret", "pm-secret"] {
        assert!(!json.contains(secret));
    }
    drop(conn);
    std::fs::remove_dir_all(dir).unwrap();
}
