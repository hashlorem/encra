//! Indicators of compromise in a case: IP addresses, domains, URLs, email
//! addresses, file hashes and CVE ids, pulled out of the notes and evidence.
//!
//! Notes are refanged first, so `hxxps://evil[.]example` is found too.
//! Domains count only when their last label is a real top-level domain (the
//! IANA list in `data/`, embedded, nothing fetched); names whose "TLD" is also
//! a common file extension (`invoice.zip`) are kept but marked.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

const IANA_TLDS: &str = include_str!("data/tlds-alpha-by-domain.txt");

/// Real TLDs that are also everyday file extensions.
const FILE_LIKE_TLDS: &[&str] = &["zip", "mov", "py", "sh", "rs", "md", "pl", "ps", "so", "ai", "ms"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Domain,
    Url,
    Ipv4,
    Ipv6,
    Email,
    Sha256,
    Sha1,
    Md5,
    Cve,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Domain => "domain",
            Kind::Url => "url",
            Kind::Ipv4 => "ipv4",
            Kind::Ipv6 => "ipv6",
            Kind::Email => "email",
            Kind::Sha256 => "sha256",
            Kind::Sha1 => "sha1",
            Kind::Md5 => "md5",
            Kind::Cve => "cve",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Indicator {
    pub kind: Kind,
    pub value: String,
    pub defanged: String,
    /// "internal", "documentation range" or "possible domain".
    pub note: Option<&'static str>,
    /// Where it was found: entry titles and evidence file names.
    pub sources: Vec<String>,
}

struct Patterns {
    url: Regex,
    email: Regex,
    ipv4: Regex,
    domain: Regex,
    sha256: Regex,
    sha1: Regex,
    md5: Regex,
    cve: Regex,
    refang: Vec<(Regex, &'static str)>,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let re = |p: &str| Regex::new(p).expect("indicator pattern compiles");
        Patterns {
            url: re(r#"(?i)\b(?:https?|ftp)://[^\s<>"'`]+"#),
            email: re(r"(?i)\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}\b"),
            ipv4: re(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            domain: re(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b"),
            sha256: re(r"(?i)\b[a-f0-9]{64}\b"),
            sha1: re(r"(?i)\b[a-f0-9]{40}\b"),
            md5: re(r"(?i)\b[a-f0-9]{32}\b"),
            cve: re(r"(?i)\bCVE-\d{4}-\d{4,7}\b"),
            refang: vec![
                (re(r"(?i)\bhxxp"), "http"),
                (re(r"(?i)\bfxp://"), "ftp://"),
                (re(r"(?i)\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)"), "."),
                (re(r"(?i)\[\s*:\s*\]"), ":"),
                (re(r"(?i)\[@\]|\[at\]|\(at\)"), "@"),
            ],
        }
    })
}

fn tlds() -> &'static HashSet<String> {
    static TLDS: OnceLock<HashSet<String>> = OnceLock::new();
    TLDS.get_or_init(|| IANA_TLDS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).map(str::to_lowercase).collect())
}

/// Undo the usual defanging so indicators written safely are still found.
pub fn refang(text: &str) -> String {
    patterns().refang.iter().fold(text.to_string(), |text, (pattern, with)| pattern.replace_all(&text, *with).into_owned())
}

fn defang_dots(text: &str) -> String {
    text.replace('.', "[.]")
}

/// The safe-to-paste form used in reports.
pub fn defang(kind: Kind, value: &str) -> String {
    match kind {
        Kind::Domain | Kind::Ipv4 => defang_dots(value),
        Kind::Ipv6 => value.replace(':', "[:]"),
        Kind::Email => match value.split_once('@') {
            Some((user, domain)) => format!("{user}[@]{}", defang_dots(domain)),
            None => value.to_string(),
        },
        Kind::Url => {
            let (scheme, rest) = value.split_once("://").unwrap_or(("", value));
            let scheme = scheme.to_lowercase().replacen("http", "hxxp", 1).replacen("ftp", "fxp", 1);
            let (host, path) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
            format!("{scheme}://{}{path}", defang_dots(host))
        }
        Kind::Sha256 | Kind::Sha1 | Kind::Md5 | Kind::Cve => value.to_string(),
    }
}

fn ipv4_note(ip: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = ip.octets();
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        Some("internal")
    } else if (a, b, c) == (192, 0, 2) || (a, b, c) == (198, 51, 100) || (a, b, c) == (203, 0, 113) {
        Some("documentation range")
    } else {
        None
    }
}

fn ipv6_note(ip: Ipv6Addr) -> Option<&'static str> {
    let first = ip.segments()[0];
    if ip.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
        Some("internal")
    } else if first == 0x2001 && ip.segments()[1] == 0x0db8 {
        Some("documentation range")
    } else {
        None
    }
}

fn trim_url(url: &str) -> &str {
    url.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"'])
}

/// Every indicator in `sources` (label, text), deduplicated, grouped by kind
/// in a fixed order and by first appearance within each kind.
pub fn extract(sources: &[(String, String)]) -> Vec<Indicator> {
    let p = patterns();
    let mut found: Vec<Indicator> = Vec::new();
    let mut index: HashMap<(Kind, String), usize> = HashMap::new();
    let mut add = |kind: Kind, value: String, note: Option<&'static str>, source: &str| {
        let key = (kind, value.clone());
        let at = *index.entry(key).or_insert_with(|| {
            found.push(Indicator { kind, defanged: defang(kind, &value), value, note, sources: Vec::new() });
            found.len() - 1
        });
        if !found[at].sources.iter().any(|s| s == source) {
            found[at].sources.push(source.to_string());
        }
    };

    for (label, text) in sources {
        let text = refang(text);
        for m in p.url.find_iter(&text) {
            add(Kind::Url, trim_url(m.as_str()).to_string(), None, label);
        }
        for m in p.email.find_iter(&text) {
            let email = m.as_str().to_lowercase();
            let tld = email.rsplit('.').next().unwrap_or_default();
            if tlds().contains(tld) {
                add(Kind::Email, email, None, label);
            }
        }
        for m in p.ipv4.find_iter(&text) {
            if let Ok(ip) = m.as_str().parse::<Ipv4Addr>() {
                add(Kind::Ipv4, ip.to_string(), ipv4_note(ip), label);
            }
        }
        for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')) {
            if token.matches(':').count() >= 2 {
                if let Ok(ip) = token.parse::<Ipv6Addr>() {
                    add(Kind::Ipv6, ip.to_string(), ipv6_note(ip), label);
                }
            }
        }
        for m in p.domain.find_iter(&text) {
            let domain = m.as_str().to_lowercase();
            let tld = domain.rsplit('.').next().unwrap_or_default();
            if !tlds().contains(tld) {
                continue;
            }
            let note = FILE_LIKE_TLDS.contains(&tld).then_some("possible domain");
            add(Kind::Domain, domain, note, label);
        }
        for (pattern, kind) in [(&p.sha256, Kind::Sha256), (&p.sha1, Kind::Sha1), (&p.md5, Kind::Md5)] {
            for m in pattern.find_iter(&text) {
                add(kind, m.as_str().to_lowercase(), None, label);
            }
        }
        for m in p.cve.find_iter(&text) {
            add(Kind::Cve, m.as_str().to_uppercase(), None, label);
        }
    }
    found.sort_by_key(|i| i.kind);
    found
}

/// A cell that a spreadsheet would run as a formula gets a leading quote.
fn safe_cell(text: &str) -> String {
    if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_string()
    }
}

/// The indicators as CSV, raw or defanged, for a report or a SIEM.
pub fn to_csv(indicators: &[Indicator], defanged: bool) -> Result<String, String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record(["type", "value", "note", "found in"]).map_err(|e| e.to_string())?;
    for i in indicators {
        let value = if defanged { &i.defanged } else { &i.value };
        writer
            .write_record([i.kind.label(), &safe_cell(value), i.note.unwrap_or_default(), &safe_cell(&i.sources.join("; "))])
            .map_err(|e| e.to_string())?;
    }
    String::from_utf8(writer.into_inner().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Vec<Indicator> {
        extract(&[("Entry".to_string(), text.to_string())])
    }

    fn values(indicators: &[Indicator], kind: Kind) -> Vec<&str> {
        indicators.iter().filter(|i| i.kind == kind).map(|i| i.value.as_str()).collect()
    }

    #[test]
    fn test_defanged_notes_are_found_and_defanged_again() {
        let found = one("Sender accounts[@]invoices-examp1e[.]com via hxxps://invoices-examp1e[.]com/pay/7731. Relay 203.0.113[.]45.");
        assert_eq!(values(&found, Kind::Email), ["accounts@invoices-examp1e.com"]);
        assert_eq!(values(&found, Kind::Url), ["https://invoices-examp1e.com/pay/7731"], "trailing full stop trimmed");
        assert_eq!(values(&found, Kind::Domain), ["invoices-examp1e.com"], "found in the URL and email, listed once");
        assert_eq!(values(&found, Kind::Ipv4), ["203.0.113.45"]);
        let url = found.iter().find(|i| i.kind == Kind::Url).unwrap();
        assert_eq!(url.defanged, "hxxps://invoices-examp1e[.]com/pay/7731");
        let email = found.iter().find(|i| i.kind == Kind::Email).unwrap();
        assert_eq!(email.defanged, "accounts[@]invoices-examp1e[.]com");
    }

    #[test]
    fn test_ips_are_checked_and_labelled() {
        let found = one("10.0.4.12 clicked; 999.1.1.1 and 1.2.3 are not addresses; 8.8.8.8 resolved; fe80::1 and 2001:db8::7 seen at 09:44:52");
        assert_eq!(values(&found, Kind::Ipv4), ["10.0.4.12", "8.8.8.8"]);
        let note = |v: &str| found.iter().find(|i| i.value == v).unwrap().note;
        assert_eq!(note("10.0.4.12"), Some("internal"));
        assert_eq!(note("8.8.8.8"), None);
        assert_eq!(values(&found, Kind::Ipv6), ["fe80::1", "2001:db8::7"], "a time of day is not an address");
        assert_eq!(note("fe80::1"), Some("internal"));
        assert_eq!(note("2001:db8::7"), Some("documentation range"));
    }

    #[test]
    fn test_only_real_tlds_count_and_file_like_ones_are_marked() {
        let found = one("Read auth.log and report.pdf, then opened invoice.zip from lookalike-bank.com; see notes.md");
        assert_eq!(values(&found, Kind::Domain), ["invoice.zip", "lookalike-bank.com", "notes.md"]);
        assert_eq!(found.iter().find(|i| i.value == "invoice.zip").unwrap().note, Some("possible domain"));
        assert_eq!(found.iter().find(|i| i.value == "lookalike-bank.com").unwrap().note, None);
    }

    #[test]
    fn test_hashes_by_exact_length_and_cves() {
        let sha256 = "9f2c4d1b7e60a35c8d14f0b2e97a6c3d5b81e0f4a29c76d3e8b15f0a4c2d97e1";
        let text = format!("sha256 {sha256}, md5 5D41402ABC4B2A76B9719D911017C592, sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709, cve-2023-23397, and {}", "a".repeat(48));
        let found = one(&text);
        assert_eq!(values(&found, Kind::Sha256), [sha256]);
        assert_eq!(values(&found, Kind::Md5), ["5d41402abc4b2a76b9719d911017c592"], "lowercased");
        assert_eq!(values(&found, Kind::Sha1), ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]);
        assert_eq!(values(&found, Kind::Cve), ["CVE-2023-23397"]);
        assert_eq!(found.iter().filter(|i| i.value.starts_with("aaaa")).count(), 0, "48 hex chars is no hash");
    }

    #[test]
    fn test_sources_are_collected_and_order_is_stable() {
        let found = extract(&[
            ("Header analysis".into(), "From 203.0.113.45".into()),
            ("Gateway log".into(), "Again 203.0.113.45 and CVE-2021-44228".into()),
        ]);
        assert_eq!(found[0].kind, Kind::Ipv4);
        assert_eq!(found[0].sources, ["Header analysis", "Gateway log"]);
        assert_eq!(found.last().unwrap().kind, Kind::Cve);
    }

    #[test]
    fn test_csv_export_quotes_and_neutralises_formulas() {
        let found = extract(&[("=HYPERLINK(\"x\")".into(), "evil.example.com, 203.0.113.45".into())]);
        let raw = to_csv(&found, false).unwrap();
        assert!(raw.starts_with("type,value,note,found in\n"));
        assert!(raw.contains("ipv4,203.0.113.45,documentation range,"));
        assert!(raw.contains("'=HYPERLINK"), "a formula-looking source is quoted");
        let defanged = to_csv(&found, true).unwrap();
        assert!(defanged.contains("203[.]0[.]113[.]45"));
    }
}
