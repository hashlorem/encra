use sha1::{Digest, Sha1};
use std::time::Duration;

const HIBP_API: &str = "https://api.pwnedpasswords.com/range/";
/// A stalled or hostile endpoint must not be able to hang the UI indefinitely.
const HIBP_TIMEOUT_SECS: u64 = 10;
/// The real range response is a few hundred kilobytes at most. Cap the read so a
/// misbehaving server cannot stream unbounded data into memory.
const MAX_HIBP_BYTES: usize = 8 * 1024 * 1024;

/// Check a password against the HIBP database using k-anonymity.
/// Only the first 5 chars of the SHA-1 hash are sent over the network.
/// Returns the number of times this password appears in breaches,
/// or 0 if not found.
pub async fn check_password(password: &str) -> Result<u32, String> {
    // SHA-1 hash the password
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:X}", hasher.finalize());

    let prefix = &hash[..5];
    let suffix = &hash[5..];

    // Fetch matching hashes from HIBP
    let url = format!("{}{}", HIBP_API, prefix);
    let client = reqwest::Client::builder()
        .user_agent("encra/0.1.0")
        .timeout(Duration::from_secs(HIBP_TIMEOUT_SECS))
        .build()
        .map_err(|e| e.to_string())?;

    // Padding makes every range response a similar size, so the size of the
    // encrypted reply does not hint at which prefix was asked for.
    let mut response = client
        .get(&url)
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|e| format!("HIBP API unreachable: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("HIBP API returned {}", response.status()));
    }

    let mut body_bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("HIBP API read failed: {}", e))?
    {
        if body_bytes.len() + chunk.len() > MAX_HIBP_BYTES {
            return Err("HIBP API response was too large".into());
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8_lossy(&body_bytes);

    count_for_suffix(&body, suffix)
}

/// The breach count for `suffix` in a range response, or 0 if it is absent.
/// Padding adds made-up suffixes with a count of 0, which read the same as
/// "not found".
fn count_for_suffix(body: &str, suffix: &str) -> Result<u32, String> {
    for line in body.lines() {
        if let Some((hash_suffix, count_str)) = line.split_once(':') {
            if hash_suffix.eq_ignore_ascii_case(suffix) {
                return count_str
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| "invalid HIBP response".to_string());
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These two tests make real network calls to api.pwnedpasswords.com. They are
    // #[ignore]d so `cargo test` stays offline and deterministic; run them with
    // `cargo test -- --ignored` when a live check is actually wanted.

    const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn test_count_for_suffix_reads_padded_responses() {
        // A real hit, a padding line (count 0) and Windows line endings.
        let body = format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{SUFFIX}:3861\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n");
        assert_eq!(count_for_suffix(&body, SUFFIX).unwrap(), 3861);
        assert_eq!(count_for_suffix(&body, &SUFFIX.to_lowercase()).unwrap(), 3861);
        assert_eq!(count_for_suffix(&body, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC").unwrap(), 0, "padding reads as not found");
        assert_eq!(count_for_suffix(&body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap(), 0);
    }

    #[test]
    fn test_count_for_suffix_rejects_a_garbled_count() {
        let body = format!("{SUFFIX}:lots\r\n");
        assert!(count_for_suffix(&body, SUFFIX).is_err());
    }

    #[tokio::test]
    #[ignore = "live network call to the HIBP API"]
    async fn test_known_pwned_password() {
        // "password123" is definitely in breaches
        let result = check_password("password123").await;
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[tokio::test]
    #[ignore = "live network call to the HIBP API"]
    async fn test_unknown_password() {
        // highly unlikely this exact string is in breaches
        let result = check_password("xz7q#9mK!pW2$vL5nR8@jF3").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
