//! One-time codes (RFC 6238).
//!
//! A login's `totp_secret` column holds either a bare base32 key (30-second,
//! six-digit SHA-1 codes, what nearly every service uses) or, when a service
//! asks for something else, a minimal `otpauth://totp/?secret=..` link with
//! the settings. Older vaults only ever hold the bare form, so both are read.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 6;
const PERIODS: std::ops::RangeInclusive<u64> = 10..=300;
const DIGITS: std::ops::RangeInclusive<u32> = 6..=8;
/// RFC 4226 §4 requires a shared secret of at least 128 bits, with 80 bits as
/// the absolute floor. Base32 encodes 5 bits per character, so 16 characters is
/// the smallest secret we accept — anything shorter is a degenerate HMAC key.
const MIN_SECRET_CHARS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Cleaned base32: uppercase, no spaces, dashes or padding.
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl Config {
    /// Read what a person pasted or a QR code held: a setup key (spaces and
    /// dashes allowed, as services often group it) or an otpauth:// link.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if let Some(rest) = input.get(..10).filter(|s| s.eq_ignore_ascii_case("otpauth://")).map(|_| &input[10..]) {
            return parse_link(rest);
        }
        if input.to_ascii_lowercase().starts_with("otpauth-migration://") {
            return Err("that is an authenticator app export, not a service's setup code".into());
        }
        let secret = clean_secret(input);
        validate_secret(&secret)?;
        Ok(Self { secret, algorithm: Algorithm::Sha1, digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD })
    }

    /// What goes in the vault: the bare key when the settings are the
    /// defaults, so existing data and backups keep their shape.
    pub fn to_stored(&self) -> String {
        if self.algorithm == Algorithm::Sha1 && self.digits == DEFAULT_DIGITS && self.period == DEFAULT_PERIOD {
            return self.secret.clone();
        }
        format!("otpauth://totp/?secret={}&algorithm={}&digits={}&period={}", self.secret, self.algorithm.name(), self.digits, self.period)
    }

    /// The code for a moment in time.
    pub fn code_at(&self, unix_seconds: u64) -> Result<String, String> {
        let key = base32_decode(&self.secret)?;
        if key.is_empty() {
            return Err("secret decodes to zero bytes".into());
        }
        let counter = (unix_seconds / self.period).to_be_bytes();
        let hash = match self.algorithm {
            Algorithm::Sha1 => hmac::<Hmac<Sha1>>(&key, &counter)?,
            Algorithm::Sha256 => hmac::<Hmac<Sha256>>(&key, &counter)?,
            Algorithm::Sha512 => hmac::<Hmac<Sha512>>(&key, &counter)?,
        };
        // Dynamic truncation (RFC 4226 §5.3)
        let offset = (hash[hash.len() - 1] & 0x0F) as usize;
        let code = ((hash[offset] as u32 & 0x7F) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);
        let code = code % 10u32.pow(self.digits);
        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    /// Seconds left before the code changes.
    pub fn remaining_at(&self, unix_seconds: u64) -> u64 {
        self.period - (unix_seconds % self.period)
    }
}

fn hmac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = <M as Mac>::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn clean_secret(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=').collect::<String>().to_uppercase()
}

/// `totp/<label>?<query>` after the scheme. Only the settings are kept; the
/// label (issuer and account) is not needed to make codes.
fn parse_link(rest: &str) -> Result<Config, String> {
    let (kind, rest) = rest.split_once('/').unwrap_or((rest, ""));
    if kind.eq_ignore_ascii_case("hotp") {
        return Err("counter-based (HOTP) codes are not supported".into());
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err("not a one-time code link".into());
    }
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut config = Config { secret: String::new(), algorithm: Algorithm::Sha1, digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value)?;
        match name.to_ascii_lowercase().as_str() {
            "secret" => config.secret = clean_secret(&value),
            "algorithm" => {
                config.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => return Err(format!("unsupported algorithm \"{other}\"")),
                }
            }
            "digits" => {
                config.digits = value.parse().ok().filter(|d| DIGITS.contains(d)).ok_or("codes must be 6 to 8 digits")?;
            }
            "period" => {
                config.period = value.parse().ok().filter(|p| PERIODS.contains(p)).ok_or("codes must last 10 to 300 seconds")?;
            }
            _ => {}
        }
    }
    if config.secret.is_empty() {
        return Err("the link has no secret".into());
    }
    validate_secret(&config.secret)?;
    Ok(config)
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = value.get(i + 1..i + 3).ok_or("bad escape in link")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad escape in link")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "link is not valid text".into())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// What the vault stores. Bare keys are only checked for decoding, not the
/// length floor: one restored from an old backup must keep working.
fn from_stored(stored: &str) -> Result<Config, String> {
    if stored.trim().to_ascii_lowercase().starts_with("otpauth://") {
        return Config::parse(stored);
    }
    let secret = clean_secret(stored);
    if base32_decode(&secret)?.is_empty() {
        return Err("secret decodes to zero bytes".into());
    }
    Ok(Config { secret, algorithm: Algorithm::Sha1, digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD })
}

/// The current code, seconds left and code length in seconds, from what
/// the vault stores.
pub fn current(stored: &str) -> Result<(String, u64, u64), String> {
    let config = from_stored(stored)?;
    let now = now();
    Ok((config.code_at(now)?, config.remaining_at(now), config.period))
}

/// Decode a base32 string (RFC 4648, no padding)
pub fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim().to_uppercase().replace('=', "");
    let mut output = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_left: u32 = 0;

    for ch in input.bytes() {
        let val = BASE32_ALPHABET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| format!("invalid base32 character: '{}'", ch as char))? as u32;

        buffer = (buffer << 5) | val;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            output.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    Ok(output)
}

/// Validate that a string is a usable base32 TOTP secret.
///
/// Enforces the alphabet, a minimum length, and that decoding yields at least
/// one byte. Without the length floor a one-character secret decodes to zero
/// bytes and produces an HMAC over an empty key.
pub fn validate_secret(secret: &str) -> Result<(), String> {
    let cleaned = clean_secret(secret);
    if cleaned.is_empty() {
        return Err("secret is empty".into());
    }
    if cleaned.len() < MIN_SECRET_CHARS {
        return Err(format!(
            "secret is too short: {MIN_SECRET_CHARS} base32 characters minimum, got {}",
            cleaned.len()
        ));
    }
    for ch in cleaned.bytes() {
        if !BASE32_ALPHABET.contains(&ch) {
            return Err(format!("invalid character: '{}'", ch as char));
        }
    }
    let decoded = base32_decode(&cleaned)?;
    if decoded.is_empty() {
        return Err("secret decodes to zero bytes".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base32(bytes: &[u8]) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(5) {
            let mut buf = [0u8; 5];
            buf[..chunk.len()].copy_from_slice(chunk);
            let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
            let chars = (chunk.len() * 8).div_ceil(5);
            for i in 0..chars {
                out.push(BASE32_ALPHABET[((bits >> (35 - i * 5)) & 31) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn test_rfc_6238_vectors_for_every_algorithm() {
        let cases = [
            (Algorithm::Sha1, "12345678901234567890", ["94287082", "07081804", "65353130"]),
            (Algorithm::Sha256, "12345678901234567890123456789012", ["46119246", "68084774", "77737706"]),
            (Algorithm::Sha512, "1234567890123456789012345678901234567890123456789012345678901234", ["90693936", "25091201", "47863826"]),
        ];
        for (algorithm, seed, expected) in cases {
            let config = Config { secret: base32(seed.as_bytes()), algorithm, digits: 8, period: 30 };
            for (time, code) in [59, 1111111109, 20000000000].into_iter().zip(expected) {
                assert_eq!(config.code_at(time).unwrap(), code, "{algorithm:?} at {time}");
            }
        }
    }

    #[test]
    fn test_setup_keys_and_links() {
        // Services often show the key in lowercase groups.
        let plain = Config::parse(" jbsw y3dp-ehpk 3pxp ").unwrap();
        assert_eq!(plain.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!((plain.algorithm, plain.digits, plain.period), (Algorithm::Sha1, 6, 30));
        assert_eq!(plain.to_stored(), "JBSWY3DPEHPK3PXP", "defaults store the bare key, as older vaults do");

        let link = Config::parse("otpauth://totp/Example%20Co:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=sha256&digits=8&period=60").unwrap();
        assert_eq!((link.algorithm, link.digits, link.period), (Algorithm::Sha256, 8, 60));
        assert_eq!(Config::parse(&link.to_stored()).unwrap(), link, "stored settings read back the same");
        assert_eq!(link.remaining_at(119), 1);
        assert_eq!(link.code_at(120).unwrap().len(), 8);

        assert_eq!(Config::parse("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP").unwrap().period, 30, "defaults when a link leaves them out");

        for (bad, why) in [
            ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "HOTP"),
            ("otpauth://totp/x?issuer=Example", "no secret"),
            ("otpauth://totp/x?secret=JBSWY3", "too short"),
            ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4", "6 to 8"),
            ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "10 to 300"),
            ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "unsupported"),
            ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=%E", "bad escape"),
            ("otpauth-migration://offline?data=abc", "export"),
            ("https://example.com", "invalid character"),
        ] {
            assert!(Config::parse(bad).unwrap_err().contains(why), "{bad}");
        }
        assert!(Config::parse("ótpauth://totp/x").is_err(), "a multi-byte start must not panic");

        // A short key from an old backup still makes codes; new ones are refused.
        assert!(Config::parse("JBSWY3DP").is_err());
        assert_eq!(current("JBSWY3DP").unwrap().0.len(), 6);
        assert!(current("").is_err());
    }
}
