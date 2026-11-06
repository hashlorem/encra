use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const PERIOD: u64 = 30;
const DIGITS: u32 = 6;
/// RFC 4226 §4 requires a shared secret of at least 128 bits, with 80 bits as
/// the absolute floor. Base32 encodes 5 bits per character, so 16 characters is
/// the smallest secret we accept — anything shorter is a degenerate HMAC key.
const MIN_SECRET_CHARS: usize = 16;

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

/// Generate a TOTP code for the given secret at the current time
pub fn generate_code(secret: &str) -> Result<String, String> {
    let key = base32_decode(secret)?;
    if key.is_empty() {
        return Err("secret decodes to zero bytes".into());
    }
    let counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        / PERIOD;

    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3)
    let offset = (result[19] & 0x0F) as usize;
    let code = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let code = code % 10u32.pow(DIGITS);

    Ok(format!("{:0width$}", code, width = DIGITS as usize))
}

/// Get remaining seconds in the current 30-second window
pub fn remaining_seconds() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    PERIOD - (now % PERIOD)
}

/// Validate that a string is a usable base32 TOTP secret.
///
/// Enforces the alphabet, a minimum length, and that decoding yields at least
/// one byte. Without the length floor a one-character secret decodes to zero
/// bytes and produces an HMAC over an empty key.
pub fn validate_secret(secret: &str) -> Result<(), String> {
    let cleaned = secret.trim().to_uppercase().replace('=', "");
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
