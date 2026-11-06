use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// OS-backed cryptographic random number generator.
///
/// This is the single randomness source for the whole project. `aes_gcm::aead::OsRng`
/// is a re-export of this exact type, but naming it here keeps one visible origin so a
/// future change cannot quietly introduce a second, weaker source.
pub fn os_rng() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}

/// Fill a fixed-size buffer from the OS CSPRNG.
pub fn fill_random(buf: &mut [u8]) {
    os_rng().fill_bytes(buf);
}

/// Generate a random UUID v4 string from the OS CSPRNG.
pub fn uuid_v4() -> String {
    let mut buf = [0u8; 16];
    fill_random(&mut buf);
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
    )
}

/// Compare two byte slices in constant time.
///
/// Used only for comparing secret-derived material. Length is not treated as a
/// secret here: both operands are fixed-size base64 encodings of a 32-byte key.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Overwrite every string in a collection in place.
pub fn wipe_strings(values: &mut [String]) {
    for value in values.iter_mut() {
        value.zeroize();
    }
}

/// Reject a field that is empty or longer than the storage budget allows.
pub fn check_field(value: &str, label: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        return Err(format!("{label} is too long (max {max} bytes)"));
    }
    Ok(())
}