//! The wire format between `encra run` and the running app.
//!
//! Every message is one frame: a 4-byte magic, a version byte, a 4-byte
//! big-endian length and the payload, capped at 1 MiB. The request is JSON
//! (it carries no secrets). The response carries values as raw length-prefixed
//! bytes, never inside JSON strings, so they can be wiped after use. Anything
//! malformed is an error, never a panic.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 1 << 20;
const REQUEST_MAGIC: &[u8; 4] = b"ENRQ";
const RESPONSE_MAGIC: &[u8; 4] = b"ENRS";

/// What a caller asks for. Shown to the person approving it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Who the caller says it is. Self-reported, so shown as a claim.
    pub agent: String,
    /// The command as it will run, argv[0] included.
    pub argv: Vec<String>,
    /// argv[0] resolved to an absolute path with symlinks followed.
    pub executable: String,
    pub cwd: String,
    /// `encra://` references, deduplicated.
    pub references: Vec<String>,
}

#[derive(Debug)]
pub enum Response {
    /// One value per requested reference, in request order.
    Approved(Vec<(String, Zeroizing<Vec<u8>>)>),
    Denied,
    Error(String),
}

fn write_frame(w: &mut impl Write, magic: &[u8; 4], payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_FRAME {
        return Err("message too large".into());
    }
    let mut header = [0u8; 9];
    header[..4].copy_from_slice(magic);
    header[4] = VERSION;
    header[5..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&header).and_then(|_| w.write_all(payload)).and_then(|_| w.flush()).map_err(|e| e.to_string())
}

fn read_frame(r: &mut impl Read, magic: &[u8; 4]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut header = [0u8; 9];
    r.read_exact(&mut header).map_err(|_| "connection closed before a full message arrived".to_string())?;
    if &header[..4] != magic {
        return Err("not an Encra message".into());
    }
    if header[4] != VERSION {
        return Err(format!("unsupported protocol version {} (this Encra speaks {VERSION})", header[4]));
    }
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if len > MAX_FRAME {
        return Err("message too large".into());
    }
    let mut payload = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut payload).map_err(|_| "message was cut short".to_string())?;
    Ok(payload)
}

pub fn write_request(w: &mut impl Write, request: &Request) -> Result<(), String> {
    let payload = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    write_frame(w, REQUEST_MAGIC, &payload)
}

pub fn read_request(r: &mut impl Read) -> Result<Request, String> {
    let payload = read_frame(r, REQUEST_MAGIC)?;
    serde_json::from_slice(&payload).map_err(|_| "malformed request".to_string())
}

pub fn write_response(w: &mut impl Write, response: &Response) -> Result<(), String> {
    let mut out = Zeroizing::new(Vec::new());
    match response {
        Response::Approved(values) => {
            out.push(0);
            out.extend_from_slice(&(values.len() as u16).to_be_bytes());
            for (reference, value) in values {
                out.extend_from_slice(&(reference.len() as u16).to_be_bytes());
                out.extend_from_slice(reference.as_bytes());
                out.extend_from_slice(&(value.len() as u32).to_be_bytes());
                out.extend_from_slice(value);
            }
        }
        Response::Denied => out.push(1),
        Response::Error(message) => {
            out.push(2);
            out.extend_from_slice(message.as_bytes());
        }
    }
    write_frame(w, RESPONSE_MAGIC, &out)
}

/// Reads bounded slices off a buffer; every read is length-checked.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.bytes.len()).ok_or("malformed response")?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<usize, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn u32(&mut self) -> Result<usize, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
}

pub fn read_response(r: &mut impl Read) -> Result<Response, String> {
    let payload = read_frame(r, RESPONSE_MAGIC)?;
    let mut cur = Cursor { bytes: &payload, at: 0 };
    match cur.take(1)?[0] {
        0 => {
            let count = cur.u16()?;
            let mut values = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let ref_len = cur.u16()?;
                let reference = String::from_utf8(cur.take(ref_len)?.to_vec()).map_err(|_| "malformed response")?;
                let value_len = cur.u32()?;
                values.push((reference, Zeroizing::new(cur.take(value_len)?.to_vec())));
            }
            if cur.at != payload.len() {
                return Err("malformed response".into());
            }
            Ok(Response::Approved(values))
        }
        1 => Ok(Response::Denied),
        2 => Ok(Response::Error(String::from_utf8_lossy(&payload[1..]).into_owned())),
        _ => Err("malformed response".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            agent: "claude".into(),
            argv: vec!["/usr/bin/env".into()],
            executable: "/usr/bin/env".into(),
            cwd: "/tmp".into(),
            references: vec!["encra://GitHub#password".into()],
        }
    }

    #[test]
    fn test_frames_round_trip() {
        let mut buf = Vec::new();
        write_request(&mut buf, &request()).unwrap();
        assert_eq!(read_request(&mut buf.as_slice()).unwrap(), request());

        let mut buf = Vec::new();
        let values = vec![("encra://GitHub#password".to_string(), Zeroizing::new(b"s3cret\x00bytes".to_vec()))];
        write_response(&mut buf, &Response::Approved(values)).unwrap();
        match read_response(&mut buf.as_slice()).unwrap() {
            Response::Approved(values) => assert_eq!(values[0].1.as_slice(), b"s3cret\x00bytes"),
            other => panic!("unexpected {other:?}"),
        }
        let mut buf = Vec::new();
        write_response(&mut buf, &Response::Error("vault locked".into())).unwrap();
        assert!(matches!(read_response(&mut buf.as_slice()).unwrap(), Response::Error(m) if m == "vault locked"));
    }

    #[test]
    fn test_bad_frames_are_errors_not_panics() {
        let mut good = Vec::new();
        write_request(&mut good, &request()).unwrap();

        // Truncated at every length.
        for cut in 0..good.len() {
            assert!(read_request(&mut &good[..cut]).is_err());
        }
        // Wrong magic, wrong version, oversized length, garbage JSON.
        let mut wrong = good.clone();
        wrong[0] = b'X';
        assert!(read_request(&mut wrong.as_slice()).is_err());
        let mut version = good.clone();
        version[4] = 9;
        assert!(read_request(&mut version.as_slice()).unwrap_err().contains("version"));
        let mut huge = good.clone();
        huge[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(read_request(&mut huge.as_slice()).is_err());
        let mut junk = Vec::new();
        write_frame(&mut junk, REQUEST_MAGIC, b"{not json").unwrap();
        assert!(read_request(&mut junk.as_slice()).is_err());

        // A response whose counts point past the end of the payload.
        let mut lying = Vec::new();
        write_frame(&mut lying, RESPONSE_MAGIC, &[0, 0, 5, 0, 3, b'a']).unwrap();
        assert!(read_response(&mut lying.as_slice()).is_err());
        let mut tag = Vec::new();
        write_frame(&mut tag, RESPONSE_MAGIC, &[7]).unwrap();
        assert!(read_response(&mut tag.as_slice()).is_err());
    }
}
