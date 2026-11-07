//! Agent access: `encra run` lets a program (an AI agent's tool call, a script)
//! use a login without the caller ever seeing it. Off by default.
//!
//! The pieces: `client` is the `encra run` command, `server` is the socket and
//! request queue inside the app, `protocol` is the wire format, `refs` turns
//! `encra://Login#field` into a value, and `sock` holds the folder and peer
//! checks.

pub mod client;
pub mod protocol;
pub mod refs;
pub mod server;
pub mod sock;
