//! Schema-checked IPC between a component and a broker: length-prefixed
//! frames, a per-type size limit checked before allocation, and a decoder
//! that must accept the whole frame.

use std::fmt;
use std::io::{Read, Write};

/// A message type on the wire.
pub trait Message: Sized {
    /// Largest encoded size accepted, in bytes.
    const MAX_LEN: u32;
    /// Encodes the message.
    fn encode(&self) -> Vec<u8>;
    /// Decodes a whole frame; anything else is an error.
    ///
    /// # Errors
    ///
    /// [`IpcError::Decode`] when the bytes are not a valid message.
    fn decode(bytes: &[u8]) -> Result<Self, IpcError>;
}

/// Why a frame was refused.
#[derive(Debug)]
pub enum IpcError {
    /// The frame announced or held more than `Message::MAX_LEN` bytes.
    TooLarge(u32),
    /// The bytes did not decode.
    Decode(&'static str),
    /// Reading or writing failed (including a truncated frame).
    Io(std::io::Error),
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the message's limit"),
            Self::Decode(why) => write!(f, "malformed message: {why}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IpcError {}

/// Writes one frame: a 4-byte big-endian length, then the encoding.
///
/// # Errors
///
/// [`IpcError::TooLarge`] if the encoding exceeds `M::MAX_LEN`;
/// [`IpcError::Io`] on a write error.
pub fn write_message<M: Message>(to: &mut impl Write, message: &M) -> Result<(), IpcError> {
    let bytes = message.encode();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    if len > M::MAX_LEN {
        return Err(IpcError::TooLarge(len));
    }
    to.write_all(&len.to_be_bytes()).map_err(IpcError::Io)?;
    to.write_all(&bytes).map_err(IpcError::Io)
}

/// Reads one frame and decodes it, refusing an announced length over
/// `M::MAX_LEN` before reading or allocating it.
///
/// # Errors
///
/// [`IpcError`] for an oversized, truncated or malformed frame.
pub fn read_message<M: Message>(from: &mut impl Read) -> Result<M, IpcError> {
    let mut header = [0u8; 4];
    from.read_exact(&mut header).map_err(IpcError::Io)?;
    let len = u32::from_be_bytes(header);
    if len > M::MAX_LEN {
        return Err(IpcError::TooLarge(len));
    }
    let size = usize::try_from(len).map_err(|_| IpcError::TooLarge(len))?;
    let mut body = vec![0u8; size];
    from.read_exact(&mut body).map_err(IpcError::Io)?;
    M::decode(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test message: a UTF-8 name of at most 16 bytes.
    #[derive(Debug, PartialEq, Eq)]
    struct Name(String);

    impl Message for Name {
        const MAX_LEN: u32 = 16;
        fn encode(&self) -> Vec<u8> {
            self.0.as_bytes().to_vec()
        }
        fn decode(bytes: &[u8]) -> Result<Self, IpcError> {
            std::str::from_utf8(bytes)
                .map(|s| Self(s.to_owned()))
                .map_err(|_| IpcError::Decode("not UTF-8"))
        }
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Name("alice".to_owned())).unwrap();
        assert_eq!(
            read_message::<Name>(&mut buf.as_slice()).unwrap(),
            Name("alice".to_owned())
        );
    }

    #[test]
    fn oversize_announcement_is_refused_before_allocation() {
        let mut frame = u32::MAX.to_be_bytes().to_vec();
        frame.extend_from_slice(b"x");
        assert!(matches!(
            read_message::<Name>(&mut frame.as_slice()),
            Err(IpcError::TooLarge(_))
        ));
        let mut buf = Vec::new();
        assert!(matches!(
            write_message(&mut buf, &Name("x".repeat(17))),
            Err(IpcError::TooLarge(17))
        ));
    }

    #[test]
    fn truncated_and_malformed_frames_are_refused() {
        let mut short = 5u32.to_be_bytes().to_vec();
        short.extend_from_slice(b"ab");
        assert!(matches!(
            read_message::<Name>(&mut short.as_slice()),
            Err(IpcError::Io(_))
        ));
        let mut bad = 2u32.to_be_bytes().to_vec();
        bad.extend_from_slice(&[0xff, 0xfe]);
        assert!(matches!(
            read_message::<Name>(&mut bad.as_slice()),
            Err(IpcError::Decode(_))
        ));
    }
}
