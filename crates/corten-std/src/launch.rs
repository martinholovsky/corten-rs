//! The launch document: how `corten-sandbox` hands a program the manifest it
//! verified (spec section 8, question 26; `docs/gates/launch-proposal.md`).
//!
//! A checked program can read neither its environment nor its arguments, and
//! naming a raw descriptor needs `unsafe`, so the launcher writes this
//! document into a memfd, seals it (no write, grow or shrink) and installs
//! it as the program's standard input. The program calls
//! [`Capabilities::from_launcher`](crate::manifest::Capabilities::from_launcher),
//! which reads it and verifies the manifest itself rather than taking the
//! launcher's word: the signature, the trusted key and the expiry. The
//! rollback floor stays with the launcher's serial state file; a serial
//! field here could only repeat the manifest's own, a check that can never
//! fail.
//!
//! ```text
//! corten-launch 1
//! trusted-key ID=HEX          one or more, 64 hex digits each
//! signature HEX               the manifest's Ed25519 signature, 128 hex digits
//! manifest-length L
//!                             a blank line, then exactly L bytes of manifest
//! ```

use crate::manifest::{KeyId, MAX_MANIFEST, ManifestError, PublicKey, TrustedKeys};

const HEADER: &str = "corten-launch 1";

/// Largest launch document read: the manifest plus room for keys.
pub const MAX_LAUNCH: usize = MAX_MANIFEST + 16 * 1024;

/// Keys a launch document may carry.
pub const MAX_KEYS: usize = 32;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        // Writing to a String does not fail.
        let _written = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    })
}

/// Lowercase hex of exactly `N` bytes.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != N {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0u8; N];
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = nibble(hi)?.wrapping_shl(4) | nibble(lo)?;
    }
    Some(out)
}

/// Writes a launch document. Used by `corten-sandbox`, so the format has
/// one definition.
#[must_use]
pub fn document(keys: &[(&str, [u8; 32])], manifest: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut lines = vec![HEADER.to_owned()];
    lines.extend(
        keys.iter()
            .map(|(id, key)| format!("trusted-key {id}={}", hex(key))),
    );
    lines.push(format!("signature {}", hex(signature)));
    lines.push(format!("manifest-length {}", manifest.len()));
    let text = format!("{}\n\n", lines.join("\n"));
    let mut out = text.into_bytes();
    out.extend_from_slice(manifest);
    out
}

/// The value of `line` after `prefix`, or the error naming the field.
fn field<'a>(line: Option<&'a str>, prefix: &str) -> Result<&'a str, ManifestError> {
    line.and_then(|l| l.strip_prefix(prefix))
        .ok_or_else(|| bad(&format!("expected {}", prefix.trim_end())))
}

/// A parsed launch document.
#[derive(Debug)]
pub(crate) struct Launch {
    pub(crate) keys: TrustedKeys,
    pub(crate) signature: [u8; 64],
    pub(crate) manifest: Vec<u8>,
}

fn bad(why: &str) -> ManifestError {
    ManifestError::Launch(why.to_owned())
}

/// Parses a launch document, strictly: the header first, then the fields in
/// order, each once (keys repeated), a blank line, and exactly the stated
/// number of manifest bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<Launch, ManifestError> {
    if bytes.len() > MAX_LAUNCH {
        return Err(bad("larger than the limit"));
    }
    let split = bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| bad("no blank line before the manifest"))?;
    let (head, rest) = bytes.split_at(split);
    let body = rest.get(2..).ok_or_else(|| bad("truncated"))?;
    let head = std::str::from_utf8(head).map_err(|_| bad("the header is not UTF-8"))?;
    let mut lines = head.split('\n');
    if lines.next() != Some(HEADER) {
        return Err(bad("not a corten-launch 1 document"));
    }
    let mut keys = TrustedKeys::new();
    let mut count = 0usize;
    let mut line = lines.next();
    while let Some(entry) = line.and_then(|l| l.strip_prefix("trusted-key ")) {
        let (id, key) = entry
            .split_once('=')
            .ok_or_else(|| bad("a trusted-key is not ID=HEX"))?;
        let key = unhex::<32>(key).ok_or_else(|| bad("a trusted key is not 64 hex digits"))?;
        keys.add(KeyId(id), PublicKey(&key))?;
        count = count.checked_add(1).ok_or_else(|| bad("too many keys"))?;
        if count > MAX_KEYS {
            return Err(bad("too many keys"));
        }
        line = lines.next();
    }
    if count == 0 {
        return Err(bad("no trusted-key"));
    }
    let decimal = |text: &str| -> Result<u64, ManifestError> {
        if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("a number is malformed"));
        }
        text.parse().map_err(|_| bad("a number is malformed"))
    };
    let signature = unhex::<64>(field(line, "signature ")?)
        .ok_or_else(|| bad("the signature is not 128 hex digits"))?;
    let length = decimal(field(lines.next(), "manifest-length ")?)?;
    if lines.next().is_some() {
        return Err(bad("an unexpected header line"));
    }
    if usize::try_from(length).ok() != Some(body.len()) {
        return Err(bad("the manifest length does not match"));
    }
    Ok(Launch {
        keys,
        signature,
        manifest: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_round_trips() {
        let pk = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([2; 32])).pk;
        let mut key = [0u8; 32];
        key.copy_from_slice(pk.as_ref());
        let d = document(&[("deploy", key), ("next", key)], b"m\n", &[3; 64]);
        let l = parse(&d).unwrap();
        assert_eq!(l.signature, [3; 64]);
        assert_eq!(l.manifest, b"m\n");
    }

    #[test]
    fn every_malformed_document_is_refused() {
        let pk = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([2; 32])).pk;
        let key = hex(pk.as_ref());
        let sig = hex(&[1; 64]);
        let good = format!(
            "corten-launch 1\ntrusted-key d={key}\nsignature {sig}\nmanifest-length 2\n\nm\n"
        );
        assert!(parse(good.as_bytes()).is_ok());
        for (from, to) in [
            ("corten-launch 1", "corten-launch 2"),
            ("manifest-length 2", "manifest-length -2"),
            ("manifest-length 2", "manifest-length 2x"),
            ("manifest-length 2", "manifest-length 3"),
            ("manifest-length 2\n", "manifest-length 2\nextra 1\n"),
            ("\n\nm\n", "\nm\n"),
            (&format!("trusted-key d={key}\n"), ""),
            (&format!("signature {sig}"), "signature 00"),
            (&format!("d={key}"), &format!("d={}", key.to_uppercase())),
        ] {
            let text = good.replacen(from, to, 1);
            assert!(parse(text.as_bytes()).is_err(), "{from:?} -> {to:?}");
        }
        assert!(parse(&vec![b'a'; MAX_LAUNCH + 1]).is_err());
    }
}
