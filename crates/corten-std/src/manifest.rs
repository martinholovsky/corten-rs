//! The signed capability manifest (spec 4.3): the only source of a root
//! [`DirCap`], an [`ExecCap`] or a [`DeclassifyCap`].
//!
//! Format 3, UTF-8, one entry per line:
//!
//! ```text
//! corten-manifest 3
//! key deploy-2026-11
//! serial 42
//! not-after 1767225600
//! program sha256 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
//! dir uploads /srv/app/uploads
//! dir records /srv/app/records protected
//! exec tar /usr/bin/tar
//! declassify report
//! authn api token deploy-2026-11:5d7f...(64 hex digits),next:9a1c...
//! ```
//!
//! The first five lines are required, in this order (spec section 8,
//! questions 19 and F4; CWE-294, 324, 494):
//!
//! - `key ID` names the deployer key that signed the manifest, in the
//!   verifier's [`TrustedKeys`]. A key set lets a key be rotated: sign with
//!   the new key, trust both, then drop the old one.
//! - `serial N` is a monotonic counter. [`verify`] refuses a serial below the
//!   caller's [`MinSerial`], so an older manifest that granted more cannot be
//!   replayed. The high-water mark is persisted by the launcher
//!   (`corten-sandbox --serial-state`), the component that holds the
//!   authority to write it.
//! - `not-after T` is a Unix time in seconds; the manifest is refused at or
//!   after it.
//! - `program sha256 HEX` is the SHA-256 of the program the grants are for,
//!   as the build's provenance records it (64 lowercase hex digits). The
//!   launcher (`corten-sandbox`) refuses to start any other binary under
//!   them, so the signed grants are bound to the build that was checked
//!   (finding F4, `docs/gates/phase-6.md`).
//!
//! Formats 1 and 2, which lacked these lines, are refused. Names follow the `PathSeg`
//! grammar; paths are absolute. `declassify NAME` (Phase 4) grants the right
//! to release a labelled value as public (`crate::label`); it names no path.
//! A `dir` grant marked `protected` (Phase 6, strategy 2) is taken only as a
//! [`ProtectedDir`], whose every operation consumes an authorization proof.
//! `authn NAME token ID:HEX,...` names the Ed25519 keys whose tokens the
//! [`TokenAuthenticator`] accepts (`crate::authz`). There is no password
//! authenticator: only phishing-resistant authentication is accepted (owner
//! decision 2026-11-13). The deployer signs the exact bytes with Ed25519. The key ID is read before
//! the signature is checked, only to choose the key; nothing else is parsed
//! before then. [`Capabilities::load`] refuses a manifest over
//! [`MAX_MANIFEST`] bytes and opens every directory up front, so a missing
//! directory or a platform without `openat2` fails at start-up rather than
//! later.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::authz::{ProtectedDir, TokenAuthenticator};
use crate::label::DeclassifyCap;
use crate::net::{DnsFallback, Host, NetCap};

use crate::fs::{DirCap, FsError};
use crate::path::PathSeg;
use crate::process::ExecCap;

/// Largest manifest accepted, in bytes.
pub const MAX_MANIFEST: usize = 65_536;

const HEADER: &str = "corten-manifest 3";

/// Why a manifest was refused.
#[derive(Debug)]
pub enum ManifestError {
    /// Larger than [`MAX_MANIFEST`].
    TooLarge,
    /// The public key or signature is malformed, or the signature does not
    /// match the bytes.
    Signature,
    /// Not UTF-8, wrong header, or a malformed line (1-based line number).
    Syntax(usize),
    /// A name appears twice.
    Duplicate(String),
    /// The manifest names a key the verifier does not trust.
    UnknownKey(String),
    /// The current time is at or after the manifest's `not-after`.
    Expired {
        /// The manifest's `not-after`, Unix seconds.
        not_after: u64,
    },
    /// The manifest's serial is below the highest one accepted before: an
    /// older manifest is being replayed.
    Rollback {
        /// The manifest's serial.
        serial: u64,
        /// The lowest serial the verifier accepts.
        min: u64,
    },
    /// The system clock could not be read or is before 1970.
    Clock,
    /// A granted directory could not be opened.
    Dir {
        /// The entry's name.
        name: String,
        /// Why.
        error: FsError,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "manifest exceeds {MAX_MANIFEST} bytes"),
            Self::Signature => f.write_str("manifest signature is invalid"),
            Self::Syntax(line) => write!(f, "manifest line {line} is malformed"),
            Self::Duplicate(name) => write!(f, "manifest grants {name:?} twice"),
            Self::UnknownKey(id) => write!(f, "manifest is signed with untrusted key {id:?}"),
            Self::Expired { not_after } => {
                write!(f, "manifest expired (not-after {not_after})")
            }
            Self::Rollback { serial, min } => {
                write!(
                    f,
                    "manifest serial {serial} is below {min}: an older manifest was replayed"
                )
            }
            Self::Clock => f.write_str("the system clock could not be read"),
            Self::Dir { name, error } => write!(f, "cannot open directory {name:?}: {error}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// The capabilities a verified manifest grants. Each can be taken once.
#[derive(Debug, Default)]
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        clippy::zero_sized_map_values,
        reason = "DirCap holds no descriptor off Linux, where it cannot be created"
    )
)]
pub struct Capabilities {
    dirs: BTreeMap<String, DirCap>,
    protected_dirs: BTreeMap<String, ProtectedDir>,
    tokens: BTreeMap<String, TokenAuthenticator>,
    execs: BTreeMap<String, ExecCap>,
    declassify: BTreeMap<String, DeclassifyCap>,
    nets: BTreeMap<String, NetCap>,
    dns_fallback: Option<DnsFallback>,
    serial: u64,
}

/// One verified manifest entry. A grant is data: holding one confers no
/// authority (the application has no ambient API that takes a path). The
/// runtime sandbox (`corten-sandbox --manifest`) turns grants into kernel
/// rules; [`Capabilities::load`] turns them into capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// `dir NAME PATH [protected]`: read and write beneath `PATH`. A
    /// `protected` grant is taken only as a [`ProtectedDir`], whose
    /// operations each need an [`Authorized`](crate::authz::Authorized)
    /// proof (Phase 6, strategy 2).
    Dir {
        /// Manifest name.
        name: String,
        /// Absolute path.
        path: PathBuf,
        /// Whether every operation needs a proof.
        protected: bool,
    },
    /// `authn NAME token ID:HEX[,ID:HEX...]`: an authenticator the program may use to obtain an
    /// [`Authenticated`](crate::authz::Authenticated) principal. The program
    /// cannot construct one any other way.
    Authn {
        /// Manifest name; a token's audience must equal it.
        name: String,
        /// How it authenticates.
        method: AuthnMethod,
    },
    /// `exec NAME PATH`: run the program at `PATH`.
    Exec {
        /// Manifest name.
        name: String,
        /// Absolute path.
        path: PathBuf,
    },
    /// `declassify NAME`: release labelled values as public, recorded.
    Declassify {
        /// Manifest name.
        name: String,
    },
    /// `net NAME HOST:PORT [private]`: TLS connections to one destination
    /// (`crate::net`). `private` allows non-public addresses.
    Net {
        /// Manifest name.
        name: String,
        /// The destination host.
        host: Host,
        /// The destination port.
        port: u16,
        /// Whether non-public addresses are allowed.
        private: bool,
    },
    /// `dns fallback NAME`: resolve host grants through this public resolver
    /// over DNS over TLS when it answers (question 16).
    DnsFallback {
        /// The provider.
        provider: DnsFallback,
    },
}

/// How a manifest authenticator checks a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthnMethod {
    /// Signed tokens ([`crate::authz::TokenAuthenticator`]), verified with
    /// these Ed25519 public keys, by key identifier.
    Token {
        /// `(key identifier, public key)`, in manifest order.
        keys: Vec<(String, [u8; 32])>,
    },
}

impl Grant {
    fn name(&self) -> &str {
        match self {
            Self::Dir { name, .. }
            | Self::Exec { name, .. }
            | Self::Declassify { name }
            | Self::Authn { name, .. }
            | Self::Net { name, .. } => name,
            // At most one: a second is a duplicate.
            Self::DnsFallback { .. } => "dns fallback",
        }
    }
}

/// The Ed25519 signature over a manifest: a label, so it cannot be passed
/// where the key belongs (spec 4.2).
#[derive(Debug, Clone, Copy)]
pub struct Signature<'a>(pub &'a [u8]);

/// The deployer's Ed25519 public key: a label, as [`Signature`].
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a>(pub &'a [u8]);

/// A deployer key's identifier, as the manifest's `key` line names it.
#[derive(Debug, Clone, Copy)]
pub struct KeyId<'a>(pub &'a str);

/// The current time, Unix seconds: a label, so it cannot be swapped with a
/// serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixTime(pub u64);

/// The lowest manifest serial the verifier accepts: the highest one accepted
/// before (0 when none was).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinSerial(pub u64);

/// The deployer keys a verifier trusts, by identifier.
#[derive(Debug, Default, Clone)]
pub struct TrustedKeys {
    keys: BTreeMap<String, ed25519_compact::PublicKey>,
}

impl TrustedKeys {
    /// An empty key set; every manifest is refused until a key is added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `key` under `id`.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Syntax`] (line 0) if `id` is not a valid name,
    /// [`ManifestError::Signature`] if `key` is not an Ed25519 public key,
    /// [`ManifestError::Duplicate`] if `id` is already trusted.
    pub fn add(
        &mut self,
        KeyId(id): KeyId<'_>,
        PublicKey(key): PublicKey<'_>,
    ) -> Result<(), ManifestError> {
        if PathSeg::parse(id).is_err() {
            return Err(ManifestError::Syntax(0));
        }
        let key =
            ed25519_compact::PublicKey::from_slice(key).map_err(|_| ManifestError::Signature)?;
        if self.keys.insert(id.to_owned(), key).is_some() {
            return Err(ManifestError::Duplicate(id.to_owned()));
        }
        Ok(())
    }
}

/// A verified manifest: its grants and the header fields they were signed
/// with. The caller persists `serial` as the next [`MinSerial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    /// The grants, in manifest order.
    pub grants: Vec<Grant>,
    /// The identifier of the key that signed it.
    pub key: String,
    /// Its serial.
    pub serial: u64,
    /// Its `not-after`, Unix seconds.
    pub not_after: u64,
    /// The SHA-256 of the only program the grants may be used by.
    pub program_sha256: [u8; 32],
}

/// The key ID on line 2, read before the signature is checked, only to
/// choose the key. `None` if the first two lines are not the header and a
/// `key` line.
fn key_id(manifest: &[u8]) -> Option<&str> {
    let rest = manifest
        .strip_prefix(HEADER.as_bytes())?
        .strip_prefix(b"\n")?;
    let rest = rest.strip_prefix(b"key ")?;
    let end = rest.iter().position(|&b| b == b'\n')?;
    std::str::from_utf8(rest.get(..end)?).ok()
}

/// Verifies the signature with the key the manifest names, then parses it
/// and checks the header and that names are unique. Nothing is opened.
///
/// # Errors
///
/// [`ManifestError`]; nothing past the key ID is parsed unless the signature
/// is valid.
pub fn verify(
    manifest: &[u8],
    Signature(signature): Signature<'_>,
    keys: &TrustedKeys,
    UnixTime(now): UnixTime,
    MinSerial(min): MinSerial,
) -> Result<VerifiedManifest, ManifestError> {
    if manifest.len() > MAX_MANIFEST {
        return Err(ManifestError::TooLarge);
    }
    let id = key_id(manifest).ok_or(ManifestError::Syntax(1))?;
    let key = keys
        .keys
        .get(id)
        .ok_or_else(|| ManifestError::UnknownKey(id.to_owned()))?;
    let sig =
        ed25519_compact::Signature::from_slice(signature).map_err(|_| ManifestError::Signature)?;
    key.verify(manifest, &sig)
        .map_err(|_| ManifestError::Signature)?;
    let text = std::str::from_utf8(manifest).map_err(|_| ManifestError::Syntax(1))?;
    // `parse` reads the same line 2 that chose the key, so the key that
    // verified the bytes is the key the manifest names.
    let (header, grants) = parse(text)?;
    if now >= header.not_after {
        return Err(ManifestError::Expired {
            not_after: header.not_after,
        });
    }
    if header.serial < min {
        return Err(ManifestError::Rollback {
            serial: header.serial,
            min,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for g in &grants {
        if !seen.insert(g.name()) {
            return Err(ManifestError::Duplicate(g.name().to_owned()));
        }
    }
    Ok(VerifiedManifest {
        grants,
        key: header.key,
        serial: header.serial,
        not_after: header.not_after,
        program_sha256: header.program_sha256,
    })
}

struct Header {
    key: String,
    serial: u64,
    not_after: u64,
    program_sha256: [u8; 32],
}

/// Exactly 64 lowercase hexadecimal digits, as 32 bytes.
fn sha256_hex(text: &str, number: usize) -> Result<[u8; 32], ManifestError> {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    if bytes.len() != 64 {
        return Err(ManifestError::Syntax(number));
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let (pairs, []) = bytes.as_chunks::<2>() else {
        return Err(ManifestError::Syntax(number));
    };
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        let (Some(hi), Some(lo)) = (nibble(hi), nibble(lo)) else {
            return Err(ManifestError::Syntax(number));
        };
        *o = hi.wrapping_shl(4) | lo;
    }
    Ok(out)
}

/// `PREFIX VALUE` on line `number`, or a syntax error there.
fn header_field<'a>(
    line: Option<(usize, &'a str)>,
    prefix: &str,
    number: usize,
) -> Result<&'a str, ManifestError> {
    match line {
        Some((_, text)) => text
            .strip_prefix(prefix)
            .filter(|v| !v.is_empty() && !v.contains(' '))
            .ok_or(ManifestError::Syntax(number)),
        None => Err(ManifestError::Syntax(number)),
    }
}

/// A decimal `u64` with no sign, no leading zero and no other characters.
fn decimal(text: &str, number: usize) -> Result<u64, ManifestError> {
    let canonical =
        text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(ManifestError::Syntax(number));
    }
    text.parse().map_err(|_| ManifestError::Syntax(number))
}

fn parse(text: &str) -> Result<(Header, Vec<Grant>), ManifestError> {
    let mut lines = (1usize..).zip(text.lines());
    match lines.next() {
        Some((_, HEADER)) => {}
        _ => return Err(ManifestError::Syntax(1)),
    }
    let key = header_field(lines.next(), "key ", 2)?;
    if PathSeg::parse(key).is_err() {
        return Err(ManifestError::Syntax(2));
    }
    let serial = decimal(header_field(lines.next(), "serial ", 3)?, 3)?;
    let not_after = decimal(header_field(lines.next(), "not-after ", 4)?, 4)?;
    let program_sha256 = sha256_hex(header_field(lines.next(), "program sha256 ", 5)?, 5)?;
    let header = Header {
        key: key.to_owned(),
        serial,
        not_after,
        program_sha256,
    };
    let mut entries = Vec::new();
    for (number, line) in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("dns fallback ") {
            let provider = DnsFallback::parse(name).ok_or(ManifestError::Syntax(number))?;
            entries.push(Grant::DnsFallback { provider });
            continue;
        }
        if let Some(rest) = line.strip_prefix("net ") {
            entries.push(parse_net(rest).ok_or(ManifestError::Syntax(number))?);
            continue;
        }
        if let Some(rest) = line.strip_prefix("authn ") {
            entries.push(parse_authn(rest).ok_or(ManifestError::Syntax(number))?);
            continue;
        }
        let mut parts = line.split(' ');
        let (Some(kind), Some(name), path, flag, None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(ManifestError::Syntax(number));
        };
        // Only `dir` takes a flag, and only `protected`.
        let protected = match (kind, flag) {
            (_, None) => false,
            ("dir", Some("protected")) => true,
            (_, Some(_)) => return Err(ManifestError::Syntax(number)),
        };
        if PathSeg::parse(name).is_err() {
            return Err(ManifestError::Syntax(number));
        }
        // `declassify NAME` names no path; every other kind needs one.
        let path = match (kind, path) {
            ("declassify", None) => {
                entries.push(Grant::Declassify {
                    name: name.to_owned(),
                });
                continue;
            }
            (_, Some(path)) => path,
            (_, None) => return Err(ManifestError::Syntax(number)),
        };
        let path = Path::new(path);
        if !path.is_absolute() || path.to_str().is_none_or(|p| p.contains('\0')) {
            return Err(ManifestError::Syntax(number));
        }
        entries.push(match kind {
            "dir" => Grant::Dir {
                name: name.to_owned(),
                path: path.to_path_buf(),
                protected,
            },
            "exec" => Grant::Exec {
                name: name.to_owned(),
                path: path.to_path_buf(),
            },
            _ => return Err(ManifestError::Syntax(number)),
        });
    }
    Ok((header, entries))
}

/// `NAME HOST:PORT [private]` after `net `.
fn parse_net(rest: &str) -> Option<Grant> {
    let mut parts = rest.split(' ');
    let (Some(name), Some(target), flag, None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    PathSeg::parse(name).ok()?;
    let private = match flag {
        None => false,
        Some("private") => true,
        Some(_) => return None,
    };
    let (host, port) = crate::net::parse_target(target)?;
    Some(Grant::Net {
        name: name.to_owned(),
        host,
        port,
        private,
    })
}

/// `NAME token ID:HEX[,ID:HEX...]` after `authn `.
/// The name and key identifiers use the token field grammar
/// ([`crate::authz::token_field`]), since a token carries them.
fn parse_authn(rest: &str) -> Option<Grant> {
    let mut parts = rest.split(' ');
    let (Some(name), Some(kind), Some(value), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    PathSeg::parse(name).ok()?;
    if !crate::authz::token_field(name) {
        return None;
    }
    let method = match kind {
        "token" => {
            let mut keys: Vec<(String, [u8; 32])> = Vec::new();
            for entry in value.split(',') {
                let (id, hex) = entry.split_once(':')?;
                if !crate::authz::token_field(id) || keys.iter().any(|(k, _)| k == id) {
                    return None;
                }
                let key = sha256_hex(hex, 0).ok()?;
                ed25519_compact::PublicKey::from_slice(&key).ok()?;
                keys.push((id.to_owned(), key));
            }
            AuthnMethod::Token { keys }
        }
        _ => return None,
    };
    Some(Grant::Authn {
        name: name.to_owned(),
        method,
    })
}

/// The current time from the system clock, Unix seconds. The prelude reads
/// the clock here; application code still has no clock authority.
pub(crate) fn now() -> Result<UnixTime, ManifestError> {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    u64::try_from(t.tv_sec)
        .map(UnixTime)
        .map_err(|_| ManifestError::Clock)
}

impl Capabilities {
    /// Verifies `signature` over `manifest` with the key it names in `keys`,
    /// checks its expiry against the system clock and its serial against
    /// `min_serial`, then opens every granted directory.
    ///
    /// # Errors
    ///
    /// [`ManifestError`]; nothing is opened unless every check passes.
    pub fn load(
        manifest: &[u8],
        signature: Signature<'_>,
        keys: &TrustedKeys,
        min_serial: MinSerial,
    ) -> Result<Self, ManifestError> {
        let verified = verify(manifest, signature, keys, now()?, min_serial)?;
        let mut caps = Self {
            serial: verified.serial,
            ..Self::default()
        };
        for grant in verified.grants {
            match grant {
                Grant::Dir {
                    name,
                    path,
                    protected,
                } => {
                    let dir = DirCap::open_root(&path).map_err(|error| ManifestError::Dir {
                        name: name.clone(),
                        error,
                    })?;
                    // verify() refused duplicate names; a second insert
                    // would mean it did not. A protected grant goes only
                    // into its own map, so `take_dir` cannot reach it.
                    let duplicate = if protected {
                        caps.protected_dirs
                            .insert(name.clone(), ProtectedDir::new(name.clone(), dir))
                            .is_some()
                    } else {
                        caps.dirs.insert(name.clone(), dir).is_some()
                    };
                    if duplicate {
                        return Err(ManifestError::Duplicate(name));
                    }
                }
                Grant::Authn {
                    name,
                    method: AuthnMethod::Token { keys },
                } => {
                    let auth = TokenAuthenticator::new(name.clone(), &keys)
                        .ok_or(ManifestError::Signature)?;
                    if caps.tokens.insert(name.clone(), auth).is_some() {
                        return Err(ManifestError::Duplicate(name));
                    }
                }
                Grant::Exec { name, path } => {
                    if caps
                        .execs
                        .insert(name.clone(), ExecCap::new(name.clone(), path))
                        .is_some()
                    {
                        return Err(ManifestError::Duplicate(name));
                    }
                }
                Grant::Declassify { name } => {
                    if caps
                        .declassify
                        .insert(name.clone(), DeclassifyCap::new(name.clone()))
                        .is_some()
                    {
                        return Err(ManifestError::Duplicate(name));
                    }
                }
                Grant::DnsFallback { provider } => caps.dns_fallback = Some(provider),
                Grant::Net {
                    name,
                    host,
                    port,
                    private,
                } => {
                    if caps
                        .nets
                        .insert(name.clone(), NetCap::new(name.clone(), host, port, private))
                        .is_some()
                    {
                        return Err(ManifestError::Duplicate(name));
                    }
                }
            }
        }
        Ok(caps)
    }

    /// Takes the protected directory named `name`, once. A `dir` grant not
    /// marked `protected` is not returned here, and a protected one is not
    /// returned by [`Capabilities::take_dir`].
    pub fn take_protected_dir(&mut self, name: &str) -> Option<ProtectedDir> {
        self.protected_dirs.remove(name)
    }

    /// Takes the token authenticator named `name`, once.
    pub fn take_token_authenticator(&mut self, name: &str) -> Option<TokenAuthenticator> {
        self.tokens.remove(name)
    }

    /// Takes the directory capability named `name`, once.
    pub fn take_dir(&mut self, name: &str) -> Option<DirCap> {
        self.dirs.remove(name)
    }

    /// Takes the program capability named `name`, once.
    pub fn take_exec(&mut self, name: &str) -> Option<ExecCap> {
        self.execs.remove(name)
    }

    /// Takes the declassification capability named `name`, once.
    pub fn take_declassify(&mut self, name: &str) -> Option<DeclassifyCap> {
        self.declassify.remove(name)
    }

    /// Takes the network capability named `name`, once.
    pub fn take_net(&mut self, name: &str) -> Option<NetCap> {
        let fallback = self.dns_fallback;
        self.nets.remove(name).map(|n| n.with_fallback(fallback))
    }

    /// The serial of the manifest these capabilities came from.
    #[must_use]
    pub fn serial(&self) -> u64 {
        self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    /// Far in the future, so tests do not depend on the date.
    const LATER: u64 = 4_102_444_800;

    fn keys() -> KeyPair {
        KeyPair::from_seed(Seed::new([7u8; 32]))
    }

    fn trusted(id: &str, kp: &KeyPair) -> TrustedKeys {
        let mut t = TrustedKeys::new();
        t.add(KeyId(id), PublicKey(kp.pk.as_ref())).unwrap();
        t
    }

    fn sign(kp: &KeyPair, m: &[u8]) -> Vec<u8> {
        kp.sk.sign(m, None).to_vec()
    }

    /// The program line every test manifest carries (the SHA-256 of "abc").
    const PROGRAM: &str =
        "program sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn manifest(key: &str, serial: u64, not_after: u64, body: &str) -> String {
        format!(
            "corten-manifest 3\nkey {key}\nserial {serial}\nnot-after {not_after}\n{PROGRAM}\n{body}"
        )
    }

    fn load(
        m: &str,
        kp: &KeyPair,
        t: &TrustedKeys,
        min: u64,
    ) -> Result<Capabilities, ManifestError> {
        Capabilities::load(
            m.as_bytes(),
            Signature(&sign(kp, m.as_bytes())),
            t,
            MinSerial(min),
        )
    }

    #[test]
    fn signed_exec_manifest_loads_once() {
        let kp = keys();
        let m = manifest("k1", 3, LATER, "exec tar /usr/bin/tar\n");
        let mut caps = load(&m, &kp, &trusted("k1", &kp), 0).unwrap();
        assert_eq!(caps.serial(), 3);
        assert_eq!(
            caps.take_exec("tar")
                .map(|e| e.name().to_owned())
                .as_deref(),
            Some("tar")
        );
        assert!(caps.take_exec("tar").is_none());
    }

    #[test]
    fn declassify_grant_is_taken_once() {
        let kp = keys();
        let m = manifest("k1", 1, LATER, "declassify report\n");
        let mut caps = load(&m, &kp, &trusted("k1", &kp), 0).unwrap();
        assert_eq!(
            caps.take_declassify("report")
                .map(|c| c.name().to_owned())
                .as_deref(),
            Some("report")
        );
        assert!(caps.take_declassify("report").is_none());
        assert!(caps.take_exec("report").is_none());
    }

    #[test]
    fn tampered_manifest_is_refused_before_parsing() {
        let kp = keys();
        let t = trusted("k1", &kp);
        let m = manifest("k1", 1, LATER, "exec tar /usr/bin/tar\n");
        let sig = sign(&kp, m.as_bytes());
        let tampered = manifest("k1", 1, LATER, "exec tar /usr/bin/sh!\n");
        assert!(matches!(
            Capabilities::load(tampered.as_bytes(), Signature(&sig), &t, MinSerial(0)),
            Err(ManifestError::Signature)
        ));
        // Signed by another key that claims the trusted key's ID.
        let other = KeyPair::from_seed(Seed::new([8u8; 32]));
        assert!(matches!(
            load(&m, &other, &t, 0),
            Err(ManifestError::Signature)
        ));
        assert!(matches!(
            Capabilities::load(m.as_bytes(), Signature(&[0u8; 3]), &t, MinSerial(0)),
            Err(ManifestError::Signature)
        ));
    }

    #[test]
    fn the_key_set_selects_by_id_and_supports_rotation() {
        let old = keys();
        let new = KeyPair::from_seed(Seed::new([9u8; 32]));
        let mut both = trusted("old", &old);
        both.add(KeyId("new"), PublicKey(new.pk.as_ref())).unwrap();
        // During rotation both keys verify their own manifests.
        load(&manifest("old", 1, LATER, ""), &old, &both, 0).unwrap();
        load(&manifest("new", 2, LATER, ""), &new, &both, 0).unwrap();
        // After the old key is dropped, its manifests are refused by name.
        let only_new = trusted("new", &new);
        assert!(matches!(
            load(&manifest("old", 3, LATER, ""), &old, &only_new, 0),
            Err(ManifestError::UnknownKey(id)) if id == "old"
        ));
        // A manifest naming the new key but signed with the old one.
        assert!(matches!(
            load(&manifest("new", 3, LATER, ""), &old, &both, 0),
            Err(ManifestError::Signature)
        ));
        // An empty key set trusts nothing.
        assert!(matches!(
            load(&manifest("new", 3, LATER, ""), &new, &TrustedKeys::new(), 0),
            Err(ManifestError::UnknownKey(_))
        ));
    }

    #[test]
    fn trusted_keys_refuse_bad_ids_keys_and_duplicates() {
        let kp = keys();
        let mut t = TrustedKeys::new();
        assert!(matches!(
            t.add(KeyId("../k"), PublicKey(kp.pk.as_ref())),
            Err(ManifestError::Syntax(0))
        ));
        assert!(matches!(
            t.add(KeyId("k"), PublicKey(&[0u8; 5])),
            Err(ManifestError::Signature)
        ));
        t.add(KeyId("k"), PublicKey(kp.pk.as_ref())).unwrap();
        assert!(matches!(
            t.add(KeyId("k"), PublicKey(kp.pk.as_ref())),
            Err(ManifestError::Duplicate(_))
        ));
    }

    #[test]
    fn expiry_is_checked_at_the_boundary() {
        let kp = keys();
        let t = trusted("k1", &kp);
        let m = manifest("k1", 1, 1_000, "");
        let sig = sign(&kp, m.as_bytes());
        let at = |now| {
            verify(
                m.as_bytes(),
                Signature(&sig),
                &t,
                UnixTime(now),
                MinSerial(0),
            )
        };
        assert!(at(999).is_ok());
        assert!(matches!(
            at(1_000),
            Err(ManifestError::Expired { not_after: 1_000 })
        ));
        assert!(matches!(at(5_000), Err(ManifestError::Expired { .. })));
        // load() reads the real clock: a manifest that expired in 1970 is refused.
        assert!(matches!(
            load(&manifest("k1", 1, 1, ""), &kp, &t, 0),
            Err(ManifestError::Expired { .. })
        ));
    }

    #[test]
    fn net_grants_parse_and_are_taken_once() {
        let kp = keys();
        let m = manifest(
            "k1",
            1,
            LATER,
            "net api api.example.com:443\nnet db 10.0.0.5:5432 private\nnet v6 [2001:db8::1]:443\n",
        );
        let mut caps = load(&m, &kp, &trusted("k1", &kp), 0).unwrap();
        assert_eq!(
            caps.take_net("api").map(|n| n.name().to_owned()).as_deref(),
            Some("api")
        );
        assert!(caps.take_net("api").is_none());
        assert!(caps.take_net("db").is_some());
        assert!(caps.take_net("v6").is_some());
        for bad in [
            "net api api.example.com\n",
            "net api api.example.com:443 public\n",
            "net api api.example.com:443 private extra\n",
            "net ../x api.example.com:443\n",
            "net api\n",
        ] {
            assert!(
                matches!(
                    load(&manifest("k1", 1, LATER, bad), &kp, &trusted("k1", &kp), 0),
                    Err(ManifestError::Syntax(6))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_dns_fallback_line_parses_once() {
        let kp = keys();
        let t = trusted("k1", &kp);
        assert!(
            load(
                &manifest(
                    "k1",
                    1,
                    LATER,
                    "dns fallback cloudflare\nnet api api.example.com:443\n"
                ),
                &kp,
                &t,
                0
            )
            .is_ok()
        );
        assert!(matches!(
            load(
                &manifest("k1", 1, LATER, "dns fallback quad9\n"),
                &kp,
                &t,
                0
            ),
            Err(ManifestError::Syntax(6))
        ));
        assert!(matches!(
            load(
                &manifest(
                    "k1",
                    1,
                    LATER,
                    "dns fallback google\ndns fallback cloudflare\n"
                ),
                &kp,
                &t,
                0
            ),
            Err(ManifestError::Duplicate(_))
        ));
    }

    #[test]
    fn an_older_serial_is_refused_as_a_replay() {
        let kp = keys();
        let t = trusted("k1", &kp);
        let m = manifest("k1", 5, LATER, "");
        assert!(load(&m, &kp, &t, 5).is_ok());
        assert!(load(&m, &kp, &t, 4).is_ok());
        assert!(matches!(
            load(&m, &kp, &t, 6),
            Err(ManifestError::Rollback { serial: 5, min: 6 })
        ));
    }

    #[test]
    fn verified_manifest_reports_its_header() {
        let kp = keys();
        let t = trusted("k1", &kp);
        let m = manifest("k1", 7, LATER, "declassify r\n");
        let v = verify(
            m.as_bytes(),
            Signature(&sign(&kp, m.as_bytes())),
            &t,
            UnixTime(0),
            MinSerial(0),
        )
        .unwrap();
        assert_eq!((v.key.as_str(), v.serial, v.not_after), ("k1", 7, LATER));
        assert_eq!(
            v.grants,
            [Grant::Declassify {
                name: "r".to_owned()
            }]
        );
    }

    #[test]
    fn the_program_digest_is_returned_verified() {
        let kp = keys();
        let m = manifest("k1", 1, LATER, "");
        let v = verify(
            m.as_bytes(),
            Signature(&sign(&kp, m.as_bytes())),
            &trusted("k1", &kp),
            UnixTime(0),
            MinSerial(0),
        )
        .unwrap();
        // SHA-256 of "abc" (FIPS 180-4, appendix B.1).
        assert_eq!(v.program_sha256[..4], [0xba, 0x78, 0x16, 0xbf]);
        assert_eq!(v.program_sha256[28..], [0xf2, 0x00, 0x15, 0xad]);
    }

    #[test]
    fn malformed_headers_and_entries_are_refused() {
        let kp = keys();
        let t = trusted("k1", &kp);
        let h = |rest: &str| format!("corten-manifest 3\nkey k1\n{rest}");
        let prog_line = |line: &str| {
            format!("corten-manifest 3\nkey k1\nserial 1\nnot-after {LATER}\n{line}\n")
        };
        for (m, want_line) in [
            // Format 1 is refused, even with a format-2 header below it.
            (
                "corten-manifest 1\nexec tar /usr/bin/tar\n".to_owned(),
                Some(1),
            ),
            (
                format!("corten-manifest 1\nkey k1\nserial 1\nnot-after {LATER}\n"),
                Some(1),
            ),
            // Format 2 (no program line) is refused.
            (
                format!("corten-manifest 2\nkey k1\nserial 1\nnot-after {LATER}\n"),
                Some(1),
            ),
            ("corten-manifest 3\nserial 1\n".to_owned(), Some(1)),
            // The program line: required, sha256, 64 lowercase hex digits.
            (prog_line("exec tar /usr/bin/tar"), Some(5)),
            (prog_line(""), Some(5)),
            (prog_line("program sha512 ba78"), Some(5)),
            (
                prog_line(
                    &PROGRAM
                        .to_uppercase()
                        .replace("PROGRAM SHA256", "program sha256"),
                ),
                Some(5),
            ),
            (prog_line(PROGRAM.strip_suffix('d').unwrap()), Some(5)),
            (prog_line(&format!("{PROGRAM}0")), Some(5)),
            (prog_line(&PROGRAM.replace("ba78", "ga78")), Some(5)),
            (h("not-after 9\nserial 1\n"), Some(3)),
            (h("serial 1\n"), Some(4)),
            (h("serial -1\nnot-after 9\n"), Some(3)),
            (h("serial 01\nnot-after 9\n"), Some(3)),
            (h("serial 1 2\nnot-after 9\n"), Some(3)),
            (h("serial 18446744073709551616\nnot-after 9\n"), Some(3)),
            (h(&format!("serial 1\nnot-after {LATER}x\n")), Some(4)),
            (manifest("k1", 1, LATER, "exec ../x /bin/x\n"), Some(6)),
            (manifest("k1", 1, LATER, "exec tar relative/tar\n"), Some(6)),
            (manifest("k1", 1, LATER, "net x /y\n"), Some(6)),
            (manifest("k1", 1, LATER, "exec tar /a /b\n"), Some(6)),
            (manifest("k1", 1, LATER, "exec tar /a\nexec tar /b\n"), None),
            (
                manifest("k1", 1, LATER, "declassify report /etc\n"),
                Some(6),
            ),
            (manifest("k1", 1, LATER, "dir data\n"), Some(6)),
            (manifest("k1", 1, LATER, "declassify ../up\n"), Some(6)),
            (
                manifest("k1", 1, LATER, "declassify tar\nexec tar /bin/tar\n"),
                None,
            ),
        ] {
            let r = load(&m, &kp, &t, 0);
            match want_line {
                Some(line) => assert!(
                    matches!(r, Err(ManifestError::Syntax(l)) if l == line),
                    "{m:?}: {r:?}"
                ),
                None => assert!(
                    matches!(r, Err(ManifestError::Duplicate(_))),
                    "{m:?}: {r:?}"
                ),
            }
        }
        let big = vec![b'a'; MAX_MANIFEST.saturating_add(1)];
        assert!(matches!(
            Capabilities::load(&big, Signature(&[0u8; 64]), &t, MinSerial(0)),
            Err(ManifestError::TooLarge)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dir_entries_open_at_load() {
        let dir = std::env::temp_dir().join(format!("corten-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kp = keys();
        let t = trusted("k1", &kp);
        let m = manifest("k1", 1, LATER, &format!("dir data {}\n", dir.display()));
        let mut caps = load(&m, &kp, &t, 0).unwrap();
        assert!(caps.take_dir("data").is_some());
        let missing = manifest("k1", 1, LATER, "dir data /nonexistent/corten\n");
        assert!(matches!(
            load(&missing, &kp, &t, 0),
            Err(ManifestError::Dir { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn dir_entries_fail_closed_off_linux() {
        let kp = keys();
        let m = manifest("k1", 1, LATER, "dir data /tmp\n");
        assert!(matches!(
            load(&m, &kp, &trusted("k1", &kp), 0),
            Err(ManifestError::Dir {
                error: FsError::Unsupported,
                ..
            })
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}")).unwrap();
            s
        })
    }

    fn grants(body: &str) -> Result<Vec<Grant>, ManifestError> {
        let kp = keys();
        let m = manifest("k1", 1, LATER, body);
        verify(
            m.as_bytes(),
            Signature(&sign(&kp, m.as_bytes())),
            &trusted("k1", &kp),
            UnixTime(0),
            MinSerial(0),
        )
        .map(|v| v.grants)
    }

    #[test]
    fn protected_is_a_dir_flag_only() {
        assert_eq!(
            grants("dir a /srv/a protected\ndir b /srv/b\n").unwrap(),
            [
                Grant::Dir {
                    name: "a".into(),
                    path: "/srv/a".into(),
                    protected: true
                },
                Grant::Dir {
                    name: "b".into(),
                    path: "/srv/b".into(),
                    protected: false
                },
            ]
        );
        for bad in [
            "exec t /usr/bin/tar protected\n",
            "dir a /srv/a private\n",
            "dir a /srv/a protected extra\n",
            "declassify r protected\n",
        ] {
            assert!(
                matches!(grants(bad), Err(ManifestError::Syntax(6))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn authn_grants_parse_and_refuse_malformed_lines() {
        let kp = keys();
        let hex = hex(kp.pk.as_ref());
        let g = grants(&format!("authn api token k1:{hex},k2:{hex}\n")).unwrap();
        assert_eq!(
            g,
            [Grant::Authn {
                name: "api".into(),
                method: AuthnMethod::Token {
                    keys: vec![("k1".into(), *kp.pk), ("k2".into(), *kp.pk)]
                },
            },]
        );
        for bad in [
            format!("authn api token k1:{hex},k1:{hex}"),
            format!("authn api token k.1:{hex}"),
            format!("authn api token k1:{}", hex.to_uppercase()),
            format!("authn api token k1:{}", hex.get(..62).unwrap()),
            format!("authn a.b token k1:{hex}"),
            "authn api token".to_owned(),
            "authn api oauth x".to_owned(),
            // No password authenticator: only phishing-resistant
            // authentication is accepted (owner decision 2026-11-13).
            "authn staff password /etc/app/users".to_owned(),
        ] {
            assert!(
                matches!(grants(&format!("{bad}\n")), Err(ManifestError::Syntax(6))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_protected_dir_and_authenticators_are_taken_only_by_their_own_kind() {
        let kp = keys();
        let hex = hex(kp.pk.as_ref());
        let m = manifest("k1", 1, LATER, &format!("authn api token k1:{hex}\n"));
        let mut caps = load(&m, &kp, &trusted("k1", &kp), 0).unwrap();
        assert!(caps.take_dir("api").is_none());
        assert_eq!(
            caps.take_token_authenticator("api")
                .map(|a| a.name().to_owned()),
            Some("api".to_owned())
        );
        assert!(caps.take_token_authenticator("api").is_none());
    }

    /// A protected `dir` grant is reachable only as a `ProtectedDir`
    /// (CWE-288: no alternate path to the same directory).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_protected_dir_is_not_a_plain_dir() {
        let dir = std::env::temp_dir().join(format!("corten-pdir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kp = keys();
        let m = manifest(
            "k1",
            1,
            LATER,
            &format!(
                "dir p {} protected\ndir q {}\n",
                dir.display(),
                dir.display()
            ),
        );
        let mut caps = load(&m, &kp, &trusted("k1", &kp), 0).unwrap();
        assert!(caps.take_dir("p").is_none());
        assert!(caps.take_protected_dir("q").is_none());
        assert_eq!(
            caps.take_protected_dir("p").map(|d| d.name().to_owned()),
            Some("p".into())
        );
        assert!(caps.take_dir("q").is_some());
        let _ignored = std::fs::remove_dir_all(&dir);
    }
}
