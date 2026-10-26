//! The signed capability manifest (spec 4.3): the only source of a root
//! [`DirCap`] or an [`ExecCap`].
//!
//! Format, UTF-8, one entry per line:
//!
//! ```text
//! corten-manifest 1
//! dir uploads /srv/app/uploads
//! exec tar /usr/bin/tar
//! ```
//!
//! Names follow the `PathSeg` grammar; paths are absolute. The deployer signs
//! the exact bytes with Ed25519. [`Capabilities::load`] checks the signature
//! before it parses anything, refuses a manifest over [`MAX_MANIFEST`] bytes,
//! and opens every directory up front, so a missing directory or a platform
//! without `openat2` fails at start-up rather than later.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::fs::{DirCap, FsError};
use crate::path::PathSeg;
use crate::process::ExecCap;

/// Largest manifest accepted, in bytes.
pub const MAX_MANIFEST: usize = 65_536;

const HEADER: &str = "corten-manifest 1";

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
    execs: BTreeMap<String, ExecCap>,
}

enum Entry {
    Dir(String, PathBuf),
    Exec(String, PathBuf),
}

fn parse(text: &str) -> Result<Vec<Entry>, ManifestError> {
    let mut lines = (1usize..).zip(text.lines());
    match lines.next() {
        Some((_, HEADER)) => {}
        _ => return Err(ManifestError::Syntax(1)),
    }
    let mut entries = Vec::new();
    for (number, line) in lines {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(' ');
        let (Some(kind), Some(name), Some(path), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ManifestError::Syntax(number));
        };
        if PathSeg::parse(name).is_err() {
            return Err(ManifestError::Syntax(number));
        }
        let path = Path::new(path);
        if !path.is_absolute() || path.to_str().is_none_or(|p| p.contains('\0')) {
            return Err(ManifestError::Syntax(number));
        }
        entries.push(match kind {
            "dir" => Entry::Dir(name.to_owned(), path.to_path_buf()),
            "exec" => Entry::Exec(name.to_owned(), path.to_path_buf()),
            _ => return Err(ManifestError::Syntax(number)),
        });
    }
    Ok(entries)
}

impl Capabilities {
    /// Verifies `signature` over `manifest` with `public_key`, then parses
    /// it and opens every granted directory.
    ///
    /// # Errors
    ///
    /// [`ManifestError`]; nothing is opened unless the signature is valid.
    pub fn load(
        manifest: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<Self, ManifestError> {
        if manifest.len() > MAX_MANIFEST {
            return Err(ManifestError::TooLarge);
        }
        let key = ed25519_compact::PublicKey::from_slice(public_key)
            .map_err(|_| ManifestError::Signature)?;
        let sig = ed25519_compact::Signature::from_slice(signature)
            .map_err(|_| ManifestError::Signature)?;
        key.verify(manifest, &sig)
            .map_err(|_| ManifestError::Signature)?;
        let text = std::str::from_utf8(manifest).map_err(|_| ManifestError::Syntax(1))?;
        let mut caps = Self::default();
        for entry in parse(text)? {
            match entry {
                Entry::Dir(name, path) => {
                    if caps.dirs.contains_key(&name) || caps.execs.contains_key(&name) {
                        return Err(ManifestError::Duplicate(name));
                    }
                    let dir = DirCap::open_root(&path).map_err(|error| ManifestError::Dir {
                        name: name.clone(),
                        error,
                    })?;
                    caps.dirs.insert(name, dir);
                }
                Entry::Exec(name, path) => {
                    if caps.dirs.contains_key(&name) || caps.execs.contains_key(&name) {
                        return Err(ManifestError::Duplicate(name));
                    }
                    caps.execs.insert(name.clone(), ExecCap::new(name, path));
                }
            }
        }
        Ok(caps)
    }

    /// Takes the directory capability named `name`, once.
    pub fn take_dir(&mut self, name: &str) -> Option<DirCap> {
        self.dirs.remove(name)
    }

    /// Takes the program capability named `name`, once.
    pub fn take_exec(&mut self, name: &str) -> Option<ExecCap> {
        self.execs.remove(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    fn keys() -> KeyPair {
        KeyPair::from_seed(Seed::new([7u8; 32]))
    }

    fn sign(kp: &KeyPair, m: &[u8]) -> Vec<u8> {
        kp.sk.sign(m, None).to_vec()
    }

    #[test]
    fn signed_exec_manifest_loads_once() {
        let kp = keys();
        let m = b"corten-manifest 1\nexec tar /usr/bin/tar\n";
        let mut caps = Capabilities::load(m, &sign(&kp, m), kp.pk.as_ref()).unwrap();
        assert_eq!(
            caps.take_exec("tar")
                .map(|e| e.name().to_owned())
                .as_deref(),
            Some("tar")
        );
        assert!(caps.take_exec("tar").is_none());
    }

    #[test]
    fn tampered_manifest_is_refused_before_parsing() {
        let kp = keys();
        let m = b"corten-manifest 1\nexec tar /usr/bin/tar\n";
        let sig = sign(&kp, m);
        let tampered = b"corten-manifest 1\nexec tar /usr/bin/sh!\n";
        assert!(matches!(
            Capabilities::load(tampered, &sig, kp.pk.as_ref()),
            Err(ManifestError::Signature)
        ));
        let other = KeyPair::from_seed(Seed::new([8u8; 32]));
        assert!(matches!(
            Capabilities::load(m, &sig, other.pk.as_ref()),
            Err(ManifestError::Signature)
        ));
        assert!(matches!(
            Capabilities::load(m, &[0u8; 3], kp.pk.as_ref()),
            Err(ManifestError::Signature)
        ));
    }

    #[test]
    fn malformed_and_duplicate_entries_are_refused() {
        let kp = keys();
        for (m, want_line) in [
            (&b"corten-manifest 2\n"[..], Some(1)),
            (b"corten-manifest 1\nexec ../x /bin/x\n", Some(2)),
            (b"corten-manifest 1\nexec tar relative/tar\n", Some(2)),
            (b"corten-manifest 1\nnet x /y\n", Some(2)),
            (b"corten-manifest 1\nexec tar /a /b\n", Some(2)),
            (b"corten-manifest 1\nexec tar /a\nexec tar /b\n", None),
        ] {
            let r = Capabilities::load(m, &sign(&kp, m), kp.pk.as_ref());
            match want_line {
                Some(line) => assert!(
                    matches!(r, Err(ManifestError::Syntax(l)) if l == line),
                    "{m:?}"
                ),
                None => assert!(matches!(r, Err(ManifestError::Duplicate(_))), "{m:?}"),
            }
        }
        let big = vec![b'a'; MAX_MANIFEST.saturating_add(1)];
        assert!(matches!(
            Capabilities::load(&big, &[0u8; 64], kp.pk.as_ref()),
            Err(ManifestError::TooLarge)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dir_entries_open_at_load() {
        let dir = std::env::temp_dir().join(format!("corten-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kp = keys();
        let m = format!("corten-manifest 1\ndir data {}\n", dir.display());
        let mut caps =
            Capabilities::load(m.as_bytes(), &sign(&kp, m.as_bytes()), kp.pk.as_ref()).unwrap();
        assert!(caps.take_dir("data").is_some());
        let missing = "corten-manifest 1\ndir data /nonexistent/corten\n";
        assert!(matches!(
            Capabilities::load(
                missing.as_bytes(),
                &sign(&kp, missing.as_bytes()),
                kp.pk.as_ref()
            ),
            Err(ManifestError::Dir { .. })
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn dir_entries_fail_closed_off_linux() {
        let kp = keys();
        let m = b"corten-manifest 1\ndir data /tmp\n";
        assert!(matches!(
            Capabilities::load(m, &sign(&kp, m), kp.pk.as_ref()),
            Err(ManifestError::Dir {
                error: FsError::Unsupported,
                ..
            })
        ));
    }
}
