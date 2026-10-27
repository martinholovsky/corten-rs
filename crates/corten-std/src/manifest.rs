//! The signed capability manifest (spec 4.3): the only source of a root
//! [`DirCap`], an [`ExecCap`] or a [`DeclassifyCap`].
//!
//! Format, UTF-8, one entry per line:
//!
//! ```text
//! corten-manifest 1
//! dir uploads /srv/app/uploads
//! exec tar /usr/bin/tar
//! declassify report
//! ```
//!
//! Names follow the `PathSeg` grammar; paths are absolute. `declassify NAME`
//! (Phase 4) grants the right to release a labelled value as public
//! (`crate::label`); it names no path. The deployer signs
//! the exact bytes with Ed25519. [`Capabilities::load`] checks the signature
//! before it parses anything, refuses a manifest over [`MAX_MANIFEST`] bytes,
//! and opens every directory up front, so a missing directory or a platform
//! without `openat2` fails at start-up rather than later.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::label::DeclassifyCap;

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
    declassify: BTreeMap<String, DeclassifyCap>,
}

/// One verified manifest entry. A grant is data: holding one confers no
/// authority (the application has no ambient API that takes a path). The
/// runtime sandbox (`corten-sandbox --manifest`) turns grants into kernel
/// rules; [`Capabilities::load`] turns them into capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// `dir NAME PATH`: read and write beneath `PATH`.
    Dir {
        /// Manifest name.
        name: String,
        /// Absolute path.
        path: PathBuf,
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
}

impl Grant {
    fn name(&self) -> &str {
        match self {
            Self::Dir { name, .. } | Self::Exec { name, .. } | Self::Declassify { name } => name,
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

/// Verifies the signature, then parses the manifest and checks names are
/// unique. Nothing is opened.
///
/// # Errors
///
/// [`ManifestError`]; nothing is parsed unless the signature is valid.
pub fn verify(
    manifest: &[u8],
    Signature(signature): Signature<'_>,
    PublicKey(public_key): PublicKey<'_>,
) -> Result<Vec<Grant>, ManifestError> {
    if manifest.len() > MAX_MANIFEST {
        return Err(ManifestError::TooLarge);
    }
    let key =
        ed25519_compact::PublicKey::from_slice(public_key).map_err(|_| ManifestError::Signature)?;
    let sig =
        ed25519_compact::Signature::from_slice(signature).map_err(|_| ManifestError::Signature)?;
    key.verify(manifest, &sig)
        .map_err(|_| ManifestError::Signature)?;
    let text = std::str::from_utf8(manifest).map_err(|_| ManifestError::Syntax(1))?;
    let grants = parse(text)?;
    let mut seen = std::collections::BTreeSet::new();
    for g in &grants {
        if !seen.insert(g.name()) {
            return Err(ManifestError::Duplicate(g.name().to_owned()));
        }
    }
    Ok(grants)
}

fn parse(text: &str) -> Result<Vec<Grant>, ManifestError> {
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
        let (Some(kind), Some(name), path, None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ManifestError::Syntax(number));
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
            },
            "exec" => Grant::Exec {
                name: name.to_owned(),
                path: path.to_path_buf(),
            },
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
        signature: Signature<'_>,
        public_key: PublicKey<'_>,
    ) -> Result<Self, ManifestError> {
        let mut caps = Self::default();
        for grant in verify(manifest, signature, public_key)? {
            match grant {
                Grant::Dir { name, path } => {
                    let dir = DirCap::open_root(&path).map_err(|error| ManifestError::Dir {
                        name: name.clone(),
                        error,
                    })?;
                    // verify() refused duplicate names; a second insert
                    // would mean it did not.
                    if caps.dirs.insert(name.clone(), dir).is_some() {
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

    /// Takes the declassification capability named `name`, once.
    pub fn take_declassify(&mut self, name: &str) -> Option<DeclassifyCap> {
        self.declassify.remove(name)
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
        let mut caps =
            Capabilities::load(m, Signature(&sign(&kp, m)), PublicKey(kp.pk.as_ref())).unwrap();
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
        let m = b"corten-manifest 1\ndeclassify report\n";
        let mut caps =
            Capabilities::load(m, Signature(&sign(&kp, m)), PublicKey(kp.pk.as_ref())).unwrap();
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
        let m = b"corten-manifest 1\nexec tar /usr/bin/tar\n";
        let sig = sign(&kp, m);
        let tampered = b"corten-manifest 1\nexec tar /usr/bin/sh!\n";
        assert!(matches!(
            Capabilities::load(tampered, Signature(&sig), PublicKey(kp.pk.as_ref())),
            Err(ManifestError::Signature)
        ));
        let other = KeyPair::from_seed(Seed::new([8u8; 32]));
        assert!(matches!(
            Capabilities::load(m, Signature(&sig), PublicKey(other.pk.as_ref())),
            Err(ManifestError::Signature)
        ));
        assert!(matches!(
            Capabilities::load(m, Signature(&[0u8; 3]), PublicKey(kp.pk.as_ref())),
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
            // `declassify` takes a name and nothing else; `dir` still needs a path.
            (b"corten-manifest 1\ndeclassify report /etc\n", Some(2)),
            (b"corten-manifest 1\ndir data\n", Some(2)),
            (b"corten-manifest 1\ndeclassify ../up\n", Some(2)),
            (
                b"corten-manifest 1\ndeclassify tar\nexec tar /bin/tar\n",
                None,
            ),
        ] {
            let r = Capabilities::load(m, Signature(&sign(&kp, m)), PublicKey(kp.pk.as_ref()));
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
            Capabilities::load(&big, Signature(&[0u8; 64]), PublicKey(kp.pk.as_ref())),
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
        let mut caps = Capabilities::load(
            m.as_bytes(),
            Signature(&sign(&kp, m.as_bytes())),
            PublicKey(kp.pk.as_ref()),
        )
        .unwrap();
        assert!(caps.take_dir("data").is_some());
        let missing = "corten-manifest 1\ndir data /nonexistent/corten\n";
        assert!(matches!(
            Capabilities::load(
                missing.as_bytes(),
                Signature(&sign(&kp, missing.as_bytes())),
                PublicKey(kp.pk.as_ref())
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
            Capabilities::load(m, Signature(&sign(&kp, m)), PublicKey(kp.pk.as_ref())),
            Err(ManifestError::Dir {
                error: FsError::Unsupported,
                ..
            })
        ));
    }
}
