//! `Secret` (spec 4.9; amendments "every wipe is observable" and "secret
//! spill control").
//!
//! A `Secret` has no `Copy`, `Clone`, `Debug` or `Display`, so it cannot be
//! duplicated, printed or logged by accident; reading it takes an explicit
//! closure. Its bytes are:
//!
//! - wiped on drop with the `zeroize` crate, whose writes the optimiser may
//!   not remove;
//! - locked in memory (`mlock` through the `region` crate), so they are not
//!   swapped out; creation fails if the lock fails (fail closed);
//! - excluded from core dumps on Linux by marking the whole process
//!   non-dumpable (`PR_SET_DUMPABLE`), because a per-page `MADV_DONTDUMP`
//!   needs `unsafe`, which Corten's own crates do not use.
//!
//! Comparison is constant-time in the contents (the length is not secret).

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Why a secret could not be created.
#[derive(Debug)]
pub enum SecretError {
    /// Locking the memory failed (for example `RLIMIT_MEMLOCK`).
    Lock(String),
    /// Marking the process non-dumpable failed.
    NoDump(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lock(e) => write!(f, "could not lock secret memory: {e}"),
            Self::NoDump(e) => write!(f, "could not exclude the process from core dumps: {e}"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Secret bytes. See the module documentation.
pub struct Secret {
    // Declared first so it drops (unlocks) after `Drop::drop` has wiped the
    // bytes and before the bytes are freed.
    _lock: Option<region::LockGuard>,
    bytes: Box<[u8]>,
}

#[cfg(target_os = "linux")]
fn exclude_from_dumps() -> Result<(), SecretError> {
    static DONE: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    DONE.get_or_init(|| {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|e| e.to_string())
    })
    .clone()
    .map_err(SecretError::NoDump)
}

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the Linux version, which can fail"
)]
fn exclude_from_dumps() -> Result<(), SecretError> {
    Ok(())
}

impl Secret {
    /// Takes ownership of `bytes`, wiping the vector it came in.
    ///
    /// # Errors
    ///
    /// [`SecretError`] if the memory cannot be locked or, on Linux, the
    /// process cannot be marked non-dumpable.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, SecretError> {
        exclude_from_dumps()?;
        // Copy into an exactly-sized allocation that never grows, then wipe
        // the original (including any spare capacity).
        let boxed: Box<[u8]> = bytes.as_slice().into();
        bytes.zeroize();
        let lock = if boxed.is_empty() {
            None
        } else {
            Some(
                region::lock(boxed.as_ptr(), boxed.len())
                    .map_err(|e| SecretError::Lock(e.to_string()))?,
            )
        };
        Ok(Self {
            _lock: lock,
            bytes: boxed,
        })
    }

    /// Takes ownership of a string's bytes, wiping the string.
    ///
    /// # Errors
    ///
    /// As [`Secret::new`].
    pub fn from_string(text: String) -> Result<Self, SecretError> {
        Self::new(text.into_bytes())
    }

    /// Runs `f` with the secret bytes. The only way to read them.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }

    /// Constant-time comparison of the contents with `other`.
    #[must_use]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        self.bytes.len() == other.len() && bool::from(self.bytes.as_ref().ct_eq(other))
    }

    /// Length in bytes (not secret).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_and_compares() {
        let s = Secret::from_string("hunter2".to_owned()).unwrap();
        assert_eq!(s.len(), 7);
        assert!(s.ct_eq(b"hunter2"));
        assert!(!s.ct_eq(b"hunter3"));
        assert!(!s.ct_eq(b"hunter"));
        assert_eq!(s.expose(<[u8]>::to_vec), b"hunter2");
    }

    #[test]
    fn empty_secret_is_allowed() {
        let s = Secret::new(Vec::new()).unwrap();
        assert!(s.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_becomes_non_dumpable() {
        let _s = Secret::new(vec![1, 2, 3]).unwrap();
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }
}
