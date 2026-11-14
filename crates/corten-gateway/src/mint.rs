//! Minting Corten tokens (`docs/gates/gateway-proposal.md`): the only
//! credential a Corten program accepts (`corten_std::authz::TokenAuthenticator`).
//!
//! The signing key is a `corten-manifest keygen` file (`corten-signing-key 1`),
//! so an operator makes it with the tool that already signs manifests, and
//! the `ID=HEX` that `keygen` prints is the program manifest's
//! `authn NAME token ID:HEX` entry (design principle 10). The file is refused
//! as `corten-manifest` refuses it: not a regular file, accessible to group or
//! others, or owned by another user than its directory, which must not be
//! writable by group or others either.
//!
//! A token names a principal only if the provider's subject is already a
//! valid principal name (`corten_std::authz::token_field`). It is refused,
//! never rewritten: a mapping could make two subjects one principal.

use std::path::Path;

use corten_std::authz::{MAX_TOKEN_LIFETIME, token_field};

/// Default lifetime of a minted token, in seconds.
pub const DEFAULT_LIFETIME: u64 = 300;

const KEY_HEADER: &str = "corten-signing-key 1";
const MAX_KEY_FILE: u64 = 4096;

/// Why a token was not minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// The provider's subject is not a valid principal name.
    Principal,
    /// The expiry would overflow.
    Clock,
}

/// Signs Corten tokens for one program grant (its `authn` name).
pub struct Minter {
    kid: String,
    key: ed25519_compact::KeyPair,
    audience: String,
    lifetime: u64,
}

impl std::fmt::Debug for Minter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minter")
            .field("kid", &self.kid)
            .field("audience", &self.audience)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0u8; 32];
    let (pairs, []) = bytes.as_chunks::<2>() else {
        return None;
    };
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = nibble(hi)?.wrapping_shl(4) | nibble(lo)?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ok = write!(s, "{b:02x}");
        s
    })
}

impl Minter {
    /// Reads the key file and checks the grant name and lifetime.
    ///
    /// # Errors
    ///
    /// A message naming the file or value refused.
    pub fn from_key_file(path: &Path, audience: &str, lifetime: u64) -> Result<Self, String> {
        use std::io::Read as _;
        use std::os::unix::fs::MetadataExt as _;
        if !token_field(audience) {
            return Err(format!("{audience:?} is not a valid authn grant name"));
        }
        if lifetime == 0 || lifetime > MAX_TOKEN_LIFETIME {
            return Err(format!(
                "token lifetime {lifetime} s is outside 1 to {MAX_TOKEN_LIFETIME}"
            ));
        }
        let shown = path.display();
        let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{shown}: {e}"))?;
        if !meta.file_type().is_file() {
            return Err(format!("{shown} is not a regular file"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "{shown} is accessible to group or others (mode {:o}); chmod 600 it",
                meta.mode() & 0o7777
            ));
        }
        let dir = path
            .parent()
            .ok_or_else(|| format!("{shown} has no directory"))?;
        let dir_meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if dir_meta.mode() & 0o022 != 0 {
            return Err(format!("{} is writable by group or others", dir.display()));
        }
        if meta.uid() != dir_meta.uid() {
            return Err(format!(
                "{shown} is owned by uid {}, not by its directory's owner (uid {})",
                meta.uid(),
                dir_meta.uid()
            ));
        }
        let mut text = String::new();
        let _read = std::fs::File::open(path)
            .map_err(|e| format!("{shown}: {e}"))?
            .take(MAX_KEY_FILE)
            .read_to_string(&mut text)
            .map_err(|_| format!("{shown} is not a key file"))?;
        let bad = || format!("{shown} is not a {KEY_HEADER} file");
        let mut lines = text.lines();
        if lines.next() != Some(KEY_HEADER) {
            return Err(bad());
        }
        let kid = lines
            .next()
            .and_then(|l| l.strip_prefix("id "))
            .filter(|id| token_field(id))
            .ok_or_else(bad)?;
        let seed = lines
            .next()
            .and_then(|l| l.strip_prefix("seed "))
            .and_then(hex32)
            .ok_or_else(bad)?;
        if lines.next().is_some() {
            return Err(bad());
        }
        Ok(Self {
            kid: kid.to_owned(),
            key: ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed)),
            audience: audience.to_owned(),
            lifetime,
        })
    }

    /// The program manifest's key entry, `ID:HEX`, for `authn NAME token`.
    #[must_use]
    pub fn manifest_entry(&self) -> String {
        format!("{}:{}", self.kid, hex(self.key.pk.as_ref()))
    }

    /// A token naming `principal`, valid from `now` for the configured
    /// lifetime.
    ///
    /// # Errors
    ///
    /// [`MintError::Principal`] if `principal` is not a valid principal
    /// name; [`MintError::Clock`] if the expiry overflows.
    pub fn mint(&self, principal: &str, now: u64) -> Result<String, MintError> {
        if !token_field(principal) {
            return Err(MintError::Principal);
        }
        let not_after = now.checked_add(self.lifetime).ok_or(MintError::Clock)?;
        let signed = format!(
            "corten-token-1.{}.{}.{principal}.{not_after}",
            self.kid, self.audience
        );
        let sig = self.key.sk.sign(signed.as_bytes(), None);
        Ok(format!("{signed}.{}", hex(sig.as_ref())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corten_std::authz::Token;
    use corten_std::log::{LogRecord, LogWriter};
    use corten_std::manifest::{Capabilities, KeyId, MinSerial, PublicKey, Signature, TrustedKeys};
    use std::os::unix::fs::PermissionsExt as _;

    struct Collect(Vec<String>);
    impl LogWriter for Collect {
        fn write(&mut self, record: &LogRecord) {
            self.0.push(record.render());
        }
    }

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("corten-mint-{tag}-{}", std::process::id()));
            let _gone = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(d)
        }
        fn key(&self, text: &str, mode: u32) -> std::path::PathBuf {
            let p = self.0.join("gw.key");
            std::fs::write(&p, text).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _gone = std::fs::remove_dir_all(&self.0);
        }
    }

    const SEED: &str = "0707070707070707070707070707070707070707070707070707070707070707";

    fn key_text(id: &str) -> String {
        format!("corten-signing-key 1\nid {id}\nseed {SEED}\n")
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn a_minted_token_authenticates_through_corten_std() {
        let d = Dir::new("roundtrip");
        let minter =
            Minter::from_key_file(&d.key(&key_text("gw-1"), 0o600), "api", DEFAULT_LIFETIME)
                .unwrap();
        // A deployer key signs a manifest naming the gateway's key, as an operator would.
        let deployer = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([9; 32]));
        let manifest = format!(
            "corten-manifest 3\nkey dep\nserial 1\nnot-after 4102444800\nprogram sha256 {}\nauthn api token {}\n",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            minter.manifest_entry()
        );
        let mut trusted = TrustedKeys::new();
        trusted
            .add(KeyId("dep"), PublicKey(deployer.pk.as_ref()))
            .unwrap();
        let sig = deployer.sk.sign(manifest.as_bytes(), None);
        let mut caps = Capabilities::load(
            manifest.as_bytes(),
            Signature(sig.as_ref()),
            &trusted,
            MinSerial(0),
        )
        .unwrap();
        let auth = caps.take_token_authenticator("api").unwrap();
        let mut log = Collect(Vec::new());
        let token = minter.mint("user-1", now()).unwrap();
        let who = auth.authenticate(Token(&token), &mut log).unwrap();
        assert_eq!((who.principal(), who.authenticator()), ("user-1", "api"));
        // A token minted for another grant name is refused by this one.
        let other =
            Minter::from_key_file(&d.key(&key_text("gw-1"), 0o600), "web", DEFAULT_LIFETIME)
                .unwrap();
        assert!(
            auth.authenticate(Token(&other.mint("user-1", now()).unwrap()), &mut log)
                .is_err()
        );
        assert!(log.0.last().unwrap().contains("other audience"));
    }

    #[test]
    fn a_subject_that_is_not_a_principal_name_is_refused_not_rewritten() {
        let d = Dir::new("principal");
        let m = Minter::from_key_file(&d.key(&key_text("gw-1"), 0o600), "api", 60).unwrap();
        for bad in ["", "a.b", "user@example.com", "a b", &"x".repeat(65)] {
            assert_eq!(m.mint(bad, 1), Err(MintError::Principal), "{bad:?}");
        }
        assert_eq!(m.mint("ok", u64::MAX), Err(MintError::Clock));
        let t = m.mint("u", 1000).unwrap();
        assert!(t.starts_with("corten-token-1.gw-1.api.u.1060."), "{t}");
        assert!(!format!("{m:?}").contains(SEED), "the key is not printed");
    }

    #[test]
    fn the_key_file_is_refused_as_corten_manifest_refuses_it() {
        let d = Dir::new("refuse");
        let ok = key_text("gw-1");
        let dotted = key_text("gw.1");
        // Only the header is wrong, so only the header check can refuse it.
        let wrong_header = ok.replace("corten-signing-key 1", "corten-signing-key 2");
        let extra = format!("{ok}extra\n");
        for (text, mode, want) in [
            (ok.as_str(), 0o640, "accessible to group or others"),
            (ok.as_str(), 0o604, "accessible to group or others"),
            (
                wrong_header.as_str(),
                0o600,
                "is not a corten-signing-key 1 file",
            ),
            (dotted.as_str(), 0o600, "is not a corten-signing-key 1 file"),
            (extra.as_str(), 0o600, "is not a corten-signing-key 1 file"),
        ] {
            let p = d.key(text, mode);
            let err = Minter::from_key_file(&p, "api", 60).unwrap_err();
            assert!(err.contains(want), "{err}");
        }
        let p = d.key(&ok, 0o600);
        // A symlink to the key, and a directory others can write.
        let link = d.0.join("link.key");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(
            Minter::from_key_file(&link, "api", 60)
                .unwrap_err()
                .contains("not a regular file")
        );
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            Minter::from_key_file(&p, "api", 60)
                .unwrap_err()
                .contains("writable by group or others")
        );
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Lifetime and grant name.
        assert!(
            Minter::from_key_file(&p, "api", 0)
                .unwrap_err()
                .contains("lifetime")
        );
        assert!(
            Minter::from_key_file(&p, "api", MAX_TOKEN_LIFETIME + 1)
                .unwrap_err()
                .contains("lifetime")
        );
        assert!(
            Minter::from_key_file(&p, "a.b", 60)
                .unwrap_err()
                .contains("grant name")
        );
        assert!(Minter::from_key_file(&p, "api", MAX_TOKEN_LIFETIME).is_ok());
    }
}
