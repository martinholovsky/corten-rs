//! Authentication and authorization as proof types (Phase 6, strategy 2;
//! `docs/gates/authz-proposal.md`).
//!
//! - An [`Authenticated`] principal comes only from an authenticator the
//!   signed manifest names, today a [`TokenAuthenticator`]
//!   (`authn NAME token ...`). It has no public constructor, so a program
//!   cannot mint a principal (CWE-306, 288). There is no password
//!   authenticator: only phishing-resistant authentication is accepted
//!   (owner decision 2026-11-13). Users sign in with passkeys at an identity
//!   provider, and an exchange gateway turns its assertion into a Corten
//!   token (`docs/gates/phase-6.md`, batch 4).
//! - An [`Authorized`] proof comes only from [`check`], which asks the
//!   program's [`Policy`] and logs the outcome before returning (CWE-862).
//!   It names the action and the resource key it was checked for, it is not
//!   `Clone`, and each protected operation consumes one, so every access is
//!   checked (CWE-638) and a proof for one resource cannot open another
//!   (CWE-639).
//! - A `dir` grant marked `protected` is taken only as a [`ProtectedDir`],
//!   whose operations take the path from the proof.
//!
//! Whether the policy is *right* stays the program's (spec section 7): this
//! module makes the check happen, not the rule correct.
//!
//! The token format is Corten's own, as the manifest's is (owner decision
//! 2026-11-13): one line, `corten-token-1.KEY.AUDIENCE.SUBJECT.NOTAFTER.SIG`,
//! where `SIG` is 128 lowercase hexadecimal digits of an Ed25519 signature
//! over everything before the last `.`. There is no algorithm field. The key
//! is chosen only among the manifest's keys for that authenticator, the
//! audience must be the authenticator's manifest name, and `NOTAFTER` (Unix
//! seconds) must be in the future and at most [`MAX_TOKEN_LIFETIME`] away.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use crate::fs::{CapFile, DirCap, FileMode, FsError, OpenMode};
use crate::log::LogWriter;
use crate::path::RelPath;

/// The longest a token may still be valid for when it is presented, in
/// seconds (15 minutes: an access token's lifetime, since a token cannot be
/// revoked before it expires; remove the key from the manifest to revoke
/// every token it signed).
pub const MAX_TOKEN_LIFETIME: u64 = 900;
/// The longest token accepted, in bytes.
pub const MAX_TOKEN: usize = 512;
const TOKEN_PREFIX: &str = "corten-token-1";

/// Whether `text` is a valid token field (a key identifier, an
/// authenticator name or a principal): `[A-Za-z0-9_-]`, 1 to 64 bytes.
#[must_use]
pub fn token_field(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A principal an authenticator the manifest names has vouched for.
///
/// No public constructor: only [`TokenAuthenticator::authenticate`] returns
/// one.
#[derive(Debug, PartialEq, Eq)]
pub struct Authenticated {
    principal: String,
    authenticator: String,
}

impl Authenticated {
    /// The principal's name.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// The manifest name of the authenticator that vouched for it.
    #[must_use]
    pub fn authenticator(&self) -> &str {
        &self.authenticator
    }
}

/// Why an authentication attempt failed. Deliberately one value: the caller
/// learns nothing about which check failed (CWE-204); the reason is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthnRefused;

impl fmt::Display for AuthnRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authentication failed")
    }
}

impl std::error::Error for AuthnRefused {}

fn refused(
    authenticator: &str,
    method: &str,
    reason: &str,
    log: &mut dyn LogWriter,
) -> AuthnRefused {
    log.write(&crate::log_record!(
        "authn.refused",
        authenticator = authenticator,
        method = method,
        reason = reason
    ));
    AuthnRefused
}

fn accepted(authenticator: &str, method: &str, principal: &str, log: &mut dyn LogWriter) {
    log.write(&crate::log_record!(
        "authn.ok",
        authenticator = authenticator,
        method = method,
        principal = principal
    ));
}

fn now() -> Option<u64> {
    crate::manifest::now().ok().map(|t| t.0)
}

/// Exactly 128 lowercase hexadecimal digits, as 64 bytes.
fn signature_hex(text: &str) -> Option<[u8; 64]> {
    let bytes = text.as_bytes();
    if bytes.len() != 128 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0u8; 64];
    let (pairs, []) = bytes.as_chunks::<2>() else {
        return None;
    };
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = nibble(hi)?.wrapping_shl(4) | nibble(lo)?;
    }
    Some(out)
}

/// A decimal `u64` with no sign, no leading zero and nothing else.
fn decimal(text: &str) -> Option<u64> {
    let canonical =
        text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

/// Verifies Corten tokens signed by the keys an `authn NAME token` grant
/// names. Taken from [`crate::manifest::Capabilities`].
#[derive(Debug)]
pub struct TokenAuthenticator {
    name: String,
    keys: BTreeMap<String, ed25519_compact::PublicKey>,
}

/// A token as presented: a label, so it cannot be passed where another
/// string belongs.
#[derive(Debug, Clone, Copy)]
pub struct Token<'a>(pub &'a str);

impl TokenAuthenticator {
    pub(crate) fn new(name: String, keys: &[(String, [u8; 32])]) -> Option<Self> {
        let mut map = BTreeMap::new();
        for (id, key) in keys {
            let key = ed25519_compact::PublicKey::from_slice(key).ok()?;
            if map.insert(id.clone(), key).is_some() {
                return None;
            }
        }
        Some(Self { name, keys: map })
    }

    /// The authenticator's manifest name, which every token's audience must
    /// equal.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Checks `token` and returns the principal it names. The outcome is
    /// logged (`authn.ok` or `authn.refused` with the reason) before this
    /// returns; the token itself is never logged.
    ///
    /// # Errors
    ///
    /// [`AuthnRefused`] for any failure: malformed, unknown key, bad
    /// signature, another audience, expired, or valid for longer than
    /// [`MAX_TOKEN_LIFETIME`].
    pub fn authenticate(
        &self,
        Token(token): Token<'_>,
        log: &mut dyn LogWriter,
    ) -> Result<Authenticated, AuthnRefused> {
        let refuse =
            |reason: &str, log: &mut dyn LogWriter| Err(refused(&self.name, "token", reason, log));
        if token.len() > MAX_TOKEN {
            return refuse("too long", log);
        }
        let Some((signed, sig)) = token.rsplit_once('.') else {
            return refuse("malformed", log);
        };
        let mut fields = signed.split('.');
        let (
            Some(TOKEN_PREFIX),
            Some(key_id),
            Some(audience),
            Some(subject),
            Some(not_after),
            None,
        ) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        )
        else {
            return refuse("malformed", log);
        };
        // The key identifier selects among the manifest's keys only, and is
        // checked before it is used (it is attacker input).
        if !token_field(key_id) {
            return refuse("malformed", log);
        }
        let Some(key) = self.keys.get(key_id) else {
            return refuse("unknown key", log);
        };
        let Some(sig) = signature_hex(sig) else {
            return refuse("malformed", log);
        };
        let Ok(sig) = ed25519_compact::Signature::from_slice(&sig) else {
            return refuse("malformed", log);
        };
        if key.verify(signed.as_bytes(), &sig).is_err() {
            return refuse("bad signature", log);
        }
        // Claims are read only after the signature holds.
        if audience != self.name {
            return refuse("other audience", log);
        }
        if !token_field(subject) {
            return refuse("malformed", log);
        }
        let (Some(not_after), Some(now)) = (decimal(not_after), now()) else {
            return refuse("malformed or no clock", log);
        };
        if now >= not_after {
            return refuse("expired", log);
        }
        if not_after
            .checked_sub(now)
            .is_none_or(|left| left > MAX_TOKEN_LIFETIME)
        {
            return refuse("lifetime too long", log);
        }
        accepted(&self.name, "token", subject, log);
        Ok(Authenticated {
            principal: subject.to_owned(),
            authenticator: self.name.clone(),
        })
    }
}

/// An action a proof is for. The prelude's protected operations use
/// [`Read`], [`Create`], [`Append`] and [`Remove`]; a program may define its
/// own for its own resources.
pub trait Action {
    /// The action's name in log records.
    const NAME: &'static str;
}

/// Reading a file.
#[derive(Debug, Clone, Copy)]
pub struct Read;
/// Creating a file.
#[derive(Debug, Clone, Copy)]
pub struct Create;
/// Appending to a file.
#[derive(Debug, Clone, Copy)]
pub struct Append;
/// Removing a file.
#[derive(Debug, Clone, Copy)]
pub struct Remove;

impl Action for Read {
    const NAME: &'static str = "read";
}
impl Action for Create {
    const NAME: &'static str = "create";
}
impl Action for Append {
    const NAME: &'static str = "append";
}
impl Action for Remove {
    const NAME: &'static str = "remove";
}

/// A resource key a proof can name; `describe` is what the log records.
pub trait AuthzKey {
    /// The key as the log should show it.
    fn describe(&self) -> String;
}

/// The program's rule: may `who` perform action `A` on `key`? Its
/// correctness is the program's (spec section 7).
pub trait Policy<A: Action, K> {
    /// Whether the action is allowed.
    fn allows(&self, who: &Authenticated, key: &K) -> bool;
}

/// Proof that `check` allowed action `A` on `key` for a principal. Not
/// `Clone`: a protected operation consumes it.
#[derive(Debug)]
pub struct Authorized<A, K> {
    principal: String,
    key: K,
    action: PhantomData<fn() -> A>,
}

impl<A, K> Authorized<A, K> {
    /// The resource key the proof was checked for.
    #[must_use]
    pub fn key(&self) -> &K {
        &self.key
    }

    /// The principal it was checked for.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
}

/// The policy refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("access denied")
    }
}

impl std::error::Error for Denied {}

/// Asks `policy` whether `who` may perform `action` on `key`, logs the
/// outcome (`authz.allowed` or `authz.denied`, with principal, action and
/// key) and returns the proof only when it allowed.
///
/// # Errors
///
/// [`Denied`] when the policy refuses.
pub fn check<A: Action, K: AuthzKey>(
    who: &Authenticated,
    action: A,
    key: K,
    policy: &impl Policy<A, K>,
    log: &mut dyn LogWriter,
) -> Result<Authorized<A, K>, Denied> {
    let _action = action;
    let allowed = policy.allows(who, &key);
    let described = key.describe();
    if allowed {
        log.write(&crate::log_record!(
            "authz.allowed",
            principal = who.principal,
            action = A::NAME,
            key = described
        ));
        Ok(Authorized {
            principal: who.principal.clone(),
            key,
            action: PhantomData,
        })
    } else {
        log.write(&crate::log_record!(
            "authz.denied",
            principal = who.principal,
            action = A::NAME,
            key = described
        ));
        Err(Denied)
    }
}

/// A path in one [`ProtectedDir`]. Only [`ProtectedDir::key`] makes one, so
/// the directory it names cannot be forged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirKey {
    dir: String,
    path: RelPath,
}

impl DirKey {
    /// The protected directory's manifest name.
    #[must_use]
    pub fn dir(&self) -> &str {
        &self.dir
    }

    /// The path beneath it.
    #[must_use]
    pub fn path(&self) -> &RelPath {
        &self.path
    }
}

impl AuthzKey for DirKey {
    fn describe(&self) -> String {
        format!("{}:{}", self.dir, self.path.to_slash_string())
    }
}

/// Why a protected operation failed.
#[derive(Debug)]
pub enum ProtectedError {
    /// The proof was checked for another protected directory.
    OtherDir,
    /// The filesystem operation failed.
    Fs(FsError),
}

impl fmt::Display for ProtectedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherDir => f.write_str("the proof is for another protected directory"),
            Self::Fs(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProtectedError {}

/// A `dir` grant marked `protected`: every operation consumes an
/// [`Authorized`] proof and acts on the path the proof names.
#[derive(Debug)]
pub struct ProtectedDir {
    name: String,
    dir: DirCap,
}

impl ProtectedDir {
    pub(crate) fn new(name: String, dir: DirCap) -> Self {
        Self { name, dir }
    }

    /// The grant's manifest name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key to check before acting on `path` in this directory.
    #[must_use]
    pub fn key(&self, path: RelPath) -> DirKey {
        DirKey {
            dir: self.name.clone(),
            path,
        }
    }

    fn path_of<A>(&self, proof: Authorized<A, DirKey>) -> Result<RelPath, ProtectedError> {
        if proof.key.dir == self.name {
            Ok(proof.key.path)
        } else {
            Err(ProtectedError::OtherDir)
        }
    }

    /// Opens the proof's path for reading.
    ///
    /// # Errors
    ///
    /// [`ProtectedError`].
    pub fn read(&self, proof: Authorized<Read, DirKey>) -> Result<CapFile, ProtectedError> {
        let path = self.path_of(proof)?;
        self.dir
            .open_file(&path, OpenMode::Read)
            .map_err(ProtectedError::Fs)
    }

    /// Creates the proof's path, which must not exist, with `mode`.
    ///
    /// # Errors
    ///
    /// [`ProtectedError`].
    pub fn create(
        &self,
        proof: Authorized<Create, DirKey>,
        mode: FileMode,
    ) -> Result<CapFile, ProtectedError> {
        let path = self.path_of(proof)?;
        self.dir
            .open_file(&path, OpenMode::CreateExclusive(mode))
            .map_err(ProtectedError::Fs)
    }

    /// Opens the proof's path for appending.
    ///
    /// # Errors
    ///
    /// [`ProtectedError`].
    pub fn append(&self, proof: Authorized<Append, DirKey>) -> Result<CapFile, ProtectedError> {
        let path = self.path_of(proof)?;
        self.dir
            .open_file(&path, OpenMode::Append)
            .map_err(ProtectedError::Fs)
    }

    /// Removes the proof's path.
    ///
    /// # Errors
    ///
    /// [`ProtectedError`].
    pub fn remove(&self, proof: Authorized<Remove, DirKey>) -> Result<(), ProtectedError> {
        let path = self.path_of(proof)?;
        self.dir.remove_file(&path).map_err(ProtectedError::Fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogRecord;
    use ed25519_compact::{KeyPair, Seed};

    #[derive(Default)]
    struct Collect(Vec<String>);
    impl LogWriter for Collect {
        fn write(&mut self, record: &LogRecord) {
            self.0.push(record.render());
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}")).unwrap();
            s
        })
    }

    fn rp(text: &str) -> RelPath {
        let mut segs = text
            .split('/')
            .map(|s| crate::path::PathSeg::parse(s).unwrap());
        let first = RelPath::new(segs.next().unwrap());
        segs.fold(first, RelPath::join)
    }

    fn kp(seed: u8) -> KeyPair {
        KeyPair::from_seed(Seed::new([seed; 32]))
    }

    fn auth() -> TokenAuthenticator {
        TokenAuthenticator::new("api".into(), &[("k1".into(), *kp(1).pk)]).unwrap()
    }

    fn token(signer: &KeyPair, fields: &str) -> String {
        let sig = signer.sk.sign(fields.as_bytes(), None);
        format!("{fields}.{}", hex(sig.as_ref()))
    }

    fn in_secs(s: u64) -> u64 {
        now().unwrap().checked_add(s).unwrap()
    }

    #[test]
    fn a_valid_token_names_its_principal_and_is_logged() {
        let mut log = Collect::default();
        let t = token(
            &kp(1),
            &format!("corten-token-1.k1.api.alice.{}", in_secs(60)),
        );
        let who = auth().authenticate(Token(&t), &mut log).unwrap();
        assert_eq!((who.principal(), who.authenticator()), ("alice", "api"));
        assert_eq!(
            log.0,
            ["authn.ok authenticator=\"api\" method=\"token\" principal=\"alice\""]
        );
        assert!(!log.0.concat().contains(&t), "the token is never logged");
    }

    #[test]
    fn every_bad_token_is_refused_with_its_reason_logged() {
        let later = in_secs(60);
        let cases = [
            (
                token(&kp(2), &format!("corten-token-1.k1.api.alice.{later}")),
                "bad signature",
            ),
            (
                token(&kp(1), &format!("corten-token-1.k9.api.alice.{later}")),
                "unknown key",
            ),
            (
                token(&kp(1), &format!("corten-token-1.k1.web.alice.{later}")),
                "other audience",
            ),
            (token(&kp(1), "corten-token-1.k1.api.alice.1000"), "expired"),
            (
                token(
                    &kp(1),
                    &format!("corten-token-1.k1.api.alice.{}", in_secs(901)),
                ),
                "lifetime too long",
            ),
            (
                token(&kp(1), &format!("corten-token-2.k1.api.alice.{later}")),
                "malformed",
            ),
            (
                token(&kp(1), &format!("corten-token-1.k1.api.al!ce.{later}")),
                "malformed",
            ),
            (
                token(&kp(1), &format!("corten-token-1.k1.api.alice.0{later}")),
                "malformed or no clock",
            ),
            (
                token(&kp(1), &format!("corten-token-1.k1.api.alice.{later}.x")),
                "malformed",
            ),
            (
                token(&kp(1), &format!("corten-token-1.k1.api.alice.{later}")).to_uppercase(),
                "malformed",
            ),
            (
                format!("corten-token-1.k1.api.{}.{later}.00", "a".repeat(600)),
                "too long",
            ),
        ];
        for (t, reason) in cases {
            let mut log = Collect::default();
            assert_eq!(
                auth().authenticate(Token(&t), &mut log),
                Err(AuthnRefused),
                "{reason}"
            );
            assert_eq!(
                log.0,
                [format!(
                    "authn.refused authenticator=\"api\" method=\"token\" reason=\"{reason}\""
                )],
                "{t}"
            );
        }
    }

    struct Owner;
    impl Policy<Read, DirKey> for Owner {
        fn allows(&self, who: &Authenticated, key: &DirKey) -> bool {
            key.path()
                .to_slash_string()
                .starts_with(&format!("{}/", who.principal()))
        }
    }

    fn alice() -> Authenticated {
        Authenticated {
            principal: "alice".into(),
            authenticator: "api".into(),
        }
    }

    #[test]
    fn check_returns_a_proof_only_when_the_policy_allows_and_logs_both() {
        let key = |p: &str| DirKey {
            dir: "docs".into(),
            path: rp(p),
        };
        let mut log = Collect::default();
        let proof = check(&alice(), Read, key("alice/a.txt"), &Owner, &mut log).unwrap();
        assert_eq!(proof.key().path().to_slash_string(), "alice/a.txt");
        assert_eq!(proof.principal(), "alice");
        assert_eq!(
            check(&alice(), Read, key("bob/a.txt"), &Owner, &mut log).err(),
            Some(Denied)
        );
        assert_eq!(
            log.0,
            [
                "authz.allowed principal=\"alice\" action=\"read\" key=\"docs:alice/a.txt\"",
                "authz.denied principal=\"alice\" action=\"read\" key=\"docs:bob/a.txt\"",
            ]
        );
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;

        struct Scratch(std::path::PathBuf);
        impl Scratch {
            fn new(tag: &str) -> Self {
                let dir =
                    std::env::temp_dir().join(format!("corten-authz-{tag}-{}", std::process::id()));
                let _ignored = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(dir.join("rw")).unwrap();
                std::fs::create_dir_all(dir.join("etc")).unwrap();
                Self(dir)
            }
        }
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ignored = std::fs::remove_dir_all(&self.0);
            }
        }

        struct Anyone;
        impl Policy<Create, DirKey> for Anyone {
            fn allows(&self, _: &Authenticated, _: &DirKey) -> bool {
                true
            }
        }
        impl Policy<Read, DirKey> for Anyone {
            fn allows(&self, _: &Authenticated, _: &DirKey) -> bool {
                true
            }
        }

        #[test]
        fn a_protected_dir_acts_only_on_the_proofs_path_in_itself() {
            let s = Scratch::new("pdir");
            std::fs::create_dir_all(s.0.join("b")).unwrap();
            let a = ProtectedDir::new("a".into(), DirCap::open_root(&s.0.join("rw")).unwrap());
            let b = ProtectedDir::new("b".into(), DirCap::open_root(&s.0.join("b")).unwrap());
            let mut log = Collect::default();
            let path = || rp("f.txt");
            let proof = check(&alice(), Create, a.key(path()), &Anyone, &mut log).unwrap();
            let f = a.create(proof, FileMode::OwnerOnly).unwrap();
            f.write_all(b"hello").unwrap();
            let read = check(&alice(), Read, a.key(path()), &Anyone, &mut log).unwrap();
            assert_eq!(a.read(read).unwrap().read_to_end(16).unwrap(), b"hello");
            // A proof for directory a does not open the same name in b.
            let for_a = check(&alice(), Read, a.key(path()), &Anyone, &mut log).unwrap();
            assert!(matches!(b.read(for_a), Err(ProtectedError::OtherDir)));
        }
    }
}
