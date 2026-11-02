//! Misuse-resistant cryptography (Phase 6, strategy 10; spec section 8,
//! question 13).
//!
//! No algorithm choice and no knobs that weaken a primitive:
//!
//! - [`AeadKey`]: authenticated encryption with XChaCha20-Poly1305. The
//!   library picks a fresh random 192-bit nonce for every message and stores
//!   it in front of the ciphertext, so a caller cannot reuse a nonce
//!   (CWE-323, 329, 1204). Opening fails on any change to the ciphertext, the
//!   nonce, the key identifier or the associated data, without saying which
//!   (CWE-353, 354).
//! - [`KeyRing`]: key rotation (CWE-324). Every sealed message names the
//!   [`KeyId`] that sealed it; a key ring seals with its current key, opens
//!   with whichever key a message names, and says when a message should be
//!   sealed again under the current key.
//! - [`password`]: Argon2id password hashes with a cost floor
//!   (CWE-916, 759, 760). [`password::verify`] says when a stored hash
//!   should be replaced with one at the current cost.
//! - [`verify_signed`]: an Ed25519 signature check against a set of
//!   [`VerifyingKeys`] with identifiers, whose only success value is
//!   [`Verified`], so unchecked data cannot be passed where checked data is
//!   required (CWE-347).
//!
//! The primitives come from the `RustCrypto` crates `chacha20poly1305` and
//! `argon2` and from `ed25519-compact` (owner decision, 2026-11-01;
//! `docs/gates/phase-6.md`). None of their types appear in this module's
//! public API: an application using the prelude need not admit them in its
//! dependency policy (layer 3 counts re-exported crates as reachable).

use std::collections::BTreeMap;
use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::random::{self, RandomError};
use crate::secret::{Secret, SecretError};

/// Key length of [`AeadKey`], in bytes.
pub const KEY_LEN: usize = 32;
/// The first byte of every sealed message: the format (key identifier,
/// XChaCha20-Poly1305, 24-byte nonce, 16-byte tag). Opening refuses any
/// other value, so a later algorithm change is a new version rather than a
/// silent break. Format 1, which named no key, is refused.
pub const FORMAT_VERSION: u8 = 2;
/// Length of the header in front of the nonce: the version byte and the
/// big-endian [`KeyId`]. The header is authenticated with the associated
/// data, so neither can be changed or swapped.
pub const HEADER_LEN: usize = 5;
/// Bytes [`AeadKey::seal`] adds to the plaintext: header, nonce and tag.
pub const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;
/// Length of the nonce [`AeadKey::seal`] stores in front of the ciphertext.
pub const NONCE_LEN: usize = 24;
/// Length of the authentication tag after the ciphertext.
pub const TAG_LEN: usize = 16;
/// Largest plaintext [`AeadKey::seal`] accepts, and largest sealed message
/// [`AeadKey::open`] reads: 16 MiB. A bound, so an attacker-supplied length
/// cannot make the prelude allocate without limit (CWE-770).
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Why a cryptographic operation failed.
#[derive(Debug)]
pub enum CryptoError {
    /// The operating system's random generator failed.
    Random(RandomError),
    /// A key could not be held as a [`Secret`].
    Secret(SecretError),
    /// A key had the wrong length.
    KeyLength,
    /// The message is longer than [`MAX_MESSAGE`].
    TooLarge,
    /// Opening failed: the message is too short, or it, its nonce or its
    /// associated data was changed, or the key is wrong. Deliberately one
    /// variant, so the failure reveals nothing about which.
    Open,
    /// Encryption failed inside the cipher.
    Seal,
    /// A stored password hash is not a well-formed Argon2id hash.
    HashFormat,
    /// A stored password hash's cost is below the floor
    /// ([`password::FLOOR`]).
    WeakHash,
    /// The password does not match the stored hash.
    Mismatch,
    /// A signature or public key is malformed, or the signature does not
    /// verify.
    Signature,
    /// The message names a key the key ring or key set does not hold. The
    /// identifier is not secret: it is stored in the clear.
    UnknownKey(u32),
    /// A key ring or key set already holds a key with this identifier.
    DuplicateKey(u32),
    /// The current key of a [`KeyRing`] cannot be retired.
    CurrentKey(u32),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(e) => write!(f, "{e}"),
            Self::Secret(e) => write!(f, "{e}"),
            Self::KeyLength => write!(f, "a key must be {KEY_LEN} bytes"),
            Self::TooLarge => write!(f, "message longer than {MAX_MESSAGE} bytes"),
            Self::Open => write!(f, "the sealed message could not be opened"),
            Self::Seal => write!(f, "encryption failed"),
            Self::HashFormat => write!(f, "not an Argon2id password hash"),
            Self::WeakHash => write!(f, "the password hash's cost is below the floor"),
            Self::Mismatch => write!(f, "the password does not match"),
            Self::Signature => write!(f, "the signature does not verify"),
            Self::UnknownKey(id) => write!(f, "no key with identifier {id}"),
            Self::DuplicateKey(id) => write!(f, "a key with identifier {id} is already held"),
            Self::CurrentKey(id) => write!(f, "key {id} is the current key and cannot be retired"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<RandomError> for CryptoError {
    fn from(e: RandomError) -> Self {
        Self::Random(e)
    }
}

impl From<SecretError> for CryptoError {
    fn from(e: SecretError) -> Self {
        Self::Secret(e)
    }
}

/// Associated data: authenticated but not encrypted. A label (spec 4.2), so
/// it cannot be swapped with the plaintext.
#[derive(Debug, Clone, Copy)]
pub struct Aad<'a>(pub &'a [u8]);

/// A key's identifier, chosen by the caller and stored in the clear in
/// every sealed message and next to every verifying key. A label (spec
/// 4.2), so it cannot be swapped with another integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub u32);

/// An XChaCha20-Poly1305 key with its [`KeyId`], held as a [`Secret`]
/// (locked, wiped, never printed). See the module documentation.
pub struct AeadKey {
    id: KeyId,
    key: Secret,
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AeadKey({})", self.id.0)
    }
}

/// The header of a sealed message: the version and the key identifier.
fn header(KeyId(id): KeyId) -> [u8; HEADER_LEN] {
    let [a, b, c, d] = id.to_be_bytes();
    [FORMAT_VERSION, a, b, c, d]
}

/// The key identifier a sealed message names, if it is in the current
/// format. Nothing is checked yet: the header is authenticated on opening.
fn named_key(sealed: &[u8]) -> Option<KeyId> {
    match sealed {
        [version, a, b, c, d, ..] if *version == FORMAT_VERSION => {
            Some(KeyId(u32::from_be_bytes([*a, *b, *c, *d])))
        }
        _ => None,
    }
}

impl AeadKey {
    /// A new random key from the operating system's generator.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] or [`CryptoError::Secret`].
    pub fn generate(id: KeyId) -> Result<Self, CryptoError> {
        let mut bytes = vec![0u8; KEY_LEN];
        random::fill(&mut bytes)?;
        Ok(Self {
            id,
            key: Secret::new(bytes)?,
        })
    }

    /// Uses existing key material, which must be exactly [`KEY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`].
    pub fn from_secret(id: KeyId, key: Secret) -> Result<Self, CryptoError> {
        if key.len() == KEY_LEN {
            Ok(Self { id, key })
        } else {
            Err(CryptoError::KeyLength)
        }
    }

    /// This key's identifier.
    #[must_use]
    pub fn id(&self) -> KeyId {
        self.id
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        self.key
            .expose(XChaCha20Poly1305::new_from_slice)
            .map_err(|_| CryptoError::KeyLength)
    }

    /// Encrypts and authenticates `plaintext`, and authenticates `aad` and
    /// the header. Returns the header ([`FORMAT_VERSION`] and this key's
    /// [`KeyId`]), nonce, ciphertext and tag, in that order.
    ///
    /// # Errors
    ///
    /// [`CryptoError::TooLarge`], [`CryptoError::Random`] or
    /// [`CryptoError::Seal`].
    pub fn seal(&self, plaintext: &[u8], Aad(aad): Aad<'_>) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_MESSAGE {
            return Err(CryptoError::TooLarge);
        }
        let head = header(self.id);
        let nonce_bytes = random::array::<NONCE_LEN>()?;
        let nonce = XNonce::from(nonce_bytes);
        // The header has a fixed length, so header || aad is unambiguous.
        let mut bound = Vec::with_capacity(HEADER_LEN.saturating_add(aad.len()));
        bound.extend_from_slice(&head);
        bound.extend_from_slice(aad);
        let ciphertext = self
            .cipher()?
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &bound,
                },
            )
            .map_err(|_| CryptoError::Seal)?;
        let mut out = Vec::with_capacity(OVERHEAD.saturating_add(plaintext.len()));
        out.extend_from_slice(&head);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Checks and decrypts a message from [`AeadKey::seal`] with the same
    /// `aad`. A message sealed under another key identifier is refused like
    /// any other failure.
    ///
    /// # Errors
    ///
    /// [`CryptoError::TooLarge`], or [`CryptoError::Open`] for every other
    /// failure.
    pub fn open(&self, sealed: &[u8], Aad(aad): Aad<'_>) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() > MAX_MESSAGE.saturating_add(OVERHEAD) {
            return Err(CryptoError::TooLarge);
        }
        if named_key(sealed) != Some(self.id) {
            return Err(CryptoError::Open);
        }
        let (head, rest) = sealed
            .split_at_checked(HEADER_LEN)
            .ok_or(CryptoError::Open)?;
        let (nonce_bytes, ciphertext) =
            rest.split_at_checked(NONCE_LEN).ok_or(CryptoError::Open)?;
        let nonce_array: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| CryptoError::Open)?;
        let nonce = XNonce::from(nonce_array);
        let mut bound = Vec::with_capacity(HEADER_LEN.saturating_add(aad.len()));
        bound.extend_from_slice(head);
        bound.extend_from_slice(aad);
        self.cipher()?
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &bound,
                },
            )
            .map_err(|_| CryptoError::Open)
    }
}

/// A plaintext opened by a [`KeyRing`], and whether it should be sealed
/// again: it was sealed under a key other than the ring's current one.
#[derive(Debug)]
#[must_use]
pub struct Opened {
    /// The decrypted message.
    pub plaintext: Vec<u8>,
    /// The message was sealed under an older key: seal it again with
    /// [`KeyRing::seal`] and store the result, so the older key can be
    /// retired.
    pub reseal: bool,
}

/// Keys for rotation (CWE-324): seals with the current key and opens with
/// whichever key a message names.
///
/// To rotate: [`KeyRing::rotate`] to a new key (the old one stays, for
/// opening), re-seal what [`Opened::reseal`] marks, then
/// [`KeyRing::retire`] the old key.
#[derive(Debug)]
pub struct KeyRing {
    current: KeyId,
    keys: BTreeMap<KeyId, AeadKey>,
}

impl KeyRing {
    /// A ring holding one key, which is current.
    #[must_use]
    pub fn new(current: AeadKey) -> Self {
        let id = current.id;
        Self {
            current: id,
            keys: BTreeMap::from([(id, current)]),
        }
    }

    /// Adds an older key, for opening only.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DuplicateKey`] if the ring holds that identifier.
    pub fn add(&mut self, older: AeadKey) -> Result<(), CryptoError> {
        let id = older.id;
        if self.keys.contains_key(&id) {
            return Err(CryptoError::DuplicateKey(id.0));
        }
        self.keys.insert(id, older);
        Ok(())
    }

    /// Makes `new` the current key. The previous one stays, for opening.
    ///
    /// # Errors
    ///
    /// [`CryptoError::DuplicateKey`] if the ring holds that identifier.
    pub fn rotate(&mut self, new: AeadKey) -> Result<(), CryptoError> {
        let id = new.id;
        self.add(new)?;
        self.current = id;
        Ok(())
    }

    /// Removes an older key: messages sealed under it can no longer be
    /// opened.
    ///
    /// # Errors
    ///
    /// [`CryptoError::CurrentKey`] for the current key,
    /// [`CryptoError::UnknownKey`] if the ring does not hold it.
    pub fn retire(&mut self, id: KeyId) -> Result<(), CryptoError> {
        if id == self.current {
            return Err(CryptoError::CurrentKey(id.0));
        }
        self.keys
            .remove(&id)
            .map(drop)
            .ok_or(CryptoError::UnknownKey(id.0))
    }

    /// The current key's identifier.
    #[must_use]
    pub fn current(&self) -> KeyId {
        self.current
    }

    /// Seals with the current key; see [`AeadKey::seal`].
    ///
    /// # Errors
    ///
    /// As [`AeadKey::seal`].
    pub fn seal(&self, plaintext: &[u8], aad: Aad<'_>) -> Result<Vec<u8>, CryptoError> {
        self.keys
            .get(&self.current)
            .ok_or(CryptoError::UnknownKey(self.current.0))?
            .seal(plaintext, aad)
    }

    /// Opens with the key the message names; see [`AeadKey::open`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::UnknownKey`] if the ring does not hold the key the
    /// message names, else as [`AeadKey::open`].
    pub fn open(&self, sealed: &[u8], aad: Aad<'_>) -> Result<Opened, CryptoError> {
        if sealed.len() > MAX_MESSAGE.saturating_add(OVERHEAD) {
            return Err(CryptoError::TooLarge);
        }
        let id = named_key(sealed).ok_or(CryptoError::Open)?;
        let key = self.keys.get(&id).ok_or(CryptoError::UnknownKey(id.0))?;
        let plaintext = key.open(sealed, aad)?;
        Ok(Opened {
            plaintext,
            reseal: id != self.current,
        })
    }
}

/// Data whose signature has been checked. The only way to get one is
/// [`verify_signed`] (or [`Verified::map`] on another `Verified`), so a
/// function that takes `Verified<T>` cannot be handed unchecked data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// The checked value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// The checked value, consuming the wrapper.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Parses or transforms the checked value; the result stays `Verified`,
    /// because it was derived only from checked data.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    pub fn map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<Verified<U>, E> {
        f(self.0).map(Verified)
    }
}

/// An Ed25519 signature: a label, so it cannot be passed where the key
/// belongs (spec 4.2).
#[derive(Debug, Clone, Copy)]
pub struct SignatureBytes<'a>(pub &'a [u8]);

/// An Ed25519 public key: a label, as [`SignatureBytes`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyingKey<'a>(pub &'a [u8]);

/// The Ed25519 public keys a signature may be checked against, each under
/// a [`KeyId`] (CWE-324): trust a new key next to the old one, move signers
/// to it, then remove the old one.
#[derive(Debug, Default)]
pub struct VerifyingKeys {
    keys: BTreeMap<KeyId, ed25519_compact::PublicKey>,
}

impl VerifyingKeys {
    /// An empty set: it verifies nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `key` under `id`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Signature`] if `key` is not an Ed25519 public key,
    /// [`CryptoError::DuplicateKey`] if `id` is already trusted.
    pub fn add(
        &mut self,
        id: KeyId,
        VerifyingKey(key): VerifyingKey<'_>,
    ) -> Result<(), CryptoError> {
        let key =
            ed25519_compact::PublicKey::from_slice(key).map_err(|_| CryptoError::Signature)?;
        if self.keys.contains_key(&id) {
            return Err(CryptoError::DuplicateKey(id.0));
        }
        self.keys.insert(id, key);
        Ok(())
    }

    /// Stops trusting the key under `id`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::UnknownKey`] if it is not trusted.
    pub fn remove(&mut self, id: KeyId) -> Result<(), CryptoError> {
        self.keys
            .remove(&id)
            .map(drop)
            .ok_or(CryptoError::UnknownKey(id.0))
    }
}

/// Checks an Ed25519 signature over `message` with the trusted key `signer`
/// names, and returns the message as [`Verified`]. Only that key is tried,
/// never every key in the set.
///
/// # Errors
///
/// [`CryptoError::UnknownKey`] if `keys` does not hold `signer`;
/// [`CryptoError::Signature`] if the signature is malformed or does not
/// verify; [`CryptoError::TooLarge`] beyond [`MAX_MESSAGE`].
pub fn verify_signed(
    message: Vec<u8>,
    SignatureBytes(signature): SignatureBytes<'_>,
    signer: KeyId,
    keys: &VerifyingKeys,
) -> Result<Verified<Vec<u8>>, CryptoError> {
    if message.len() > MAX_MESSAGE {
        return Err(CryptoError::TooLarge);
    }
    let key = keys
        .keys
        .get(&signer)
        .ok_or(CryptoError::UnknownKey(signer.0))?;
    let sig =
        ed25519_compact::Signature::from_slice(signature).map_err(|_| CryptoError::Signature)?;
    key.verify(&message, &sig)
        .map_err(|_| CryptoError::Signature)?;
    Ok(Verified(message))
}

/// Argon2id password hashes (CWE-916, 759, 760).
///
/// [`hash`](password::hash) uses a fresh 16-byte random salt (RFC 9106, section 3.1) and
/// OWASP's recommended Argon2id configuration (19 MiB, 2 iterations, 1 lane;
/// Password Storage Cheat Sheet, checked 2026-11-01). [`verify`](password::verify) refuses a
/// stored hash below every one of OWASP's minimum configurations, so a weak
/// hash planted in storage or kept from an older system cannot be accepted,
/// and it says when an accepted hash should be replaced with one at the
/// current cost ([`Check::Rehash`]).
pub mod password {
    use std::fmt;

    use argon2::password_hash::phc::PasswordHash as Phc;
    use argon2::password_hash::{PasswordHasher, PasswordVerifier};
    use argon2::{Algorithm, Argon2, Params, Version};

    use super::CryptoError;
    use crate::random;
    use crate::secret::Secret;

    /// Salt length, in bytes (RFC 9106: 16 bytes recommended).
    pub const SALT_LEN: usize = 16;
    /// Memory cost of new hashes, in KiB (19 MiB).
    pub const M_COST: u32 = 19 * 1024;
    /// Iterations of new hashes.
    pub const T_COST: u32 = 2;
    /// Lanes of new hashes.
    pub const P_COST: u32 = 1;
    /// OWASP's minimum Argon2id configurations as (memory in KiB,
    /// iterations); each gives an equal level of defence.
    pub const FLOOR: [(u32, u32); 5] = [
        (47_104, 1),
        (19_456, 2),
        (12_288, 3),
        (9_216, 4),
        (7_168, 5),
    ];

    /// A stored password hash in the PHC string format
    /// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). Not secret, but
    /// printed only through [`PasswordHash::as_str`].
    #[derive(Clone, PartialEq, Eq)]
    pub struct PasswordHash(String);

    impl PasswordHash {
        /// The PHC string, for storage.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }

        /// Wraps a PHC string read from storage. It is checked by
        /// [`verify`], not here.
        #[must_use]
        pub fn from_stored(text: String) -> Self {
            Self(text)
        }
    }

    impl fmt::Debug for PasswordHash {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("PasswordHash(..)")
        }
    }

    /// A matching password: whether its stored hash is at the current cost.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[must_use]
    pub enum Check {
        /// The stored hash uses [`M_COST`], [`T_COST`] and [`P_COST`].
        Current,
        /// The stored hash meets the floor but uses other costs: hash the
        /// password again with [`hash`] and store the result.
        Rehash,
    }

    /// Whether Argon2id costs `m_cost` (KiB) and `t_cost` meet at least one
    /// of OWASP's minimum configurations ([`FLOOR`]).
    fn meets_floor(m_cost: u32, t_cost: u32) -> bool {
        FLOOR.iter().any(|&(m, t)| m_cost >= m && t_cost >= t)
    }

    fn hasher(params: Params) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    /// Hashes `password` with a fresh random salt.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`], or [`CryptoError::HashFormat`] if hashing
    /// fails inside the library.
    pub fn hash(password: &Secret) -> Result<PasswordHash, CryptoError> {
        let salt = random::array::<SALT_LEN>()?;
        let params =
            Params::new(M_COST, T_COST, P_COST, None).map_err(|_| CryptoError::HashFormat)?;
        let phc = password
            .expose(|pw| hasher(params).hash_password_with_salt(pw, &salt))
            .map_err(|_| CryptoError::HashFormat)?;
        Ok(PasswordHash(phc.to_string()))
    }

    /// Checks `password` against a stored hash.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::HashFormat`]: not a well-formed Argon2id (version 19)
    ///   PHC string (the parser holds every field in a fixed-size buffer, so
    ///   a long input is refused without a large allocation);
    /// - [`CryptoError::WeakHash`]: its cost is below [`FLOOR`];
    /// - [`CryptoError::Mismatch`]: the password does not match.
    pub fn verify(password: &Secret, stored: &PasswordHash) -> Result<Check, CryptoError> {
        let phc = Phc::new(&stored.0).map_err(|_| CryptoError::HashFormat)?;
        if phc.algorithm.as_str() != "argon2id" || phc.version != Some(0x13) {
            return Err(CryptoError::HashFormat);
        }
        let params = Params::try_from(&phc).map_err(|_| CryptoError::HashFormat)?;
        if !meets_floor(params.m_cost(), params.t_cost()) {
            return Err(CryptoError::WeakHash);
        }
        let current =
            (params.m_cost(), params.t_cost(), params.p_cost()) == (M_COST, T_COST, P_COST);
        password
            .expose(|pw| hasher(params).verify_password(pw, &phc))
            .map_err(|_| CryptoError::Mismatch)?;
        Ok(if current {
            Check::Current
        } else {
            Check::Rehash
        })
    }
}

#[cfg(test)]
mod tests {
    use super::password::{self, PasswordHash};
    use super::*;

    fn secret(bytes: &[u8]) -> Secret {
        Secret::new(bytes.to_vec()).unwrap()
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = AeadKey::generate(KeyId(1)).unwrap();
        let sealed = key.seal(b"attack at dawn", Aad(b"msg-1")).unwrap();
        assert_eq!(sealed.len(), OVERHEAD + 14);
        assert_eq!(sealed[0], FORMAT_VERSION);
        assert_eq!(key.open(&sealed, Aad(b"msg-1")).unwrap(), b"attack at dawn");
    }

    #[test]
    fn every_seal_uses_a_new_nonce() {
        let key = AeadKey::generate(KeyId(1)).unwrap();
        let a = key.seal(b"same", Aad(b"")).unwrap();
        let b = key.seal(b"same", Aad(b"")).unwrap();
        assert_ne!(
            a[HEADER_LEN..HEADER_LEN + NONCE_LEN],
            b[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        );
        assert_ne!(a, b);
    }

    #[test]
    fn open_refuses_every_single_bit_flip() {
        let key = AeadKey::generate(KeyId(1)).unwrap();
        let sealed = key.seal(b"payload", Aad(b"ad")).unwrap();
        // Denominator: every bit of header, nonce, ciphertext and tag.
        let mut refused = 0usize;
        for i in 0..sealed.len() * 8 {
            let mut t = sealed.clone();
            t[i / 8] ^= 1 << (i % 8);
            if matches!(key.open(&t, Aad(b"ad")), Err(CryptoError::Open)) {
                refused += 1;
            }
        }
        assert_eq!(refused, sealed.len() * 8);
    }

    #[test]
    fn open_refuses_other_aad_other_key_and_short_input() {
        let key = AeadKey::generate(KeyId(1)).unwrap();
        let sealed = key.seal(b"payload", Aad(b"ad")).unwrap();
        assert!(matches!(
            key.open(&sealed, Aad(b"other")),
            Err(CryptoError::Open)
        ));
        let other = AeadKey::generate(KeyId(1)).unwrap();
        assert!(matches!(
            other.open(&sealed, Aad(b"ad")),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            key.open(&sealed[..OVERHEAD - 1], Aad(b"ad")),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            key.open(&sealed[..OVERHEAD], Aad(b"ad")),
            Err(CryptoError::Open)
        ));
        assert!(matches!(key.open(&[], Aad(b"ad")), Err(CryptoError::Open)));
    }

    #[test]
    fn sizes_are_bounded() {
        let key = AeadKey::generate(KeyId(1)).unwrap();
        let big = vec![0u8; MAX_MESSAGE + 1];
        assert!(matches!(
            key.seal(&big, Aad(b"")),
            Err(CryptoError::TooLarge)
        ));
        assert!(matches!(
            key.open(&vec![0u8; MAX_MESSAGE + OVERHEAD + 1], Aad(b"")),
            Err(CryptoError::TooLarge)
        ));
    }

    #[test]
    fn keys_of_the_wrong_length_are_refused() {
        assert!(matches!(
            AeadKey::from_secret(KeyId(1), secret(&[7; 31])),
            Err(CryptoError::KeyLength)
        ));
        assert!(matches!(
            AeadKey::from_secret(KeyId(1), secret(&[7; 33])),
            Err(CryptoError::KeyLength)
        ));
        assert!(AeadKey::from_secret(KeyId(1), secret(&[7; 32])).is_ok());
    }

    // RFC 8032, section 7.1, TEST 2.
    const PK: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const SIG: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                       085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn trusted(pk: &[u8]) -> VerifyingKeys {
        let mut keys = VerifyingKeys::new();
        keys.add(KeyId(7), VerifyingKey(pk)).unwrap();
        keys
    }

    #[test]
    fn rfc8032_vector_verifies_and_tampering_does_not() {
        let (pk, sig) = (hex(PK), hex(SIG));
        let keys = trusted(&pk);
        let v = verify_signed(vec![0x72], SignatureBytes(&sig), KeyId(7), &keys).unwrap();
        assert_eq!(v.get(), &vec![0x72]);
        assert!(matches!(
            verify_signed(vec![0x73], SignatureBytes(&sig), KeyId(7), &keys),
            Err(CryptoError::Signature)
        ));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&bad), KeyId(7), &keys),
            Err(CryptoError::Signature)
        ));
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&sig[..63]), KeyId(7), &keys),
            Err(CryptoError::Signature)
        ));
    }

    #[test]
    fn verified_map_keeps_the_wrapper() {
        let (pk, sig) = (hex(PK), hex(SIG));
        let v = verify_signed(vec![0x72], SignatureBytes(&sig), KeyId(7), &trusted(&pk)).unwrap();
        let n: Verified<usize> = v.map(|m| Ok::<_, ()>(m.len())).unwrap();
        assert_eq!(n.into_inner(), 1);
    }

    #[test]
    fn password_hash_round_trips_and_uses_the_configured_cost() {
        let h = password::hash(&secret(b"correct horse")).unwrap();
        assert!(
            h.as_str().starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{}",
            h.as_str()
        );
        assert_eq!(
            password::verify(&secret(b"correct horse"), &h).unwrap(),
            password::Check::Current
        );
        assert!(matches!(
            password::verify(&secret(b"correct horsf"), &h),
            Err(CryptoError::Mismatch)
        ));
        assert_eq!(format!("{h:?}"), "PasswordHash(..)");
    }

    #[test]
    fn two_hashes_of_one_password_differ() {
        let a = password::hash(&secret(b"pw")).unwrap();
        let b = password::hash(&secret(b"pw")).unwrap();
        assert_ne!(a, b);
    }

    /// A hash below the floor, made with the library directly, as a weak
    /// legacy hash in storage would be.
    fn hash_with(m: u32, t: u32, alg: argon2::Algorithm) -> PasswordHash {
        use argon2::password_hash::PasswordHasher;
        let params = argon2::Params::new(m, t, 1, None).unwrap();
        let phc = argon2::Argon2::new(alg, argon2::Version::V0x13, params)
            .hash_password_with_salt(b"pw", b"0123456789abcdef")
            .unwrap();
        PasswordHash::from_stored(phc.to_string())
    }

    #[test]
    fn verify_refuses_hashes_below_the_floor() {
        let pw = secret(b"pw");
        // Just below each floor line, and at it.
        for &(m, t) in &password::FLOOR {
            if t > 1 {
                assert!(matches!(
                    password::verify(&pw, &hash_with(m, t - 1, argon2::Algorithm::Argon2id)),
                    Err(CryptoError::WeakHash)
                ));
            }
            assert_eq!(
                password::verify(&pw, &hash_with(m, t, argon2::Algorithm::Argon2id)).unwrap(),
                if (m, t) == (password::M_COST, password::T_COST) {
                    password::Check::Current
                } else {
                    password::Check::Rehash
                },
                "m={m} t={t}"
            );
        }
        assert!(matches!(
            password::verify(&pw, &hash_with(7_167, 5, argon2::Algorithm::Argon2id)),
            Err(CryptoError::WeakHash)
        ));
    }

    #[test]
    fn verify_refuses_other_algorithms_and_garbage() {
        let pw = secret(b"pw");
        for alg in [argon2::Algorithm::Argon2i, argon2::Algorithm::Argon2d] {
            assert!(matches!(
                password::verify(&pw, &hash_with(19_456, 2, alg)),
                Err(CryptoError::HashFormat)
            ));
        }
        for text in [
            "",
            "plain",
            "$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA",
        ] {
            assert!(matches!(
                password::verify(&pw, &PasswordHash::from_stored(text.to_owned())),
                Err(CryptoError::HashFormat)
            ));
        }
    }

    #[test]
    fn the_header_names_the_key_and_is_authenticated() {
        let material = [9u8; KEY_LEN];
        let one = AeadKey::from_secret(KeyId(1), secret(&material)).unwrap();
        let two = AeadKey::from_secret(KeyId(2), secret(&material)).unwrap();
        let sealed = one.seal(b"m", Aad(b"")).unwrap();
        assert_eq!(&sealed[..HEADER_LEN], &[FORMAT_VERSION, 0, 0, 0, 1]);
        // Same key material, header rewritten to name key 2: refused,
        // because the header is part of the authenticated data.
        let mut relabelled = sealed.clone();
        relabelled[4] = 2;
        assert!(matches!(
            two.open(&relabelled, Aad(b"")),
            Err(CryptoError::Open)
        ));
        // And a key does not open a message that names another key.
        assert!(matches!(
            two.open(&sealed, Aad(b"")),
            Err(CryptoError::Open)
        ));
        // Format 1 (no key identifier) is refused.
        let mut v1 = vec![1u8];
        v1.extend_from_slice(&sealed[HEADER_LEN..]);
        assert!(matches!(one.open(&v1, Aad(b"")), Err(CryptoError::Open)));
    }

    #[test]
    fn a_key_ring_rotates_reseals_and_retires() {
        let mut ring = KeyRing::new(AeadKey::generate(KeyId(1)).unwrap());
        let old = ring.seal(b"kept", Aad(b"ad")).unwrap();
        let opened = ring.open(&old, Aad(b"ad")).unwrap();
        assert_eq!(
            (opened.plaintext.as_slice(), opened.reseal),
            (&b"kept"[..], false)
        );
        ring.rotate(AeadKey::generate(KeyId(2)).unwrap()).unwrap();
        assert_eq!(ring.current(), KeyId(2));
        let opened = ring.open(&old, Aad(b"ad")).unwrap();
        assert!(opened.reseal, "a message under the old key must say so");
        let fresh = ring.seal(&opened.plaintext, Aad(b"ad")).unwrap();
        assert_eq!(&fresh[..HEADER_LEN], &[FORMAT_VERSION, 0, 0, 0, 2]);
        assert!(!ring.open(&fresh, Aad(b"ad")).unwrap().reseal);
        assert!(matches!(
            ring.retire(KeyId(2)),
            Err(CryptoError::CurrentKey(2))
        ));
        ring.retire(KeyId(1)).unwrap();
        assert!(matches!(
            ring.retire(KeyId(1)),
            Err(CryptoError::UnknownKey(1))
        ));
        assert!(matches!(
            ring.open(&old, Aad(b"ad")),
            Err(CryptoError::UnknownKey(1))
        ));
        assert!(matches!(
            ring.add(AeadKey::generate(KeyId(2)).unwrap()),
            Err(CryptoError::DuplicateKey(2))
        ));
        assert!(matches!(
            ring.rotate(AeadKey::generate(KeyId(2)).unwrap()),
            Err(CryptoError::DuplicateKey(2))
        ));
        assert_eq!(ring.current(), KeyId(2));
        assert!(matches!(ring.open(&[], Aad(b"ad")), Err(CryptoError::Open)));
        assert_eq!(
            format!("{:?}", AeadKey::generate(KeyId(3)).unwrap()),
            "AeadKey(3)"
        );
    }

    #[test]
    fn verifying_keys_are_chosen_by_identifier() {
        let (pk, sig) = (hex(PK), hex(SIG));
        let mut keys = trusted(&pk);
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&sig), KeyId(8), &keys),
            Err(CryptoError::UnknownKey(8))
        ));
        assert!(matches!(
            keys.add(KeyId(7), VerifyingKey(&pk)),
            Err(CryptoError::DuplicateKey(7))
        ));
        assert!(matches!(
            keys.add(KeyId(8), VerifyingKey(&pk[..31])),
            Err(CryptoError::Signature)
        ));
        // Another trusted key does not verify a signature the named key made.
        let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([1; 32]));
        keys.add(KeyId(8), VerifyingKey(other.pk.as_ref())).unwrap();
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&sig), KeyId(8), &keys),
            Err(CryptoError::Signature)
        ));
        let by_other = other.sk.sign([0x72], None);
        verify_signed(
            vec![0x72],
            SignatureBytes(by_other.as_ref()),
            KeyId(8),
            &keys,
        )
        .unwrap();
        keys.remove(KeyId(7)).unwrap();
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&sig), KeyId(7), &keys),
            Err(CryptoError::UnknownKey(7))
        ));
        assert!(matches!(
            keys.remove(KeyId(7)),
            Err(CryptoError::UnknownKey(7))
        ));
        assert!(matches!(
            verify_signed(
                vec![0x72],
                SignatureBytes(&sig),
                KeyId(7),
                &VerifyingKeys::new()
            ),
            Err(CryptoError::UnknownKey(7))
        ));
    }
}
