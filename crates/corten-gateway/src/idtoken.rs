//! ID-token validation for the gateway's OpenID Connect relying party
//! (`docs/gates/gateway-proposal.md`; owner decision 2026-11-14, Q2 option C:
//! these steps are written here, not taken from a library).
//!
//! A token is accepted only when every check holds, in this order:
//!
//! 1. at most [`MAX_ID_TOKEN`] bytes, three non-empty base64url (no padding)
//!    parts;
//! 2. the header's `alg` is in the configured list (never chosen by the
//!    token), and the header carries no key material or extensions (`jwk`,
//!    `jku`, `x5u`, `x5c`, `crit`): keys come only from the provider's key
//!    set, which the `kid` merely selects from;
//! 3. the signature verifies with that key (`aws-lc-rs`: RS256 with a 2048 to
//!    8192-bit modulus, ES256, or Ed25519);
//! 4. claims, read only after the signature holds: `iss` equal to the
//!    provider, `aud` containing the client ID (and `azp` equal to it when
//!    there are several audiences or `azp` is present), `exp` not passed and
//!    `iat` not in the future (each within [`CLOCK_SKEW`]), `nonce` equal to
//!    the one sent (compared in constant time), and `acr` phishing-resistant
//!    under the policy (OpenID Connect EAP ACR Values 1.0: `phr`, `phrh`).
//!
//! Every refusal names its reason ([`Refused`]) for the log; the caller
//! shows the user one generic failure.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

/// Largest ID token accepted, in bytes.
pub const MAX_ID_TOKEN: usize = 16 * 1024;
/// Largest key set accepted, in bytes.
pub const MAX_JWKS: usize = 64 * 1024;
/// Most keys read from one key set.
pub const MAX_KEYS: usize = 32;
/// Tolerated clock difference with the provider, in seconds.
pub const CLOCK_SKEW: u64 = 60;

/// Why a token or key set was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Larger than the cap.
    TooLarge,
    /// Not three base64url parts, or not the expected JSON.
    Malformed,
    /// The header's algorithm is not one the configuration allows.
    Algorithm,
    /// The header carries key material or a critical extension.
    HeaderKey,
    /// No key in the set has the header's `kid`.
    UnknownKey,
    /// The key's type or declared algorithm does not match the header.
    KeyMismatch,
    /// The signature does not verify.
    Signature,
    /// `iss` is not the configured provider.
    Issuer,
    /// `aud` or `azp` does not name this client.
    Audience,
    /// `exp` has passed.
    Expired,
    /// `iat` is in the future.
    IssuedInFuture,
    /// `nonce` is missing or not the one sent.
    Nonce,
    /// `acr` is missing or not phishing-resistant under the policy.
    Acr,
    /// `sub` is missing or empty.
    Subject,
    /// The key set is malformed, too large, or names a `kid` twice.
    KeySet,
}

impl Refused {
    /// The reason as the log records it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too large",
            Self::Malformed => "malformed",
            Self::Algorithm => "algorithm not allowed",
            Self::HeaderKey => "key material or extension in header",
            Self::UnknownKey => "unknown key",
            Self::KeyMismatch => "key does not match algorithm",
            Self::Signature => "bad signature",
            Self::Issuer => "other issuer",
            Self::Audience => "other audience",
            Self::Expired => "expired",
            Self::IssuedInFuture => "issued in the future",
            Self::Nonce => "nonce mismatch",
            Self::Acr => "not phishing-resistant",
            Self::Subject => "no subject",
            Self::KeySet => "bad key set",
        }
    }
}

/// A signature algorithm the gateway can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// RSASSA-PKCS1-v1_5 with SHA-256, modulus 2048 to 8192 bits.
    Rs256,
    /// ECDSA P-256 with SHA-256.
    Es256,
    /// Ed25519 (`EdDSA` or the fully specified `Ed25519`, RFC 9864).
    Ed25519,
}

impl Alg {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            "EdDSA" | "Ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyMaterial {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256 { point: Vec<u8> },
    Ed25519 { x: Vec<u8> },
}

impl KeyMaterial {
    fn fits(&self, alg: Alg) -> bool {
        matches!(
            (self, alg),
            (Self::Rsa { .. }, Alg::Rs256)
                | (Self::P256 { .. }, Alg::Es256)
                | (Self::Ed25519 { .. }, Alg::Ed25519)
        )
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use aws_lc_rs::signature;
        match self {
            Self::Rsa { n, e } => signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            Self::P256 { point } => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            Self::Ed25519 { x } => signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(message, signature)
                .is_ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Jwk {
    kid: String,
    alg: Option<Alg>,
    key: KeyMaterial,
}

/// The provider's signing keys (its JWKS document).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct RawJwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn b64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

fn exactly(text: Option<&String>, len: usize) -> Option<Vec<u8>> {
    b64(text?).filter(|v| v.len() == len)
}

impl Jwks {
    /// Parses a key set. Keys that are not for signatures (`use` other than
    /// `sig`), or of a type or curve the gateway cannot verify, are skipped;
    /// a key without a `kid`, a malformed supported key, a `kid` named twice
    /// or more than [`MAX_KEYS`] keys refuses the whole set.
    ///
    /// # Errors
    ///
    /// [`Refused::TooLarge`] or [`Refused::KeySet`].
    pub fn parse(json: &[u8]) -> Result<Self, Refused> {
        if json.len() > MAX_JWKS {
            return Err(Refused::TooLarge);
        }
        let raw: RawJwks = serde_json::from_slice(json).map_err(|_| Refused::KeySet)?;
        if raw.keys.len() > MAX_KEYS {
            return Err(Refused::KeySet);
        }
        let mut keys: Vec<Jwk> = Vec::new();
        for k in raw.keys {
            if k.usage.as_deref().is_some_and(|u| u != "sig") {
                continue;
            }
            let key = match (k.kty.as_str(), k.crv.as_deref()) {
                ("RSA", _) => {
                    let n = b64(k.n.as_deref().ok_or(Refused::KeySet)?).ok_or(Refused::KeySet)?;
                    let e = b64(k.e.as_deref().ok_or(Refused::KeySet)?).ok_or(Refused::KeySet)?;
                    KeyMaterial::Rsa { n, e }
                }
                ("EC", Some("P-256")) => {
                    let x = exactly(k.x.as_ref(), 32).ok_or(Refused::KeySet)?;
                    let y = exactly(k.y.as_ref(), 32).ok_or(Refused::KeySet)?;
                    let mut point = Vec::with_capacity(65);
                    point.push(0x04);
                    point.extend_from_slice(&x);
                    point.extend_from_slice(&y);
                    KeyMaterial::P256 { point }
                }
                ("OKP", Some("Ed25519")) => KeyMaterial::Ed25519 {
                    x: exactly(k.x.as_ref(), 32).ok_or(Refused::KeySet)?,
                },
                _ => continue,
            };
            let kid = k.kid.filter(|s| !s.is_empty() && s.len() <= 128);
            let kid = kid.ok_or(Refused::KeySet)?;
            let alg = match k.alg.as_deref() {
                None => None,
                Some(name) => Some(Alg::parse(name).ok_or(Refused::KeySet)?),
            };
            if alg.is_some_and(|a| !key.fits(a)) || keys.iter().any(|j| j.kid == kid) {
                return Err(Refused::KeySet);
            }
            keys.push(Jwk { kid, alg, key });
        }
        Ok(Self { keys })
    }
}

/// Which `acr` values count as phishing-resistant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcrPolicy {
    /// `phr` or `phrh` (passkeys, synced or device-bound): the default.
    PhishingResistant,
    /// `phrh` only (a hardware-protected authenticator).
    HardwareProtected,
}

impl AcrPolicy {
    fn allows(self, acr: &str) -> bool {
        match self {
            Self::PhishingResistant => acr == "phr" || acr == "phrh",
            Self::HardwareProtected => acr == "phrh",
        }
    }

    /// The `acr_values` to request from the provider.
    #[must_use]
    pub fn request(self) -> &'static str {
        match self {
            Self::PhishingResistant => "phrh phr",
            Self::HardwareProtected => "phrh",
        }
    }
}

/// What the token must say.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    /// The provider's issuer identifier, compared exactly.
    pub issuer: &'a str,
    /// This gateway's client ID at the provider.
    pub client_id: &'a str,
    /// The `nonce` sent with this sign-in.
    pub nonce: &'a str,
    /// The algorithms the configuration allows.
    pub algorithms: &'a [Alg],
    /// Which authentication contexts count.
    pub acr: AcrPolicy,
}

/// A validated sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIn {
    /// The provider's subject identifier.
    pub subject: String,
    /// The authentication context the provider asserted.
    pub acr: String,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    jwk: Option<serde_json::Value>,
    jku: Option<serde_json::Value>,
    x5u: Option<serde_json::Value>,
    x5c: Option<serde_json::Value>,
    crit: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    // A string or an array of strings, matched explicitly below (no
    // untagged enum on data from outside).
    aud: serde_json::Value,
    azp: Option<String>,
    exp: u64,
    iat: u64,
    nonce: Option<String>,
    acr: Option<String>,
    sub: Option<String>,
}

fn same_secret(a: &str, b: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// Validates an ID token against the provider's key set and what this
/// sign-in expects, at time `now` (Unix seconds).
///
/// # Errors
///
/// The first check that fails, as [`Refused`].
pub fn validate(
    token: &str,
    keys: &Jwks,
    expect: &Expect<'_>,
    now: u64,
) -> Result<SignIn, Refused> {
    if token.len() > MAX_ID_TOKEN {
        return Err(Refused::TooLarge);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refused::Malformed);
    };
    let (Some(header), Some(payload), Some(signature)) = (b64(h), b64(p), b64(s)) else {
        return Err(Refused::Malformed);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(Refused::Malformed);
    }
    let header: Header = serde_json::from_slice(&header).map_err(|_| Refused::Malformed)?;
    if header.jwk.is_some()
        || header.jku.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.crit.is_some()
    {
        return Err(Refused::HeaderKey);
    }
    let alg = Alg::parse(&header.alg)
        .filter(|a| expect.algorithms.contains(a))
        .ok_or(Refused::Algorithm)?;
    let kid = header.kid.ok_or(Refused::UnknownKey)?;
    let key = keys
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(Refused::UnknownKey)?;
    if !key.key.fits(alg) || key.alg.is_some_and(|a| a != alg) {
        return Err(Refused::KeyMismatch);
    }
    // The signed bytes are the first two parts exactly as received.
    let signed_len = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(Refused::Malformed)?;
    let signed = token.get(..signed_len).ok_or(Refused::Malformed)?;
    if !key.key.verify(signed.as_bytes(), &signature) {
        return Err(Refused::Signature);
    }
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| Refused::Malformed)?;
    if claims.iss != expect.issuer {
        return Err(Refused::Issuer);
    }
    let audience_ok = match &claims.aud {
        serde_json::Value::String(a) => a == expect.client_id,
        serde_json::Value::Array(list) => {
            list.iter().all(serde_json::Value::is_string)
                && list.iter().any(|a| a.as_str() == Some(expect.client_id))
                && (list.len() == 1 || claims.azp.is_some())
        }
        _ => false,
    };
    let azp_ok = claims
        .azp
        .as_deref()
        .is_none_or(|azp| azp == expect.client_id);
    if !audience_ok || !azp_ok {
        return Err(Refused::Audience);
    }
    if claims
        .exp
        .checked_add(CLOCK_SKEW)
        .is_none_or(|limit| now >= limit)
    {
        return Err(Refused::Expired);
    }
    if now
        .checked_add(CLOCK_SKEW)
        .is_none_or(|limit| claims.iat > limit)
    {
        return Err(Refused::IssuedInFuture);
    }
    if !claims
        .nonce
        .as_deref()
        .is_some_and(|n| same_secret(n, expect.nonce))
    {
        return Err(Refused::Nonce);
    }
    let acr = claims
        .acr
        .filter(|a| expect.acr.allows(a))
        .ok_or(Refused::Acr)?;
    let subject = claims
        .sub
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or(Refused::Subject)?;
    Ok(SignIn { subject, acr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self as sig, KeyPair as _};
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;

    fn enc(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// `n` and `e` from a DER `RSAPublicKey` (test-only reader).
    fn rsa_parts(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
            let tag = input[0];
            let (len, rest) = if input[1] < 0x80 {
                (usize::from(input[1]), &input[2..])
            } else {
                let n = usize::from(input[1] & 0x7f);
                let len = input[2..2 + n].iter().fold(0usize, |a, b| {
                    a.checked_mul(256)
                        .unwrap()
                        .checked_add(usize::from(*b))
                        .unwrap()
                });
                (len, &input[2 + n..])
            };
            (tag, &rest[..len], &rest[len..])
        }
        let (_, seq, _) = tlv(der);
        let (_, n, rest) = tlv(seq);
        let (_, e, _) = tlv(rest);
        let strip = |v: &[u8]| v.iter().skip_while(|b| **b == 0).copied().collect();
        (strip(n), strip(e))
    }

    struct Keys {
        es: sig::EcdsaKeyPair,
        ed: sig::Ed25519KeyPair,
        rs: sig::RsaKeyPair,
        jwks: Jwks,
    }

    fn keys() -> Keys {
        let es = sig::EcdsaKeyPair::generate(&sig::ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let ed = sig::Ed25519KeyPair::generate().unwrap();
        let rs = sig::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let point = es.public_key().as_ref();
        let (n, e) = rsa_parts(rs.public_key().as_ref());
        let doc = json!({"keys": [
            {"kty": "EC", "crv": "P-256", "kid": "es", "use": "sig", "alg": "ES256",
             "x": enc(&point[1..33]), "y": enc(&point[33..65])},
            {"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": enc(ed.public_key().as_ref())},
            {"kty": "RSA", "kid": "rs", "alg": "RS256", "n": enc(&n), "e": enc(&e)},
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}
        ]});
        let jwks = Jwks::parse(doc.to_string().as_bytes()).unwrap();
        Keys { es, ed, rs, jwks }
    }

    fn claims() -> serde_json::Value {
        json!({"iss": "https://idp.example", "aud": "gw", "exp": NOW + 300, "iat": NOW,
               "nonce": "n-123", "acr": "phr", "sub": "user-1"})
    }

    fn sign(k: &Keys, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let signed = format!(
            "{}.{}",
            enc(header.to_string().as_bytes()),
            enc(claims.to_string().as_bytes())
        );
        let s = match header["kid"].as_str().unwrap_or("es") {
            "ed" => k.ed.sign(signed.as_bytes()).as_ref().to_vec(),
            "rs" => {
                let mut out = vec![0; k.rs.public_modulus_len()];
                k.rs.sign(
                    &sig::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    signed.as_bytes(),
                    &mut out,
                )
                .unwrap();
                out
            }
            _ => {
                k.es.sign(&SystemRandom::new(), signed.as_bytes())
                    .unwrap()
                    .as_ref()
                    .to_vec()
            }
        };
        format!("{signed}.{}", enc(&s))
    }

    const ALL: &[Alg] = &[Alg::Rs256, Alg::Es256, Alg::Ed25519];

    fn expect(acr: AcrPolicy) -> Expect<'static> {
        Expect {
            issuer: "https://idp.example",
            client_id: "gw",
            nonce: "n-123",
            algorithms: ALL,
            acr,
        }
    }

    fn check(
        k: &Keys,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<SignIn, Refused> {
        validate(
            &sign(k, header, claims),
            &k.jwks,
            &expect(AcrPolicy::PhishingResistant),
            NOW,
        )
    }

    #[test]
    fn each_algorithm_verifies_a_phishing_resistant_sign_in() {
        let k = keys();
        for (alg, kid) in [
            ("ES256", "es"),
            ("EdDSA", "ed"),
            ("Ed25519", "ed"),
            ("RS256", "rs"),
        ] {
            let got = check(&k, &json!({"alg": alg, "kid": kid}), &claims()).unwrap();
            assert_eq!(
                (got.subject.as_str(), got.acr.as_str()),
                ("user-1", "phr"),
                "{alg}"
            );
        }
        // Keys not for signatures, and key types the gateway cannot verify, were skipped.
        assert_eq!(k.jwks.keys.len(), 3);
    }

    #[test]
    fn header_choices_are_never_the_tokens() {
        let k = keys();
        let c = claims();
        for (header, want) in [
            (json!({"alg": "none", "kid": "es"}), Refused::Algorithm),
            (json!({"alg": "HS256", "kid": "es"}), Refused::Algorithm),
            (json!({"alg": "ES384", "kid": "es"}), Refused::Algorithm),
            (
                json!({"alg": "ES256", "kid": "es", "jwk": {"kty": "EC"}}),
                Refused::HeaderKey,
            ),
            (
                json!({"alg": "ES256", "kid": "es", "jku": "https://evil"}),
                Refused::HeaderKey,
            ),
            (
                json!({"alg": "ES256", "kid": "es", "x5c": ["MIIB"]}),
                Refused::HeaderKey,
            ),
            (
                json!({"alg": "ES256", "kid": "es", "crit": ["exp"]}),
                Refused::HeaderKey,
            ),
            (json!({"alg": "ES256"}), Refused::UnknownKey),
            (json!({"alg": "ES256", "kid": "other"}), Refused::UnknownKey),
            // An RS256 header naming the EC key: the key decides, not the header.
            (json!({"alg": "RS256", "kid": "es"}), Refused::KeyMismatch),
        ] {
            assert_eq!(check(&k, &header, &c), Err(want), "{header}");
        }
        // An algorithm the configuration does not allow, even if the key fits.
        let only_es = Expect {
            algorithms: &[Alg::Es256],
            ..expect(AcrPolicy::PhishingResistant)
        };
        let t = sign(&k, &json!({"alg": "RS256", "kid": "rs"}), &claims());
        assert_eq!(
            validate(&t, &k.jwks, &only_es, NOW),
            Err(Refused::Algorithm)
        );
    }

    #[test]
    fn a_changed_payload_or_signature_is_refused() {
        let k = keys();
        let t = sign(&k, &json!({"alg": "ES256", "kid": "es"}), &claims());
        let mut parts: Vec<String> = t.split('.').map(str::to_owned).collect();
        let mut forged = claims();
        forged["sub"] = json!("admin");
        parts[1] = enc(forged.to_string().as_bytes());
        let swapped = parts.join(".");
        let e = expect(AcrPolicy::PhishingResistant);
        assert_eq!(
            validate(&swapped, &k.jwks, &e, NOW),
            Err(Refused::Signature)
        );
        // A signature made by another key under the same kid.
        let other = keys();
        let t2 = sign(&other, &json!({"alg": "ES256", "kid": "es"}), &claims());
        assert_eq!(validate(&t2, &k.jwks, &e, NOW), Err(Refused::Signature));
    }

    #[test]
    fn every_claim_is_checked() {
        let k = keys();
        let h = json!({"alg": "ES256", "kid": "es"});
        let with = |field: &str, value: serde_json::Value| {
            let mut c = claims();
            c[field] = value;
            c
        };
        let without = |field: &str| {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(field);
            c
        };
        for (c, want) in [
            (with("iss", json!("https://other.example")), Refused::Issuer),
            (with("aud", json!("someone-else")), Refused::Audience),
            (with("aud", json!(["gw", "other"])), Refused::Audience),
            (with("aud", json!([1, "gw"])), Refused::Audience),
            (with("azp", json!("other")), Refused::Audience),
            (with("exp", json!(NOW - CLOCK_SKEW)), Refused::Expired),
            (
                with("iat", json!(NOW + CLOCK_SKEW + 1)),
                Refused::IssuedInFuture,
            ),
            (with("nonce", json!("n-124")), Refused::Nonce),
            (without("nonce"), Refused::Nonce),
            (with("acr", json!("pwd")), Refused::Acr),
            (
                with("acr", json!("urn:mace:incommon:iap:silver")),
                Refused::Acr,
            ),
            (without("acr"), Refused::Acr),
            (without("sub"), Refused::Subject),
            (with("sub", json!("")), Refused::Subject),
            (with("exp", json!(1.8e9)), Refused::Malformed),
        ] {
            assert_eq!(check(&k, &h, &c), Err(want), "{c}");
        }
        // Several audiences are accepted with azp naming this client.
        let mut ok = with("aud", json!(["gw", "other"]));
        ok["azp"] = json!("gw");
        assert!(check(&k, &h, &ok).is_ok());
        // Within the skew, a token just expired or just issued is still accepted.
        assert!(check(&k, &h, &with("exp", json!(NOW - CLOCK_SKEW + 1))).is_ok());
        assert!(check(&k, &h, &with("iat", json!(NOW + CLOCK_SKEW))).is_ok());
    }

    #[test]
    fn hardware_policy_accepts_only_phrh() {
        let k = keys();
        let h = json!({"alg": "ES256", "kid": "es"});
        let hw = expect(AcrPolicy::HardwareProtected);
        let phr = sign(&k, &h, &claims());
        assert_eq!(validate(&phr, &k.jwks, &hw, NOW), Err(Refused::Acr));
        let mut c = claims();
        c["acr"] = json!("phrh");
        let phrh = sign(&k, &h, &c);
        assert!(validate(&phrh, &k.jwks, &hw, NOW).is_ok());
        assert!(validate(&phrh, &k.jwks, &expect(AcrPolicy::PhishingResistant), NOW).is_ok());
        assert_eq!(AcrPolicy::HardwareProtected.request(), "phrh");
    }

    #[test]
    fn shape_and_size_are_checked_first() {
        let k = keys();
        let e = expect(AcrPolicy::PhishingResistant);
        let t = sign(&k, &json!({"alg": "ES256", "kid": "es"}), &claims());
        for bad in [
            "a.b".to_owned(),
            format!("{t}.extra"),
            format!("{t}="),
            t.replacen('.', "..", 1),
            "x".repeat(MAX_ID_TOKEN + 1),
        ] {
            assert!(validate(&bad, &k.jwks, &e, NOW).is_err(), "{bad:.40}");
        }
        assert_eq!(
            validate(&"x".repeat(MAX_ID_TOKEN + 1), &k.jwks, &e, NOW),
            Err(Refused::TooLarge)
        );
    }

    #[test]
    fn a_key_set_with_a_duplicate_or_malformed_key_is_refused() {
        let ec = |kid: &str| json!({"kty": "EC", "crv": "P-256", "kid": kid, "x": enc(&[1; 32]), "y": enc(&[2; 32])});
        for doc in [
            json!({"keys": [ec("a"), ec("a")]}),
            json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "a", "x": enc(&[1; 31]), "y": enc(&[2; 32])}]}),
            json!({"keys": [{"kty": "EC", "crv": "P-256", "x": enc(&[1; 32]), "y": enc(&[2; 32])}]}),
            json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "a", "alg": "RS256", "x": enc(&[1; 32]), "y": enc(&[2; 32])}]}),
            json!({"keys": (0..=MAX_KEYS).map(|i| ec(&format!("k{i}"))).collect::<Vec<_>>()}),
            json!({"nokeys": []}),
        ] {
            assert_eq!(
                Jwks::parse(doc.to_string().as_bytes()),
                Err(Refused::KeySet),
                "{doc}"
            );
        }
        assert_eq!(
            Jwks::parse(&vec![b' '; MAX_JWKS + 1]),
            Err(Refused::TooLarge)
        );
    }
}
