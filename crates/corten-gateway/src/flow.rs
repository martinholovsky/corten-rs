//! The OpenID Connect authorization-code flow, as the gateway's relying party
//! runs it (`docs/gates/gateway-proposal.md`; owner decision 2026-11-14, Q2
//! option C). Pure logic: no network. The caller fetches documents and
//! performs the HTTP requests this module describes.
//!
//! - [`discover`] accepts provider metadata only for the configured issuer
//!   (OpenID Connect Discovery 4.3, RFC 8414 3.3), with HTTPS endpoints, PKCE
//!   S256, `private_key_jwt`, an allowed signing algorithm and the `acr`
//!   values the policy needs; otherwise the gateway does not start.
//! - [`Pendings::begin`] builds the authorization request with a fresh
//!   256-bit `state`, `nonce` and PKCE verifier (S256), kept server-side.
//! - [`Pendings::finish`] consumes the `state` once, refuses a provider
//!   error, a repeated parameter, an old request, or an `iss` response
//!   parameter (RFC 9207) for another issuer, and returns the code.
//! - [`token_request`] builds the token request with a `private_key_jwt`
//!   client assertion (RFC 7523 as updated by RFC 10070: `aud` is the
//!   issuer identifier, the sole value; type `client-authentication+jwt`).
//! - [`id_token_from`] reads the ID token from the token response, for
//!   [`crate::idtoken::validate`].

use std::collections::BTreeMap;

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::idtoken::{AcrPolicy, Alg};

/// Largest metadata or token response read, in bytes.
pub const MAX_DOCUMENT: usize = 64 * 1024;
/// How long an authorization request may wait for its callback, in seconds.
pub const PENDING_TTL: u64 = 600;
/// Most authorization requests outstanding at once.
pub const MAX_PENDING: usize = 10_000;
/// Longest authorization code accepted, in bytes.
pub const MAX_CODE: usize = 2048;
/// Lifetime of a client assertion, in seconds.
pub const ASSERTION_TTL: u64 = 60;

/// Why a flow step was refused. Each names its reason for the log; the user
/// sees one generic failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// Provider metadata refused, with the reason.
    Metadata(&'static str),
    /// No outstanding request has this `state` (unknown, or already used).
    State,
    /// The request is older than [`PENDING_TTL`].
    Expired,
    /// Too many requests outstanding.
    Busy,
    /// The provider returned an error code (restricted to `[a-z_]`).
    Provider(String),
    /// The `iss` response parameter is missing where required, or another issuer's.
    IssuerParameter,
    /// A parameter is missing, repeated, too long or malformed.
    Malformed,
    /// The system random generator or the signer failed.
    Crypto,
}

impl FlowError {
    /// The reason as the log records it.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Metadata(why) => format!("metadata refused: {why}"),
            Self::State => "unknown or used state".to_owned(),
            Self::Expired => "authorization request expired".to_owned(),
            Self::Busy => "too many outstanding requests".to_owned(),
            Self::Provider(code) => format!("provider error {code}"),
            Self::IssuerParameter => "issuer parameter mismatch".to_owned(),
            Self::Malformed => "malformed response".to_owned(),
            Self::Crypto => "randomness or signing failed".to_owned(),
        }
    }
}

/// A provider the gateway accepted at start-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The issuer identifier.
    pub issuer: String,
    /// Where the browser is sent.
    pub authorization_endpoint: String,
    /// Where the code is exchanged.
    pub token_endpoint: String,
    /// Where the signing keys are fetched.
    pub jwks_uri: String,
    /// Whether the provider sends the `iss` response parameter (RFC 9207),
    /// which then becomes mandatory.
    pub iss_parameter: bool,
    /// The configured algorithms the provider also uses.
    pub algorithms: Vec<Alg>,
}

#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    acr_values_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

fn https(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.fragment().is_none()
            && u.username().is_empty()
            && u.password().is_none()
    })
}

/// Accepts provider metadata fetched from `issuer`'s
/// `/.well-known/openid-configuration`.
///
/// # Errors
///
/// [`FlowError::Metadata`] naming the first requirement not met.
pub fn discover(
    json: &[u8],
    issuer: &str,
    policy: AcrPolicy,
    allowed: &[Alg],
) -> Result<Provider, FlowError> {
    if json.len() > MAX_DOCUMENT {
        return Err(FlowError::Metadata("too large"));
    }
    let m: Metadata =
        serde_json::from_slice(json).map_err(|_| FlowError::Metadata("not provider metadata"))?;
    if m.issuer != issuer {
        return Err(FlowError::Metadata("issuer is not the configured one"));
    }
    if ![
        &m.issuer,
        &m.authorization_endpoint,
        &m.token_endpoint,
        &m.jwks_uri,
    ]
    .iter()
    .all(|u| https(u))
    {
        return Err(FlowError::Metadata("an endpoint is not HTTPS"));
    }
    if !m
        .code_challenge_methods_supported
        .iter()
        .any(|c| c == "S256")
    {
        return Err(FlowError::Metadata("no PKCE S256"));
    }
    if !m
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|c| c == "private_key_jwt")
    {
        return Err(FlowError::Metadata("no private_key_jwt"));
    }
    let needed: &[&str] = match policy {
        AcrPolicy::PhishingResistant => &["phr", "phrh"],
        AcrPolicy::HardwareProtected => &["phrh"],
    };
    if !m
        .acr_values_supported
        .iter()
        .any(|a| needed.contains(&a.as_str()))
    {
        return Err(FlowError::Metadata("no phishing-resistant acr value"));
    }
    let algorithms: Vec<Alg> = allowed
        .iter()
        .copied()
        .filter(|a| {
            m.id_token_signing_alg_values_supported
                .iter()
                .any(|name| alg_name_matches(*a, name))
        })
        .collect();
    if algorithms.is_empty() {
        return Err(FlowError::Metadata("no allowed signing algorithm"));
    }
    Ok(Provider {
        issuer: m.issuer,
        authorization_endpoint: m.authorization_endpoint,
        token_endpoint: m.token_endpoint,
        jwks_uri: m.jwks_uri,
        iss_parameter: m.authorization_response_iss_parameter_supported,
        algorithms,
    })
}

fn alg_name_matches(alg: Alg, name: &str) -> bool {
    match alg {
        Alg::Rs256 => name == "RS256",
        Alg::Es256 => name == "ES256",
        Alg::Ed25519 => name == "EdDSA" || name == "Ed25519",
    }
}

/// This gateway's registration at the provider.
#[derive(Debug, Clone, Copy)]
pub struct Client<'a> {
    /// The client ID.
    pub client_id: &'a str,
    /// The exact registered redirect URI.
    pub redirect_uri: &'a str,
    /// Which authentication contexts to request and accept.
    pub acr: AcrPolicy,
}

/// The secrets of one sign-in, kept server-side until its callback.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    nonce: String,
    verifier: String,
    issuer: String,
    created: u64,
}

/// What a valid callback yields: the code and this sign-in's secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    /// The authorization code.
    pub code: String,
    /// The PKCE verifier to send with it.
    pub verifier: String,
    /// The `nonce` the ID token must carry.
    pub nonce: String,
}

/// Outstanding authorization requests, by `state`. Bounded in number and
/// age, and each `state` is used once.
#[derive(Debug, Default)]
pub struct Pendings {
    by_state: BTreeMap<String, Pending>,
}

fn random_token() -> Result<String, FlowError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| FlowError::Crypto)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The S256 code challenge for a verifier (RFC 7636 4.2).
#[must_use]
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        verifier.as_bytes(),
    ))
}

impl Pendings {
    fn expire(&mut self, now: u64) {
        self.by_state.retain(|_, p| {
            p.created
                .checked_add(PENDING_TTL)
                .is_some_and(|limit| now < limit)
        });
    }

    /// Starts a sign-in: records its secrets and returns the URL to send
    /// the browser to.
    ///
    /// # Errors
    ///
    /// [`FlowError::Busy`] at [`MAX_PENDING`] live requests;
    /// [`FlowError::Crypto`]; [`FlowError::Metadata`] if the endpoint does
    /// not parse.
    pub fn begin(
        &mut self,
        provider: &Provider,
        client: &Client<'_>,
        now: u64,
    ) -> Result<String, FlowError> {
        self.expire(now);
        if self.by_state.len() >= MAX_PENDING {
            return Err(FlowError::Busy);
        }
        let (state, nonce, verifier) = (random_token()?, random_token()?, random_token()?);
        let mut url = url::Url::parse(&provider.authorization_endpoint)
            .map_err(|_| FlowError::Metadata("authorization endpoint"))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client.client_id)
            .append_pair("redirect_uri", client.redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge(&verifier))
            .append_pair("code_challenge_method", "S256")
            .append_pair("acr_values", client.acr.request());
        let pending = Pending {
            nonce,
            verifier,
            issuer: provider.issuer.clone(),
            created: now,
        };
        let _replaced = self.by_state.insert(state, pending);
        Ok(url.into())
    }

    /// Checks the callback's query string. The `state` it names is consumed
    /// whatever the outcome.
    ///
    /// # Errors
    ///
    /// The first check that fails, as [`FlowError`].
    pub fn finish(
        &mut self,
        query: &str,
        provider: &Provider,
        now: u64,
    ) -> Result<Callback, FlowError> {
        let mut params: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if params.insert(k.into_owned(), v.into_owned()).is_some() {
                return Err(FlowError::Malformed);
            }
        }
        let state = params.get("state").ok_or(FlowError::State)?;
        let pending = self.by_state.remove(state).ok_or(FlowError::State)?;
        if pending
            .created
            .checked_add(PENDING_TTL)
            .is_none_or(|limit| now >= limit)
        {
            return Err(FlowError::Expired);
        }
        match params.get("iss") {
            Some(iss) if *iss != pending.issuer || *iss != provider.issuer => {
                return Err(FlowError::IssuerParameter);
            }
            None if provider.iss_parameter => return Err(FlowError::IssuerParameter),
            _ => {}
        }
        if let Some(error) = params.get("error") {
            let code: String = error
                .chars()
                .filter(|c| c.is_ascii_lowercase() || *c == '_')
                .take(64)
                .collect();
            return Err(FlowError::Provider(code));
        }
        let code = params.get("code").ok_or(FlowError::Malformed)?;
        if code.is_empty() || code.len() > MAX_CODE || !code.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(FlowError::Malformed);
        }
        Ok(Callback {
            code: code.clone(),
            verifier: pending.verifier,
            nonce: pending.nonce,
        })
    }

    /// How many requests are outstanding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_state.len()
    }

    /// Whether none are.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_state.is_empty()
    }
}

/// The gateway's own key for `private_key_jwt`, registered at the provider.
pub struct ClientKey {
    /// The key identifier registered with the public key.
    pub kid: String,
    /// The P-256 signing key.
    pub key: EcdsaKeyPair,
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl ClientKey {
    /// The public key as a JWK, for registering the client.
    #[must_use]
    pub fn public_jwk(&self) -> serde_json::Value {
        let point = self.key.public_key().as_ref();
        let (x, y) = (point.get(1..33), point.get(33..65));
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": self.kid,
            "x": x.map(|v| URL_SAFE_NO_PAD.encode(v)),
            "y": y.map(|v| URL_SAFE_NO_PAD.encode(v)),
        })
    }

    fn assertion(&self, client_id: &str, issuer: &str, now: u64) -> Result<String, FlowError> {
        let header = serde_json::json!({
            "alg": "ES256", "kid": self.kid, "typ": "client-authentication+jwt",
        });
        let exp = now.checked_add(ASSERTION_TTL).ok_or(FlowError::Crypto)?;
        // RFC 10070: the issuer identifier is the sole audience, never the
        // token endpoint.
        let claims = serde_json::json!({
            "iss": client_id, "sub": client_id, "aud": issuer,
            "jti": random_token()?, "iat": now, "exp": exp,
        });
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| FlowError::Crypto)?;
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())))
    }
}

/// The token request for a callback: `(url, form body)`, to POST with
/// `Content-Type: application/x-www-form-urlencoded`.
///
/// # Errors
///
/// [`FlowError::Crypto`] if the assertion cannot be signed.
pub fn token_request(
    provider: &Provider,
    client: &Client<'_>,
    callback: &Callback,
    key: &ClientKey,
    now: u64,
) -> Result<(String, String), FlowError> {
    let assertion = key.assertion(client.client_id, &provider.issuer, now)?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &callback.code)
        .append_pair("redirect_uri", client.redirect_uri)
        .append_pair("code_verifier", &callback.verifier)
        .append_pair("client_id", client.client_id)
        .append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .append_pair("client_assertion", &assertion)
        .finish();
    Ok((provider.token_endpoint.clone(), body))
}

#[derive(Deserialize)]
struct TokenResponse {
    token_type: String,
    id_token: Option<String>,
}

/// The ID token in a token response.
///
/// # Errors
///
/// [`FlowError::Malformed`] if the response is too large, not a bearer
/// token response, or has no ID token.
pub fn id_token_from(json: &[u8]) -> Result<String, FlowError> {
    if json.len() > MAX_DOCUMENT {
        return Err(FlowError::Malformed);
    }
    let r: TokenResponse = serde_json::from_slice(json).map_err(|_| FlowError::Malformed)?;
    if !r.token_type.eq_ignore_ascii_case("bearer") {
        return Err(FlowError::Malformed);
    }
    r.id_token
        .filter(|t| !t.is_empty())
        .ok_or(FlowError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISS: &str = "https://idp.example";
    const NOW: u64 = 1_800_000_000;
    const ALL: &[Alg] = &[Alg::Rs256, Alg::Es256, Alg::Ed25519];

    fn metadata() -> serde_json::Value {
        json!({
            "issuer": ISS,
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "jwks_uri": "https://idp.example/jwks",
            "code_challenge_methods_supported": ["plain", "S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "acr_values_supported": ["pwd", "phr", "phrh"],
            "authorization_response_iss_parameter_supported": true
        })
    }

    fn provider() -> Provider {
        discover(
            metadata().to_string().as_bytes(),
            ISS,
            AcrPolicy::PhishingResistant,
            ALL,
        )
        .unwrap()
    }

    fn client() -> Client<'static> {
        Client {
            client_id: "gw",
            redirect_uri: "https://gw.example/callback",
            acr: AcrPolicy::PhishingResistant,
        }
    }

    #[test]
    fn discovery_accepts_a_provider_that_meets_every_requirement() {
        let p = provider();
        assert_eq!(p.issuer, ISS);
        assert!(p.iss_parameter);
        assert_eq!(p.algorithms, [Alg::Rs256, Alg::Es256]);
    }

    #[test]
    fn discovery_refuses_each_missing_requirement() {
        let with = |field: &str, value: serde_json::Value| {
            let mut m = metadata();
            m[field] = value;
            m
        };
        for (m, policy, why) in [
            (
                with("issuer", json!("https://idp.example/")),
                AcrPolicy::PhishingResistant,
                "issuer is not the configured one",
            ),
            (
                with("token_endpoint", json!("http://idp.example/token")),
                AcrPolicy::PhishingResistant,
                "an endpoint is not HTTPS",
            ),
            (
                with("jwks_uri", json!("https://u:p@idp.example/jwks")),
                AcrPolicy::PhishingResistant,
                "an endpoint is not HTTPS",
            ),
            (
                with(
                    "authorization_endpoint",
                    json!("https://idp.example/a#frag"),
                ),
                AcrPolicy::PhishingResistant,
                "an endpoint is not HTTPS",
            ),
            (
                with("code_challenge_methods_supported", json!(["plain"])),
                AcrPolicy::PhishingResistant,
                "no PKCE S256",
            ),
            (
                with(
                    "token_endpoint_auth_methods_supported",
                    json!(["client_secret_post"]),
                ),
                AcrPolicy::PhishingResistant,
                "no private_key_jwt",
            ),
            (
                with("acr_values_supported", json!(["pwd", "mfa"])),
                AcrPolicy::PhishingResistant,
                "no phishing-resistant acr value",
            ),
            (
                with("acr_values_supported", json!(["phr"])),
                AcrPolicy::HardwareProtected,
                "no phishing-resistant acr value",
            ),
            (
                with(
                    "id_token_signing_alg_values_supported",
                    json!(["HS256", "PS256"]),
                ),
                AcrPolicy::PhishingResistant,
                "no allowed signing algorithm",
            ),
        ] {
            assert_eq!(
                discover(m.to_string().as_bytes(), ISS, policy, ALL),
                Err(FlowError::Metadata(why)),
                "{m}"
            );
        }
        assert_eq!(
            discover(
                &vec![b' '; MAX_DOCUMENT + 1],
                ISS,
                AcrPolicy::PhishingResistant,
                ALL
            ),
            Err(FlowError::Metadata("too large"))
        );
    }

    fn query_of(url: &str) -> BTreeMap<String, String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    }

    #[test]
    fn begin_sends_pkce_s256_state_nonce_and_acr() {
        let mut pendings = Pendings::default();
        let url = pendings.begin(&provider(), &client(), NOW).unwrap();
        assert!(url.starts_with("https://idp.example/authorize?"));
        let q = query_of(&url);
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "openid");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["acr_values"], "phrh phr");
        assert_eq!(q["redirect_uri"], "https://gw.example/callback");
        let p = &pendings.by_state[&q["state"]];
        assert_eq!(q["code_challenge"], challenge(&p.verifier));
        assert_eq!(q["nonce"], p.nonce);
        // 32 random bytes each, and fresh per request.
        assert_eq!((q["state"].len(), p.verifier.len()), (43, 43));
        let url2 = pendings.begin(&provider(), &client(), NOW).unwrap();
        assert_ne!(query_of(&url2)["state"], q["state"]);
        // RFC 7636 appendix B: the S256 challenge of its example verifier.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    fn started() -> (Pendings, String) {
        let mut pendings = Pendings::default();
        let url = pendings.begin(&provider(), &client(), NOW).unwrap();
        let state = query_of(&url)["state"].clone();
        (pendings, state)
    }

    #[test]
    fn a_callback_is_accepted_once() {
        let (mut pendings, state) = started();
        let q = format!("code=abc&state={state}&iss=https%3A%2F%2Fidp.example");
        let cb = pendings.finish(&q, &provider(), NOW + 10).unwrap();
        assert_eq!(cb.code, "abc");
        assert!(pendings.is_empty());
        assert_eq!(
            pendings.finish(&q, &provider(), NOW + 11),
            Err(FlowError::State)
        );
    }

    #[test]
    fn a_bad_callback_is_refused_and_still_consumes_its_state() {
        let p = provider();
        let iss = "iss=https%3A%2F%2Fidp.example";
        for (q, want) in [
            ("code=abc&state=nope".to_owned(), FlowError::State),
            ("code=abc".to_owned(), FlowError::State),
            (
                "code=abc&state=S&iss=https%3A%2F%2Fevil.example".to_owned(),
                FlowError::IssuerParameter,
            ),
            ("code=abc&state=S".to_owned(), FlowError::IssuerParameter),
            (
                format!("error=access_denied&state=S&{iss}"),
                FlowError::Provider("access_denied".into()),
            ),
            (
                format!("error=x%3Cscript%3E&state=S&{iss}"),
                FlowError::Provider("xscript".into()),
            ),
            (format!("state=S&{iss}"), FlowError::Malformed),
            (format!("code=a%20b&state=S&{iss}"), FlowError::Malformed),
            (
                format!("code={}&state=S&{iss}", "a".repeat(MAX_CODE + 1)),
                FlowError::Malformed,
            ),
            (format!("code=a&code=b&state=S&{iss}"), FlowError::Malformed),
        ] {
            let (mut pendings, state) = started();
            let q = q.replace("state=S", &format!("state={state}"));
            assert_eq!(pendings.finish(&q, &p, NOW + 10), Err(want), "{q}");
            if q.contains(&state) && !q.contains("code=a&code=b") {
                assert!(pendings.is_empty(), "state left outstanding after {q}");
            }
        }
    }

    #[test]
    fn requests_expire_and_are_bounded() {
        let (mut pendings, state) = started();
        let q = format!("code=abc&state={state}&iss=https%3A%2F%2Fidp.example");
        assert_eq!(
            pendings.finish(&q, &provider(), NOW + PENDING_TTL),
            Err(FlowError::Expired)
        );
        let mut full = Pendings::default();
        for _ in 0..MAX_PENDING {
            full.begin(&provider(), &client(), NOW).unwrap();
        }
        assert_eq!(
            full.begin(&provider(), &client(), NOW),
            Err(FlowError::Busy)
        );
        // Expired requests free their place.
        assert!(
            full.begin(&provider(), &client(), NOW + PENDING_TTL)
                .is_ok()
        );
        assert_eq!(full.len(), 1);
    }

    #[test]
    fn the_token_request_carries_the_verifier_and_a_valid_client_assertion() {
        let key = ClientKey {
            kid: "gw-1".into(),
            key: EcdsaKeyPair::generate(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING)
                .unwrap(),
        };
        let cb = Callback {
            code: "abc".into(),
            verifier: "v".repeat(43),
            nonce: "n".into(),
        };
        let (url, body) = token_request(&provider(), &client(), &cb, &key, NOW).unwrap();
        assert_eq!(url, "https://idp.example/token");
        let form: BTreeMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code_verifier"], cb.verifier);
        assert_eq!(
            form["client_assertion_type"],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        let parts: Vec<&str> = form["client_assertion"].split('.').collect();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            header,
            json!({"alg": "ES256", "kid": "gw-1", "typ": "client-authentication+jwt"})
        );
        // RFC 10070: the issuer is the sole audience, a string, not the token endpoint.
        assert_eq!(claims["aud"], json!(ISS));
        assert_eq!(
            (claims["iss"].as_str(), claims["sub"].as_str()),
            (Some("gw"), Some("gw"))
        );
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            ASSERTION_TTL
        );
        assert_eq!(claims["jti"].as_str().unwrap().len(), 43);
        // The signature verifies under the published public key.
        let jwk = key.public_jwk();
        let mut point = vec![4u8];
        point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
        point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
        let signed = format!("{}.{}", parts[0], parts[1]);
        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            &point,
        )
        .verify(
            signed.as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .unwrap();
        assert!(
            !format!("{key:?}").contains("EcdsaKeyPair"),
            "the key is not printed"
        );
    }

    #[test]
    fn the_id_token_is_read_only_from_a_bearer_response() {
        assert_eq!(
            id_token_from(br#"{"token_type":"Bearer","id_token":"a.b.c"}"#),
            Ok("a.b.c".into())
        );
        assert_eq!(
            id_token_from(br#"{"token_type":"bearer","id_token":"a.b.c","access_token":"x"}"#),
            Ok("a.b.c".into())
        );
        for bad in [
            br#"{"token_type":"MAC","id_token":"a.b.c"}"#.to_vec(),
            br#"{"token_type":"Bearer"}"#.to_vec(),
            br#"{"token_type":"Bearer","id_token":""}"#.to_vec(),
            vec![b' '; MAX_DOCUMENT + 1],
        ] {
            assert_eq!(id_token_from(&bad), Err(FlowError::Malformed));
        }
    }
}
