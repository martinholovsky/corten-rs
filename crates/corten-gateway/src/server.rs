//! The gateway's HTTPS server and proxy (`docs/gates/gateway-proposal.md`,
//! owner decisions Q5 to Q7): TLS 1.3 for browsers, sign-in through the
//! provider, sessions, and every other request forwarded to the program over
//! a Unix socket with a fresh Corten token.
//!
//! The rules it applies are in [`crate::edge`]; this module wires them to the
//! network. Limits: [`MAX_CONCURRENT`] requests at once (503 beyond), a TLS
//! handshake and a request head within [`HEAD_TIMEOUT`], a program response
//! within [`Settings::upstream_timeout`] and at most [`MAX_UPSTREAM`] bytes
//! (buffered, not streamed: a limitation of this version). Shared state is
//! held under short locks, never across an `.await`; log records are
//! buffered under the lock and written after it.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use corten_std::log::{LogRecord, LogWriter};
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::{TokioIo, TokioTimer};

use crate::client::{Breaker, BreakerEvent, Https, RefreshLimiter};
use crate::edge::{self, Public, RateLimiter, Reject, Route};
use crate::flow::{self, Client, ClientKey, Pendings, Provider};
use crate::idtoken::{self, AcrPolicy, Alg, Expect, Jwks, Refused};
use crate::mint::Minter;
use crate::session::{self, Lookup, SessionConfig, Sessions};

/// Most requests handled at once.
pub const MAX_CONCURRENT: usize = 1024;
/// Longest TLS handshake and request head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest program response relayed, in bytes.
pub const MAX_UPSTREAM: usize = 16 * 1024 * 1024;
/// Largest request head buffered, in bytes.
pub const MAX_HEAD: usize = 64 * 1024;

/// What the operator configures.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The public origin and host.
    pub public: Public,
    /// The provider's issuer identifier.
    pub issuer: String,
    /// This gateway's client ID at the provider.
    pub client_id: String,
    /// Which authentication contexts count.
    pub acr: AcrPolicy,
    /// Which ID-token algorithms are allowed.
    pub algorithms: Vec<Alg>,
    /// The program's Unix socket.
    pub upstream: PathBuf,
    /// Session lifetimes and limits.
    pub sessions: SessionConfig,
    /// Sign-in requests one address may make at once.
    pub login_burst: u32,
    /// Seconds per further sign-in request.
    pub login_refill: u64,
    /// Longest wait for the program's response.
    pub upstream_timeout: Duration,
}

struct Loaded {
    provider: Provider,
    keys: Jwks,
}

struct State {
    pendings: Pendings,
    sessions: Sessions,
    limiter: RateLimiter,
    breaker: Breaker,
    refresh: RefreshLimiter,
    loaded: Option<Loaded>,
}

/// Log records gathered under a lock and written after it.
#[derive(Default)]
struct Buffer(Vec<LogRecord>);

impl LogWriter for Buffer {
    fn write(&mut self, record: &LogRecord) {
        self.0.push(record.clone());
    }
}

/// A running gateway.
pub struct Gateway {
    settings: Settings,
    client_key: ClientKey,
    minter: Minter,
    https: Https,
    state: Mutex<State>,
    log: Mutex<Box<dyn LogWriter + Send>>,
    permits: tokio::sync::Semaphore,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

type Reply = Response<Full<Bytes>>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn locked<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>, StatusCode> {
    // A poisoned lock means a handler panicked mid-update: fail closed.
    m.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn reply(status: StatusCode) -> Reply {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = status;
    edge::no_store(r.headers_mut());
    r
}

fn redirect(location: &str) -> Reply {
    let mut r = reply(StatusCode::SEE_OTHER);
    if let Ok(v) = HeaderValue::from_str(location) {
        let _ = r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

fn rejected(why: Reject) -> Reply {
    let mut r = reply(why.status());
    if let Reject::TooMany(after) = why
        && let Ok(v) = HeaderValue::from_str(&after.to_string())
    {
        let _ = r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

const NOT_RELAYED: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "trailer",
    "upgrade",
    "proxy-authenticate",
];

impl Gateway {
    /// A gateway that has not yet loaded its provider: sign-in answers 503
    /// until [`Gateway::load_provider`] succeeds.
    #[must_use]
    pub fn new(
        settings: Settings,
        client_key: ClientKey,
        minter: Minter,
        https: Https,
        log: Box<dyn LogWriter + Send>,
    ) -> Self {
        let state = State {
            pendings: Pendings::default(),
            sessions: Sessions::new(settings.sessions),
            limiter: RateLimiter::new(settings.login_burst, settings.login_refill),
            breaker: Breaker::default(),
            refresh: RefreshLimiter::default(),
            loaded: None,
        };
        Self {
            settings,
            client_key,
            minter,
            https,
            state: Mutex::new(state),
            log: Mutex::new(log),
            permits: tokio::sync::Semaphore::new(MAX_CONCURRENT),
        }
    }

    fn emit(&self, records: &[LogRecord]) {
        if let Ok(mut log) = self.log.lock() {
            for r in records {
                log.write(r);
            }
        }
    }

    fn note(&self, record: &LogRecord) {
        self.emit(std::slice::from_ref(record));
    }

    /// Fetches and checks the provider's metadata and key set.
    ///
    /// # Errors
    ///
    /// A message naming what was refused; sign-in stays unavailable.
    pub async fn load_provider(&self) -> Result<(), String> {
        let issuer = self.settings.issuer.trim_end_matches('/');
        let doc = self
            .https
            .get_with_retry(&format!("{issuer}/.well-known/openid-configuration"))
            .await
            .map_err(|e| format!("discovery: {e:?}"))?;
        let provider = flow::discover(
            &doc,
            &self.settings.issuer,
            self.settings.acr,
            &self.settings.algorithms,
        )
        .map_err(|e| e.reason())?;
        let jwks = self
            .https
            .get_with_retry(&provider.jwks_uri)
            .await
            .map_err(|e| format!("key set: {e:?}"))?;
        let keys = Jwks::parse(&jwks).map_err(|e| e.as_str().to_owned())?;
        locked(&self.state)
            .map_err(|_| "state lock poisoned".to_owned())?
            .loaded = Some(Loaded { provider, keys });
        self.note(&corten_std::log_record!(
            "gateway.provider_loaded",
            issuer = self.settings.issuer
        ));
        Ok(())
    }

    /// Handles one request from `peer`, with the security headers on every
    /// response.
    pub async fn handle(&self, req: Request<Incoming>, peer: IpAddr) -> Reply {
        let mut response = if let Ok(_permit) = self.permits.try_acquire() {
            match self.route(req, peer).await {
                Ok(r) => r,
                Err(status) => reply(status),
            }
        } else {
            let mut r = reply(StatusCode::SERVICE_UNAVAILABLE);
            let _ = r
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            r
        };
        edge::harden(response.headers_mut());
        response
    }

    async fn route(&self, req: Request<Incoming>, peer: IpAddr) -> Result<Reply, StatusCode> {
        if let Err(why) = edge::check_host(req.headers(), &self.settings.public) {
            return Ok(rejected(why));
        }
        match edge::route(req.method(), req.uri().path()) {
            Err(why) => Ok(rejected(why)),
            Ok(Route::Login) => self.login(peer),
            Ok(Route::Callback) => self.callback(&req, peer).await,
            Ok(Route::Logout) => self.logout(&req),
            Ok(Route::Proxy) => self.proxy(req).await,
        }
    }

    fn client(&self) -> (String, String, AcrPolicy) {
        (
            self.settings.client_id.clone(),
            format!("{}/.corten/callback", self.settings.public.origin),
            self.settings.acr,
        )
    }

    fn login(&self, peer: IpAddr) -> Result<Reply, StatusCode> {
        let at = now();
        let mut state = locked(&self.state)?;
        if let Err(why) = state.limiter.take(peer, at) {
            return Ok(rejected(why));
        }
        let (client_id, redirect_uri, acr) = self.client();
        let client = Client {
            client_id: &client_id,
            redirect_uri: &redirect_uri,
            acr,
        };
        let State {
            pendings, loaded, ..
        } = &mut *state;
        let Some(loaded) = loaded.as_ref() else {
            return Ok(reply(StatusCode::SERVICE_UNAVAILABLE));
        };
        match pendings.begin(&loaded.provider, &client, at) {
            Ok(url) => Ok(redirect(&url)),
            Err(flow::FlowError::Busy) => Ok(reply(StatusCode::SERVICE_UNAVAILABLE)),
            Err(_) => Ok(reply(StatusCode::INTERNAL_SERVER_ERROR)),
        }
    }

    fn refuse_sign_in(&self, reason: &str) -> Reply {
        self.note(&corten_std::log_record!(
            "gateway.sign_in_refused",
            reason = reason
        ));
        reply(StatusCode::FORBIDDEN)
    }

    async fn callback(&self, req: &Request<Incoming>, peer: IpAddr) -> Result<Reply, StatusCode> {
        let at = now();
        let query = req.uri().query().unwrap_or("");
        let (callback, provider) = {
            let mut state = locked(&self.state)?;
            if let Err(why) = state.limiter.take(peer, at) {
                return Ok(rejected(why));
            }
            if !state.breaker.allows(at) {
                return Ok(reply(StatusCode::SERVICE_UNAVAILABLE));
            }
            let State {
                pendings, loaded, ..
            } = &mut *state;
            let Some(loaded) = loaded.as_ref() else {
                return Ok(reply(StatusCode::SERVICE_UNAVAILABLE));
            };
            let provider = loaded.provider.clone();
            match pendings.finish(query, &provider, at) {
                Ok(cb) => (cb, provider),
                Err(e) => {
                    drop(state);
                    return Ok(self.refuse_sign_in(&e.reason()));
                }
            }
        };
        let (client_id, redirect_uri, acr) = self.client();
        let client = Client {
            client_id: &client_id,
            redirect_uri: &redirect_uri,
            acr,
        };
        let (url, body) = flow::token_request(&provider, &client, &callback, &self.client_key, at)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let answer = self.https.post_form(&url, &body).await;
        let event = locked(&self.state)?.breaker.record(answer.is_ok(), at);
        if let Some(e) = event {
            let state = if e == BreakerEvent::Opened {
                "open"
            } else {
                "closed"
            };
            self.note(&corten_std::log_record!("gateway.breaker", state = state));
        }
        let Ok(answer) = answer else {
            return Ok(self.refuse_sign_in("token endpoint failed"));
        };
        let Ok(id_token) = flow::id_token_from(&answer) else {
            return Ok(self.refuse_sign_in("no id token"));
        };
        let expect = Expect {
            issuer: &provider.issuer,
            client_id: &client_id,
            nonce: &callback.nonce,
            algorithms: &provider.algorithms,
            acr,
        };
        let mut checked = {
            let state = locked(&self.state)?;
            let keys = state.loaded.as_ref().map(|l| &l.keys);
            keys.map(|k| idtoken::validate(&id_token, k, &expect, at))
        };
        // A key the cached set lacks: re-fetch it once, rate-limited. The
        // lock is taken and released in its own statement, never held
        // across the fetch's `.await`.
        let may_refresh =
            checked == Some(Err(Refused::UnknownKey)) && locked(&self.state)?.refresh.take(at);
        if may_refresh
            && let Ok(doc) = self.https.get_with_retry(&provider.jwks_uri).await
            && let Ok(fresh) = Jwks::parse(&doc)
        {
            checked = Some(idtoken::validate(&id_token, &fresh, &expect, at));
            if let Some(l) = locked(&self.state)?.loaded.as_mut() {
                l.keys = fresh;
            }
        }
        let sign_in = match checked {
            Some(Ok(s)) => s,
            Some(Err(why)) => return Ok(self.refuse_sign_in(why.as_str())),
            None => return Ok(reply(StatusCode::SERVICE_UNAVAILABLE)),
        };
        if !corten_std::authz::token_field(&sign_in.subject) {
            return Ok(self.refuse_sign_in("subject is not a principal name"));
        }
        let mut buf = Buffer::default();
        let started =
            locked(&self.state)?
                .sessions
                .start(&sign_in.subject, &sign_in.acr, at, &mut buf);
        self.emit(&buf.0);
        let Ok(id) = started else {
            return Ok(reply(StatusCode::SERVICE_UNAVAILABLE));
        };
        let mut r = redirect("/");
        let cookie = HeaderValue::from_str(&session::set_cookie(&id, &self.settings.sessions))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let _ = r.headers_mut().insert(header::SET_COOKIE, cookie);
        Ok(r)
    }

    fn logout(&self, req: &Request<Incoming>) -> Result<Reply, StatusCode> {
        if let Err(why) = edge::check_same_origin(req.headers(), &self.settings.public) {
            return Ok(rejected(why));
        }
        let cookie = cookie_of(req);
        let mut buf = Buffer::default();
        let _ended = locked(&self.state)?
            .sessions
            .end(cookie.as_deref(), now(), &mut buf);
        self.emit(&buf.0);
        let mut r = redirect("/");
        let h = r.headers_mut();
        let clear = HeaderValue::from_str(&session::clear_cookie())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let _ = h.insert(header::SET_COOKIE, clear);
        let _ = h.insert(
            "clear-site-data",
            HeaderValue::from_static("\"cache\", \"cookies\", \"storage\""),
        );
        Ok(r)
    }

    async fn proxy(&self, req: Request<Incoming>) -> Result<Reply, StatusCode> {
        let at = now();
        let cookie = cookie_of(&req);
        let mut buf = Buffer::default();
        let found = locked(&self.state)?
            .sessions
            .check(cookie.as_deref(), at, &mut buf);
        self.emit(&buf.0);
        let Lookup::Live { principal, .. } = found else {
            return Ok(if matches!(*req.method(), Method::GET | Method::HEAD) {
                redirect("/.corten/login")
            } else {
                reply(StatusCode::UNAUTHORIZED)
            });
        };
        let token = self
            .minter
            .mint(&principal, at)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let headers = match edge::upstream_headers(req.headers(), &token) {
            Ok(h) => h,
            Err(why) => return Ok(rejected(why)),
        };
        let method = req.method().clone();
        let target = req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        let Ok(body) = Limited::new(req.into_body(), edge::MAX_BODY)
            .collect()
            .await
        else {
            return Ok(rejected(Reject::TooLarge));
        };
        let mut upstream = Request::builder()
            .method(method)
            .uri(target)
            .body(Full::new(body.to_bytes()))
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        *upstream.headers_mut() = headers;
        match tokio::time::timeout(self.settings.upstream_timeout, self.forward(upstream)).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(status)) => Ok(reply(status)),
            Err(_) => Ok(reply(StatusCode::GATEWAY_TIMEOUT)),
        }
    }

    async fn forward(&self, upstream: Request<Full<Bytes>>) -> Result<Reply, StatusCode> {
        let stream = tokio::net::UnixStream::connect(&self.settings.upstream)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let task = tokio::spawn(conn);
        let response = sender
            .send_request(upstream)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let (parts, body) = response.into_parts();
        let bytes = Limited::new(body, MAX_UPSTREAM)
            .collect()
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?
            .to_bytes();
        task.abort();
        let mut out = Response::new(Full::new(bytes));
        *out.status_mut() = parts.status;
        for (name, value) in &parts.headers {
            if NOT_RELAYED.contains(&name.as_str()) {
                continue;
            }
            // The program cannot set or overwrite the gateway's session cookie.
            if name == header::SET_COOKIE
                && value
                    .to_str()
                    .is_ok_and(|v| v.trim_start().starts_with(session::COOKIE))
            {
                continue;
            }
            let _ = out.headers_mut().append(name.clone(), value.clone());
        }
        Ok(out)
    }

    /// Serves HTTPS on `listener` until the task is dropped.
    pub async fn serve(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        tls: tokio_rustls::TlsAcceptor,
    ) {
        loop {
            let Ok((tcp, addr)) = listener.accept().await else {
                continue;
            };
            let gateway = Arc::clone(&self);
            let tls = tls.clone();
            let _conn = tokio::spawn(async move {
                let Ok(Ok(stream)) = tokio::time::timeout(HEAD_TIMEOUT, tls.accept(tcp)).await
                else {
                    return;
                };
                let peer = addr.ip();
                let service = hyper::service::service_fn(move |req| {
                    let gateway = Arc::clone(&gateway);
                    async move { Ok::<_, std::convert::Infallible>(gateway.handle(req, peer).await) }
                });
                let _done = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEAD_TIMEOUT)
                    .max_buf_size(MAX_HEAD)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }
}

fn cookie_of(req: &Request<Incoming>) -> Option<String> {
    let mut found = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(session::from_header);
    let first = found.next()?;
    // The session cookie in two Cookie headers is ambiguous: use neither.
    if found.next().is_some() {
        None
    } else {
        Some(first.to_owned())
    }
}

/// A TLS 1.3 acceptor from PEM files: the certificate chain and its key.
///
/// # Errors
///
/// A message naming the file or the refusal.
pub fn tls_acceptor(
    chain: &std::path::Path,
    key: &std::path::Path,
) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(chain)
        .map_err(|e| format!("{}: {e}", chain.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", chain.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};

    struct Pki {
        ca: rustls::pki_types::CertificateDer<'static>,
        leaf_pem: String,
        key_pem: String,
    }

    fn pki() -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        Pki {
            ca: ca.der().clone(),
            leaf_pem: leaf.pem(),
            key_pem: leaf_key.serialize_pem(),
        }
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<String>>>);
    impl LogWriter for Sink {
        fn write(&mut self, record: &LogRecord) {
            self.0.lock().unwrap().push(record.render());
        }
    }

    /// The mock provider's state: nonces by code, and the acr it asserts.
    #[derive(Default)]
    struct Idp {
        nonces: BTreeMap<String, String>,
        acr: String,
        sub: String,
    }

    fn enc(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    fn json(body: String) -> Response<Full<Bytes>> {
        Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    async fn serve_idp(
        tls: tokio_rustls::TlsAcceptor,
        idp: Arc<Mutex<Idp>>,
        key: Arc<EcdsaKeyPair>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let iss = format!("https://127.0.0.1:{port}");
        let _task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (tls, idp, key, iss) =
                    (tls.clone(), Arc::clone(&idp), Arc::clone(&key), iss.clone());
                let _c = tokio::spawn(async move {
                    let Ok(s) = tls.accept(tcp).await else { return };
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let (idp, key, iss) = (Arc::clone(&idp), Arc::clone(&key), iss.clone());
                        async move {
                            let path = req.uri().path().to_owned();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            Ok::<_, std::convert::Infallible>(match path.as_str() {
                                "/.well-known/openid-configuration" => json(serde_json::json!({
                                    "issuer": iss, "authorization_endpoint": format!("{iss}/authorize"),
                                    "token_endpoint": format!("{iss}/token"), "jwks_uri": format!("{iss}/jwks"),
                                    "code_challenge_methods_supported": ["S256"],
                                    "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                                    "id_token_signing_alg_values_supported": ["ES256"],
                                    "acr_values_supported": ["phr", "phrh"],
                                    "authorization_response_iss_parameter_supported": true
                                }).to_string()),
                                "/jwks" => {
                                    let p = key.public_key().as_ref();
                                    json(serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "idp-1",
                                        "x": enc(&p[1..33]), "y": enc(&p[33..65])}]}).to_string())
                                }
                                "/token" => {
                                    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
                                    assert_eq!(form["client_assertion"].split('.').count(), 3);
                                    assert_eq!(form["grant_type"], "authorization_code");
                                    let (nonce, acr, sub) = {
                                        let i = idp.lock().unwrap();
                                        (i.nonces[&form["code"]].clone(), i.acr.clone(), i.sub.clone())
                                    };
                                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                    let signed = format!("{}.{}",
                                        enc(br#"{"alg":"ES256","kid":"idp-1"}"#),
                                        enc(serde_json::json!({"iss": iss, "aud": "gw", "exp": now.checked_add(300).unwrap(), "iat": now,
                                            "nonce": nonce, "acr": acr, "sub": sub}).to_string().as_bytes()));
                                    let sig = key.sign(&SystemRandom::new(), signed.as_bytes()).unwrap();
                                    json(serde_json::json!({"token_type": "Bearer", "id_token": format!("{signed}.{}", enc(sig.as_ref()))}).to_string())
                                }
                                _ => Response::builder().status(404).body(Full::new(Bytes::new())).unwrap(),
                            })
                        }
                    });
                    let _served = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        port
    }

    /// The program: echoes the Authorization and Cookie it received, and
    /// tries to set the gateway's cookie and leak a Server header.
    fn serve_program(path: &std::path::Path) {
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let _task = tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let _c = tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let h = |n: &str| {
                            req.headers()
                                .get(n)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("-")
                                .to_owned()
                        };
                        let body = format!("auth={}|cookie={}", h("authorization"), h("cookie"));
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header("server", "program/1.0")
                                .header("set-cookie", "__Host-corten-session=evil; Path=/")
                                .header("set-cookie", "theme=dark")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    });
                    let _served = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
        });
    }

    struct World {
        gw_port: u16,
        roots: rustls::RootCertStore,
        idp: Arc<Mutex<Idp>>,
        minter_entry: String,
        logs: Sink,
        dir: PathBuf,
    }

    async fn world(login_burst: u32) -> World {
        world_with(login_burst, false).await
    }

    /// The program side as Corten deploys it: a signed manifest that trusts
    /// the gateway's minting key (`authn api token ...`) and grants a socket
    /// (`listen app unix ... authn api`), served by `corten_std::listen`.
    fn serve_corten_program(socket: &std::path::Path, entry: &str) {
        let deployer = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([9; 32]));
        let m = format!(
            "corten-manifest 3\nkey dep\nserial 1\nnot-after 4102444800\nprogram sha256 {}\nauthn api token {entry}\nlisten app unix {} authn api\n",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            socket.display()
        );
        let mut trusted = corten_std::manifest::TrustedKeys::new();
        trusted
            .add(
                corten_std::manifest::KeyId("dep"),
                corten_std::manifest::PublicKey(deployer.pk.as_ref()),
            )
            .unwrap();
        let sig = deployer.sk.sign(m.as_bytes(), None);
        let mut caps = corten_std::manifest::Capabilities::load(
            m.as_bytes(),
            corten_std::manifest::Signature(sig.as_ref()),
            &trusted,
            corten_std::manifest::MinSerial(0),
        )
        .unwrap();
        let listener = caps.take_listener("app").unwrap();
        let _serving = std::thread::spawn(move || {
            listener.serve(
                |who, req| {
                    corten_std::listen::Response::ok(format!(
                        "principal={}|auth={}|cookie={}",
                        who.principal(),
                        req.header("authorization").unwrap_or("-"),
                        req.header("cookie").unwrap_or("-")
                    ))
                },
                Sink::default(),
            )
        });
    }

    async fn world_with(login_burst: u32, real_program: bool) -> World {
        use std::os::unix::fs::PermissionsExt as _;
        static WORLDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let pki = pki();
        let n = WORLDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("corten-gw-{}-{n}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(dir.join("cert.pem"), &pki.leaf_pem).unwrap();
        std::fs::write(dir.join("key.pem"), &pki.key_pem).unwrap();
        std::fs::write(dir.join("mint.key"), "corten-signing-key 1\nid gw-1\nseed 0707070707070707070707070707070707070707070707070707070707070707\n").unwrap();
        std::fs::set_permissions(dir.join("mint.key"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let tls = tls_acceptor(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
        let idp = Arc::new(Mutex::new(Idp {
            acr: "phr".into(),
            sub: "user-1".into(),
            ..Idp::default()
        }));
        let idp_key = Arc::new(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap());
        let idp_port = serve_idp(tls.clone(), Arc::clone(&idp), idp_key).await;
        let minter = Minter::from_key_file(&dir.join("mint.key"), "api", 300).unwrap();
        let minter_entry = minter.manifest_entry();
        let socket = dir.join("program.sock");
        if real_program {
            serve_corten_program(&socket, &minter_entry);
        } else {
            serve_program(&socket);
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pki.ca.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_port = listener.local_addr().unwrap().port();
        let logs = Sink::default();
        let settings = Settings {
            public: Public {
                origin: format!("https://127.0.0.1:{gw_port}"),
                host: format!("127.0.0.1:{gw_port}"),
            },
            issuer: format!("https://127.0.0.1:{idp_port}"),
            client_id: "gw".into(),
            acr: AcrPolicy::PhishingResistant,
            algorithms: vec![Alg::Es256],
            upstream: socket,
            sessions: SessionConfig::default(),
            login_burst,
            login_refill: 60,
            upstream_timeout: Duration::from_secs(5),
        };
        let gateway = Arc::new(Gateway::new(
            settings,
            ClientKey {
                kid: "gw-client".into(),
                key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
            },
            minter,
            Https::new(roots.clone()).unwrap(),
            Box::new(logs.clone()),
        ));
        gateway.load_provider().await.unwrap();
        let _serving = tokio::spawn(Arc::clone(&gateway).serve(listener, tls));
        World {
            gw_port,
            roots,
            idp,
            minter_entry,
            logs,
            dir,
        }
    }

    /// One HTTPS request to the gateway, as a browser would send it.
    async fn browse(
        w: &World,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> Response<Bytes> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(w.roots.clone())
            .with_no_client_auth();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.gw_port))
            .await
            .unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        let _c = tokio::spawn(conn);
        let mut b = Request::builder().method(method).uri(path);
        let mut has_host = false;
        for (k, v) in extra {
            has_host |= k.eq_ignore_ascii_case("host");
            b = b.header(*k, *v);
        }
        if !has_host {
            b = b.header("host", format!("127.0.0.1:{}", w.gw_port));
        }
        let r = send
            .send_request(b.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        let (parts, body) = r.into_parts();
        Response::from_parts(parts, body.collect().await.unwrap().to_bytes())
    }

    fn location(r: &Response<Bytes>) -> String {
        r.headers()[header::LOCATION].to_str().unwrap().to_owned()
    }

    /// Runs the sign-in: login, the provider's redirect, the callback.
    async fn sign_in(w: &World) -> Response<Bytes> {
        let login = browse(w, "GET", "/.corten/login", &[]).await;
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let q: BTreeMap<String, String> = url::Url::parse(&location(&login))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        let _ = w
            .idp
            .lock()
            .unwrap()
            .nonces
            .insert("code-1".into(), q["nonce"].clone());
        let iss = url::form_urlencoded::byte_serialize(
            format!(
                "https://127.0.0.1:{}",
                url::Url::parse(&location(&login)).unwrap().port().unwrap()
            )
            .as_bytes(),
        )
        .collect::<String>();
        browse(
            w,
            "GET",
            &format!(
                "/.corten/callback?code=code-1&state={}&iss={iss}",
                q["state"]
            ),
            &[],
        )
        .await
    }

    fn session_cookie(r: &Response<Bytes>) -> String {
        let set = r.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(
            set.contains("Secure") && set.contains("HttpOnly") && set.contains("SameSite=Lax"),
            "{set}"
        );
        set.split(';').next().unwrap().to_owned()
    }

    /// The principal a token names, as a Corten program loading a manifest
    /// that trusts the gateway's minting key would see it.
    fn principal_of(token: &str, entry: &str) -> String {
        let deployer = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([9; 32]));
        let m = format!(
            "corten-manifest 3\nkey dep\nserial 1\nnot-after 4102444800\nprogram sha256 {}\nauthn api token {entry}\n",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut trusted = corten_std::manifest::TrustedKeys::new();
        trusted
            .add(
                corten_std::manifest::KeyId("dep"),
                corten_std::manifest::PublicKey(deployer.pk.as_ref()),
            )
            .unwrap();
        let sig = deployer.sk.sign(m.as_bytes(), None);
        let mut caps = corten_std::manifest::Capabilities::load(
            m.as_bytes(),
            corten_std::manifest::Signature(sig.as_ref()),
            &trusted,
            corten_std::manifest::MinSerial(0),
        )
        .unwrap();
        let mut sink = Sink::default();
        caps.take_token_authenticator("api")
            .unwrap()
            .authenticate(corten_std::authz::Token(token), &mut sink)
            .unwrap()
            .principal()
            .to_owned()
    }

    #[tokio::test]
    async fn a_passkey_sign_in_reaches_the_program_with_a_corten_token() {
        let w = world(10).await;
        // Signed out: a GET is sent to sign in; every response is hardened.
        let first = browse(&w, "GET", "/hello", &[]).await;
        assert_eq!(
            (first.status(), location(&first).as_str()),
            (StatusCode::SEE_OTHER, "/.corten/login")
        );
        assert_eq!(
            first.headers()["strict-transport-security"],
            "max-age=31536000"
        );
        assert_eq!(
            browse(&w, "POST", "/api", &[]).await.status(),
            StatusCode::UNAUTHORIZED
        );
        // Sign in.
        let done = sign_in(&w).await;
        assert_eq!(
            (done.status(), location(&done).as_str()),
            (StatusCode::SEE_OTHER, "/")
        );
        let cookie = session_cookie(&done);
        // A proxied request carries a Corten token, never the session cookie.
        let got = browse(
            &w,
            "GET",
            "/hello",
            &[
                ("cookie", &format!("{cookie}; theme=light")),
                ("authorization", "Bearer forged"),
            ],
        )
        .await;
        assert_eq!(got.status(), StatusCode::OK);
        let body = String::from_utf8(got.body().to_vec()).unwrap();
        let token = body
            .strip_prefix("auth=Bearer ")
            .unwrap()
            .split('|')
            .next()
            .unwrap()
            .to_owned();
        assert!(body.ends_with("|cookie=theme=light"), "{body}");
        // The program cannot set the gateway's cookie or leak its Server header.
        let sets: Vec<&str> = got
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(sets, ["theme=dark"]);
        assert!(got.headers().get("server").is_none());
        // The token authenticates through corten_std, from a signed manifest.
        assert_eq!(principal_of(&token, &w.minter_entry), "user-1");
        // Logout: cross-site refused; same-origin ends the session.
        let cross = browse(
            &w,
            "POST",
            "/.corten/logout",
            &[("cookie", &cookie), ("origin", "https://evil.example")],
        )
        .await;
        assert_eq!(cross.status(), StatusCode::FORBIDDEN);
        let out = browse(
            &w,
            "POST",
            "/.corten/logout",
            &[("cookie", &cookie), ("sec-fetch-site", "same-origin")],
        )
        .await;
        assert_eq!(out.status(), StatusCode::SEE_OTHER);
        assert!(
            out.headers()["clear-site-data"]
                .to_str()
                .unwrap()
                .contains("cookies")
        );
        // The ended cookie, replayed, goes back to sign-in and is logged.
        let replay = browse(&w, "GET", "/hello", &[("cookie", &cookie)]).await;
        assert_eq!(location(&replay), "/.corten/login");
        assert!(
            w.logs
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("session.use_after_end"))
        );
    }

    /// Q6 end to end: a passkey sign-in at the gateway reaches a Corten
    /// program's `listen` grant as the signed-in principal; the program sees
    /// neither the token nor the session cookie, and a request that skips
    /// the gateway gets 401.
    #[tokio::test]
    async fn a_corten_program_behind_the_gateway_serves_the_signed_in_user() {
        let w = world_with(10, true).await;
        let cookie = session_cookie(&sign_in(&w).await);
        let got = browse(&w, "GET", "/hello", &[("cookie", &cookie)]).await;
        assert_eq!(got.status(), StatusCode::OK);
        assert_eq!(&got.body()[..], b"principal=user-1|auth=-|cookie=-");
        // Straight to the socket, without the gateway: no token, no service.
        let direct = {
            use std::io::{Read as _, Write as _};
            let mut s =
                std::os::unix::net::UnixStream::connect(w.dir.join("program.sock")).unwrap();
            s.write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        assert!(direct.starts_with("HTTP/1.1 401"), "{direct}");
    }

    #[tokio::test]
    async fn a_sign_in_that_is_not_phishing_resistant_gets_no_session() {
        let w = world(10).await;
        w.idp.lock().unwrap().acr = "pwd".into();
        let r = sign_in(&w).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        assert!(
            w.logs
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("not phishing-resistant"))
        );
    }

    #[tokio::test]
    async fn a_subject_that_is_not_a_principal_name_gets_no_session() {
        let w = world(10).await;
        w.idp.lock().unwrap().sub = "user@example.com".into();
        let r = sign_in(&w).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        assert!(
            w.logs
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("subject is not a principal name"))
        );
    }

    #[tokio::test]
    async fn another_host_and_too_many_sign_ins_are_refused() {
        let w = world(2).await;
        assert_eq!(
            browse(&w, "GET", "/hello", &[("host", "evil.example")])
                .await
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            browse(&w, "GET", "/.corten/login", &[]).await.status(),
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            browse(&w, "GET", "/.corten/login", &[]).await.status(),
            StatusCode::SEE_OTHER
        );
        let limited = browse(&w, "GET", "/.corten/login", &[]).await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(limited.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(
            browse(&w, "GET", "/.corten/unknown", &[]).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
