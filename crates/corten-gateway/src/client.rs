//! The gateway's HTTPS client for its identity provider: discovery, the key
//! set and the token endpoint (`docs/gates/gateway-proposal.md`), built to
//! sota-architecture rules/04.
//!
//! - **Timeouts on every call:** [`Https::connect_timeout`] (5 s) and
//!   [`Https::request_timeout`] (10 s) by default. They are configured values,
//!   not measured from a provider, and should be tuned to its p99.
//! - **TLS 1.3 only**, as `corten_std::net`. The platform's roots
//!   ([`Https::platform`]), as question 13 decided.
//! - **Nothing followed or trusted that was not asked for:** HTTPS only, no
//!   redirects (a 3xx is an error), status 200 only, `application/json` only,
//!   and at most [`MAX_RESPONSE`] bytes read.
//! - **Retries:** [`Https::get_with_retry`] retries a GET on a connection
//!   error, a timeout or 408, 429, 502, 503 and 504, at most three attempts in
//!   all with full-jitter backoff. A POST (the token exchange, whose code is
//!   single-use) is never retried.
//! - **A circuit breaker** ([`Breaker`]) and a **refresh limiter**
//!   ([`RefreshLimiter`]) for the provider are pure state the server owns and
//!   logs; the gateway fails closed (no sign-in) while the breaker is open.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;

/// Most bytes read from one response.
pub const MAX_RESPONSE: usize = 64 * 1024;

/// Why a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// Not an `https` URL with a host.
    Url,
    /// The connection could not be made.
    Connect,
    /// The TLS handshake failed (an untrusted certificate, or no TLS 1.3).
    Tls,
    /// Connecting or the whole request took too long.
    Timeout,
    /// A status other than 200 (3xx included: redirects are not followed).
    Status(u16),
    /// The response is not `application/json`.
    ContentType,
    /// The body exceeds [`MAX_RESPONSE`].
    TooLarge,
    /// The request could not be written or the response read.
    Io,
}

impl HttpError {
    /// Whether a GET may be retried after this error (rules/04 section 2).
    #[must_use]
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Connect | Self::Timeout | Self::Status(408 | 429 | 502 | 503 | 504)
        )
    }
}

/// An HTTPS client for one identity provider.
#[derive(Clone)]
pub struct Https {
    tls: Arc<rustls::ClientConfig>,
    /// Longest wait for a TCP connection.
    pub connect_timeout: Duration,
    /// Longest wait for a whole request, from connecting to the last byte.
    pub request_timeout: Duration,
}

impl std::fmt::Debug for Https {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Https")
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

enum Method<'a> {
    Get,
    PostForm(&'a str),
}

impl Https {
    /// A client trusting `roots`, TLS 1.3 only.
    ///
    /// # Errors
    ///
    /// A message if the TLS provider refuses the configuration.
    pub fn new(roots: rustls::RootCertStore) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: Arc::new(tls),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
        })
    }

    /// A client trusting the platform's roots (question 13).
    ///
    /// # Errors
    ///
    /// A message if no root certificate could be loaded.
    pub fn platform() -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        let found = rustls_native_certs::load_native_certs();
        let (added, _ignored) = roots.add_parsable_certificates(found.certs);
        if added == 0 {
            return Err("no platform root certificates found".to_owned());
        }
        Self::new(roots)
    }

    /// GETs a JSON document.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub async fn get(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        self.request(url, Method::Get).await
    }

    /// POSTs a form and reads a JSON response. Never retried.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub async fn post_form(&self, url: &str, body: &str) -> Result<Vec<u8>, HttpError> {
        self.request(url, Method::PostForm(body)).await
    }

    /// GETs a JSON document, retrying a retryable failure at most twice
    /// with full-jitter backoff (base 200 ms, cap 2 s).
    ///
    /// # Errors
    ///
    /// The last [`HttpError`].
    pub async fn get_with_retry(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        let mut attempt: u32 = 0;
        loop {
            match self.get(url).await {
                Err(e) if e.retryable() && attempt < 2 => {
                    tokio::time::sleep(backoff(attempt)).await;
                    attempt = attempt.saturating_add(1);
                }
                done => return done,
            }
        }
    }

    async fn request(&self, url: &str, method: Method<'_>) -> Result<Vec<u8>, HttpError> {
        let url = url::Url::parse(url).map_err(|_| HttpError::Url)?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(HttpError::Url);
        }
        let host = url.host_str().ok_or(HttpError::Url)?.to_owned();
        let port = url.port_or_known_default().ok_or(HttpError::Url)?;
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        // RFC 9110 section 7.2: `Host` carries the port unless it is the
        // default (`url.port()` is `None` exactly then).
        let authority = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        tokio::time::timeout(
            self.request_timeout,
            self.exchange(&host, port, &authority, &target, method),
        )
        .await
        .map_err(|_| HttpError::Timeout)?
    }

    async fn exchange(
        &self,
        host: &str,
        port: u16,
        authority: &str,
        target: &str,
        method: Method<'_>,
    ) -> Result<Vec<u8>, HttpError> {
        let tcp = tokio::time::timeout(
            self.connect_timeout,
            tokio::net::TcpStream::connect((host, port)),
        )
        .await
        .map_err(|_| HttpError::Timeout)?
        .map_err(|_| HttpError::Connect)?;
        let name =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_| HttpError::Url)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, tcp)
            .await
            .map_err(|_| HttpError::Tls)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| HttpError::Io)?;
        // The connection task ends with the request: one request per connection.
        let task = tokio::spawn(conn);
        let builder = hyper::Request::builder()
            .uri(target)
            .header(hyper::header::HOST, authority)
            .header(hyper::header::ACCEPT, "application/json")
            .header(hyper::header::USER_AGENT, "corten-gateway");
        let request = match method {
            Method::Get => builder
                .method(hyper::Method::GET)
                .body(Full::new(Bytes::new())),
            Method::PostForm(body) => builder
                .method(hyper::Method::POST)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Full::new(Bytes::copy_from_slice(body.as_bytes()))),
        }
        .map_err(|_| HttpError::Io)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| HttpError::Io)?;
        let status = response.status().as_u16();
        if status != 200 {
            task.abort();
            return Err(HttpError::Status(status));
        }
        let json = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
            });
        if !json {
            task.abort();
            return Err(HttpError::ContentType);
        }
        let body = Limited::new(response.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|e| {
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    HttpError::TooLarge
                } else {
                    HttpError::Io
                }
            })?
            .to_bytes();
        task.abort();
        Ok(body.to_vec())
    }
}

/// The wait before retry `attempt` (0-based): full jitter over
/// `min(2 s, 200 ms * 2^attempt)`.
fn backoff(attempt: u32) -> Duration {
    use aws_lc_rs::rand::SecureRandom as _;
    let ceiling: u64 = 200u64.checked_shl(attempt).unwrap_or(u64::MAX).min(2000);
    let mut bytes = [0u8; 8];
    // A failed draw waits the full ceiling: slower, never a tighter loop.
    let draw = aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_or(ceiling, |()| u64::from_le_bytes(bytes));
    Duration::from_millis(draw.checked_rem(ceiling.max(1)).unwrap_or(ceiling))
}

/// A transition the server logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerEvent {
    /// Calls stop for [`Breaker::OPEN_FOR`] seconds.
    Opened,
    /// A call succeeded after the circuit was open.
    Closed,
}

/// A circuit breaker for the identity provider (rules/04 section 3): after
/// [`Breaker::THRESHOLD`] consecutive failures it opens for
/// [`Breaker::OPEN_FOR`] seconds, then lets one probe through.
#[derive(Debug, Default, Clone, Copy)]
pub struct Breaker {
    failures: u32,
    open_until: Option<u64>,
}

impl Breaker {
    /// Consecutive failures that open the circuit.
    pub const THRESHOLD: u32 = 5;
    /// Seconds the circuit stays open.
    pub const OPEN_FOR: u64 = 30;

    /// Whether a call may be made at `now`.
    #[must_use]
    pub fn allows(&self, now: u64) -> bool {
        self.open_until.is_none_or(|until| now >= until)
    }

    /// Records a call's outcome; returns the transition, if any.
    pub fn record(&mut self, ok: bool, now: u64) -> Option<BreakerEvent> {
        if ok {
            self.failures = 0;
            return self.open_until.take().map(|_| BreakerEvent::Closed);
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= Self::THRESHOLD {
            let was_open = self.open_until.is_some();
            self.open_until = Some(now.saturating_add(Self::OPEN_FOR));
            self.failures = 0;
            return (!was_open).then_some(BreakerEvent::Opened);
        }
        None
    }
}

/// Limits re-fetching the provider's key set on an unknown `kid` to once per
/// [`RefreshLimiter::MIN_INTERVAL`] seconds, so tokens naming made-up keys
/// cannot turn into a stream of requests to the provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefreshLimiter {
    last: Option<u64>,
}

impl RefreshLimiter {
    /// Shortest gap between two refreshes, in seconds.
    pub const MIN_INTERVAL: u64 = 60;

    /// Whether a refresh may run at `now`; if so, it is recorded.
    pub fn take(&mut self, now: u64) -> bool {
        let allowed = self.last.is_none_or(|last| {
            last.checked_add(Self::MIN_INTERVAL)
                .is_none_or(|next| now >= next)
        });
        if allowed {
            self.last = Some(now);
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU32, Ordering};

    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    struct Pki {
        ca: CertificateDer<'static>,
        leaf: CertificateDer<'static>,
        key: Vec<u8>,
    }

    fn pki() -> &'static Pki {
        static PKI: OnceLock<Pki> = OnceLock::new();
        PKI.get_or_init(|| {
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
                leaf: leaf.der().clone(),
                key: leaf_key.serialize_der(),
            }
        })
    }

    fn client(trusting: bool) -> Https {
        let mut roots = rustls::RootCertStore::empty();
        if trusting {
            roots.add(pki().ca.clone()).unwrap();
        }
        let mut c = Https::new(roots).unwrap();
        c.request_timeout = Duration::from_millis(500);
        c
    }

    type Hits = Arc<AtomicU32>;

    async fn route(
        req: hyper::Request<hyper::body::Incoming>,
        hits: Hits,
    ) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
        let n = hits.fetch_add(1, Ordering::SeqCst);
        let json = |status: u16, body: Vec<u8>| {
            hyper::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        };
        Ok(match req.uri().path() {
            "/ok" => json(200, br#"{"a":1}"#.to_vec()),
            "/charset" => hyper::Response::builder()
                .header("content-type", "application/json; charset=utf-8")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap(),
            "/redirect" => hyper::Response::builder()
                .status(302)
                .header("location", "https://evil.example/")
                .body(Full::new(Bytes::new()))
                .unwrap(),
            "/html" => hyper::Response::builder()
                .header("content-type", "text/html")
                .body(Full::new(Bytes::from_static(b"<p>")))
                .unwrap(),
            "/big" => json(200, vec![b' '; MAX_RESPONSE + 1]),
            "/slow" => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                json(200, b"{}".to_vec())
            }
            "/flaky" if n < 2 => json(503, Vec::new()),
            "/flaky" => json(200, b"{}".to_vec()),
            "/down" => json(503, Vec::new()),
            "/host" => {
                let host = req.headers().get("host").map(|v| v.as_bytes().to_vec());
                json(200, host.unwrap_or_default())
            }
            "/form" => {
                let form = req.method() == hyper::Method::POST
                    && req
                        .headers()
                        .get("content-type")
                        .is_some_and(|v| v == "application/x-www-form-urlencoded");
                let body = req.into_body().collect().await.unwrap().to_bytes();
                if form && &body[..] == b"a=1" {
                    json(200, b"{}".to_vec())
                } else {
                    json(400, Vec::new())
                }
            }
            _ => json(404, Vec::new()),
        })
    }

    /// Serves HTTPS on 127.0.0.1 with the given TLS versions; returns the port
    /// and the request counter.
    async fn serve(versions: &'static [&'static rustls::SupportedProtocolVersion]) -> (u16, Hits) {
        let p = pki();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![p.leaf.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.key.clone())),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits: Hits = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&hits);
        let _server = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                let _conn = tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let svc =
                        hyper::service::service_fn(move |req| route(req, Arc::clone(&counter)));
                    let _done = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        (port, hits)
    }

    static TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    static TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

    #[tokio::test]
    async fn a_json_document_is_read_over_tls13() {
        let (port, _) = serve(TLS13).await;
        let c = client(true);
        assert_eq!(
            c.get(&format!("https://127.0.0.1:{port}/ok"))
                .await
                .unwrap(),
            br#"{"a":1}"#
        );
        assert_eq!(
            c.get(&format!("https://127.0.0.1:{port}/charset"))
                .await
                .unwrap(),
            b"{}"
        );
        assert_eq!(
            c.post_form(&format!("https://127.0.0.1:{port}/form"), "a=1")
                .await
                .unwrap(),
            b"{}"
        );
    }

    /// RFC 9110 section 7.2: the port is part of `Host` unless it is the
    /// scheme's default. A provider that builds its issuer from `Host`
    /// (Keycloak does) would otherwise name a different issuer.
    #[tokio::test]
    async fn host_carries_a_non_default_port() {
        let (port, _) = serve(TLS13).await;
        let host = client(true)
            .get(&format!("https://127.0.0.1:{port}/host"))
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(host).unwrap(),
            format!("127.0.0.1:{port}")
        );
    }

    #[tokio::test]
    async fn anything_not_asked_for_is_refused() {
        let (port, _) = serve(TLS13).await;
        let c = client(true);
        let at = |path: &str| format!("https://127.0.0.1:{port}{path}");
        assert_eq!(c.get(&at("/redirect")).await, Err(HttpError::Status(302)));
        assert_eq!(c.get(&at("/missing")).await, Err(HttpError::Status(404)));
        assert_eq!(c.get(&at("/html")).await, Err(HttpError::ContentType));
        assert_eq!(c.get(&at("/big")).await, Err(HttpError::TooLarge));
        assert_eq!(c.get(&at("/slow")).await, Err(HttpError::Timeout));
        for url in [
            format!("http://127.0.0.1:{port}/ok"),
            format!("https://u:p@127.0.0.1:{port}/ok"),
            "not a url".to_owned(),
        ] {
            assert_eq!(c.get(&url).await, Err(HttpError::Url), "{url}");
        }
    }

    #[tokio::test]
    async fn an_untrusted_certificate_or_tls12_is_refused() {
        let (port, _) = serve(TLS13).await;
        assert_eq!(
            client(false)
                .get(&format!("https://127.0.0.1:{port}/ok"))
                .await,
            Err(HttpError::Tls)
        );
        let (old, _) = serve(TLS12).await;
        assert_eq!(
            client(true)
                .get(&format!("https://127.0.0.1:{old}/ok"))
                .await,
            Err(HttpError::Tls)
        );
    }

    #[tokio::test]
    async fn a_get_is_retried_at_most_twice_and_a_post_never() {
        let (port, hits) = serve(TLS13).await;
        let c = client(true);
        assert_eq!(
            c.get_with_retry(&format!("https://127.0.0.1:{port}/flaky"))
                .await
                .unwrap(),
            b"{}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        let (port, hits) = serve(TLS13).await;
        assert_eq!(
            c.get_with_retry(&format!("https://127.0.0.1:{port}/down"))
                .await,
            Err(HttpError::Status(503))
        );
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        let (port, hits) = serve(TLS13).await;
        assert_eq!(
            c.post_form(&format!("https://127.0.0.1:{port}/down"), "a=1")
                .await,
            Err(HttpError::Status(503))
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // Final statuses are not retried.
        let (port, hits) = serve(TLS13).await;
        assert_eq!(
            c.get_with_retry(&format!("https://127.0.0.1:{port}/missing"))
                .await,
            Err(HttpError::Status(404))
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_stays_within_its_ceiling() {
        for attempt in 0..6 {
            let cap = 200u64.checked_shl(attempt).unwrap().min(2000);
            for _ in 0..50 {
                assert!(
                    backoff(attempt) < Duration::from_millis(cap),
                    "attempt {attempt}"
                );
            }
        }
    }

    #[test]
    fn the_breaker_opens_after_the_threshold_and_closes_on_success() {
        let mut b = Breaker::default();
        for i in 1..Breaker::THRESHOLD {
            assert_eq!(b.record(false, 100), None, "failure {i}");
            assert!(b.allows(100));
        }
        assert_eq!(b.record(false, 100), Some(BreakerEvent::Opened));
        assert!(!b.allows(100 + Breaker::OPEN_FOR - 1));
        assert!(b.allows(100 + Breaker::OPEN_FOR));
        // The probe succeeds: closed, logged once.
        assert_eq!(b.record(true, 131), Some(BreakerEvent::Closed));
        assert_eq!(b.record(true, 132), None);
        // A success resets the count.
        for _ in 1..Breaker::THRESHOLD {
            let _ = b.record(false, 200);
        }
        let _ = b.record(true, 200);
        assert_eq!(b.record(false, 200), None);
    }

    #[test]
    fn key_set_refreshes_are_rate_limited() {
        let mut r = RefreshLimiter::default();
        assert!(r.take(1000));
        assert!(!r.take(1000 + RefreshLimiter::MIN_INTERVAL - 1));
        assert!(r.take(1000 + RefreshLimiter::MIN_INTERVAL));
    }
}
