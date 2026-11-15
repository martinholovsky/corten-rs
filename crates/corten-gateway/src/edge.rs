//! The gateway's browser-facing rules, as pure decisions the server applies
//! (`docs/gates/gateway-proposal.md`; sota-code-security rules/05 and 20,
//! sota-api-design rules/07).
//!
//! - **Routes:** `GET /.corten/login`, `GET /.corten/callback`,
//!   `POST /.corten/logout`; any other `/.corten/` path is 404; everything else
//!   is proxied to the program.
//! - **Host:** the `Host` header must be the configured public host (DNS
//!   rebinding), or 421.
//! - **Logout is cross-site protected:** `Sec-Fetch-Site: same-origin`, or,
//!   when a browser sends no Fetch Metadata, an `Origin` equal to the
//!   configured origin. An absent signal never passes.
//! - **Headers on every response** ([`harden`]): HSTS (one year, no
//!   `includeSubDomains` or `preload`: the operator decides those for the
//!   domain), `nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors
//!   'none'`, COOP and CORP `same-origin`, a deny-all `Permissions-Policy`;
//!   `Server`, `X-Powered-By` and other diagnostic headers removed. Set, never
//!   appended, so each is sent once.
//! - **What the program receives** ([`upstream_headers`]): the client's
//!   `Authorization`, the gateway's session cookie, hop-by-hop headers and
//!   forwarding headers are removed, and `Authorization: Bearer` carries the
//!   Corten token (owner decision 2026-11-14, Q6).
//! - **Rate limits** ([`RateLimiter`]) on sign-in, per client address.

use std::collections::BTreeMap;
use std::net::IpAddr;

use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode};

use crate::session::COOKIE;

/// The gateway's own path prefix.
pub const PREFIX: &str = "/.corten/";
/// Largest request body forwarded to the program, in bytes.
pub const MAX_BODY: usize = 1024 * 1024;

/// What a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Start a sign-in.
    Login,
    /// The provider's callback.
    Callback,
    /// End the session.
    Logout,
    /// Forward to the program.
    Proxy,
}

/// A request refused before it reaches any handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// An unknown gateway path.
    NotFound,
    /// The wrong method for a gateway path.
    MethodNotAllowed,
    /// The `Host` is not this gateway's.
    WrongHost,
    /// A cross-site or unverifiable state-changing request.
    CrossSite,
    /// Over the rate limit; retry after this many seconds.
    TooMany(u64),
    /// The body is over [`MAX_BODY`].
    TooLarge,
}

impl Reject {
    /// The status sent. The body is the status's reason only: it names no
    /// limit, count or rule.
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::WrongHost => StatusCode::MISDIRECTED_REQUEST,
            Self::CrossSite => StatusCode::FORBIDDEN,
            Self::TooMany(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }
}

/// Classifies a request by method and path.
///
/// # Errors
///
/// [`Reject::NotFound`] for an unknown gateway path,
/// [`Reject::MethodNotAllowed`] for the wrong method on a known one.
pub fn route(method: &Method, path: &str) -> Result<Route, Reject> {
    let Some(rest) = path.strip_prefix(PREFIX) else {
        return Ok(Route::Proxy);
    };
    let (want, found) = match rest {
        "login" => (Method::GET, Route::Login),
        "callback" => (Method::GET, Route::Callback),
        "logout" => (Method::POST, Route::Logout),
        _ => return Err(Reject::NotFound),
    };
    if *method == want {
        Ok(found)
    } else {
        Err(Reject::MethodNotAllowed)
    }
}

/// The public origin and host the gateway answers for.
#[derive(Debug, Clone)]
pub struct Public {
    /// `https://HOST[:PORT]`, as browsers send it in `Origin`.
    pub origin: String,
    /// `HOST[:PORT]`, as browsers send it in `Host`.
    pub host: String,
}

/// Refuses a request whose `Host` is not the gateway's.
///
/// # Errors
///
/// [`Reject::WrongHost`].
pub fn check_host(headers: &HeaderMap, public: &Public) -> Result<(), Reject> {
    let mut all = headers.get_all(header::HOST).iter();
    match (all.next(), all.next()) {
        (Some(h), None) if h.as_bytes().eq_ignore_ascii_case(public.host.as_bytes()) => Ok(()),
        _ => Err(Reject::WrongHost),
    }
}

/// Refuses a state-changing request that is not provably same-origin.
///
/// # Errors
///
/// [`Reject::CrossSite`].
pub fn check_same_origin(headers: &HeaderMap, public: &Public) -> Result<(), Reject> {
    if let Some(site) = headers.get("sec-fetch-site") {
        return if site.as_bytes() == b"same-origin" {
            Ok(())
        } else {
            Err(Reject::CrossSite)
        };
    }
    // No Fetch Metadata (an older browser): the Origin must be ours, exactly.
    match headers.get(header::ORIGIN) {
        Some(o) if o.as_bytes() == public.origin.as_bytes() => Ok(()),
        _ => Err(Reject::CrossSite),
    }
}

const REMOVED_FROM_RESPONSES: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-runtime",
    "server-timing",
    "x-xss-protection",
];

/// Sets the security headers on a response (each once) and removes
/// diagnostic ones.
pub fn harden(headers: &mut HeaderMap) {
    for name in REMOVED_FROM_RESPONSES {
        let _gone = headers.remove(*name);
    }
    for (name, value) in [
        ("strict-transport-security", "max-age=31536000"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "frame-ancestors 'none'"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
    ] {
        let _replaced = headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
}

/// Marks a gateway response as never to be stored.
pub fn no_store(headers: &mut HeaderMap) {
    let _replaced = headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

const FORWARDING: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
];

/// The headers the program receives: the client's own minus credentials,
/// the gateway cookie, hop-by-hop and forwarding headers, plus the token.
///
/// # Errors
///
/// None in practice; a token that is not a valid header value is refused.
pub fn upstream_headers(incoming: &HeaderMap, token: &str) -> Result<HeaderMap, Reject> {
    let mut out = HeaderMap::new();
    // Headers a `Connection` header names are hop-by-hop too.
    let named: Vec<String> = incoming
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|n| n.trim().to_ascii_lowercase())
        .collect();
    for (name, value) in incoming {
        let n = name.as_str();
        if n == "cookie"
            || HOP_BY_HOP.contains(&n)
            || FORWARDING.contains(&n)
            || named.iter().any(|x| x == n)
        {
            continue;
        }
        let _ = out.append(name.clone(), value.clone());
    }
    // Other cookies pass; the gateway's session cookie never does.
    let kept: Vec<&str> = incoming
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|c| !c.is_empty() && !c.starts_with(&format!("{COOKIE}=")))
        .collect();
    if !kept.is_empty() {
        let joined = HeaderValue::from_str(&kept.join("; ")).map_err(|_| Reject::TooLarge)?;
        let _ = out.insert(header::COOKIE, joined);
    }
    let bearer = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| Reject::TooLarge)?;
    // `insert` replaces every `Authorization` the client sent: this is the
    // control that keeps a forged credential from reaching the program, so it
    // must never become `append`.
    let _ = out.insert(header::AUTHORIZATION, bearer);
    Ok(out)
}

/// A token bucket per client address for the sign-in endpoints: `burst`
/// requests at once, refilled at one per `refill` seconds, at most
/// [`RateLimiter::MAX_CLIENTS`] addresses tracked (the oldest forgotten).
#[derive(Debug)]
pub struct RateLimiter {
    burst: u32,
    refill: u64,
    clients: BTreeMap<IpAddr, (u32, u64)>,
}

impl RateLimiter {
    /// Most addresses tracked at once.
    pub const MAX_CLIENTS: usize = 100_000;

    /// A limiter allowing `burst` requests at once, one more per `refill`
    /// seconds.
    #[must_use]
    pub fn new(burst: u32, refill: u64) -> Self {
        Self {
            burst: burst.max(1),
            refill: refill.max(1),
            clients: BTreeMap::new(),
        }
    }

    /// Takes one token for `client` at `now`.
    ///
    /// # Errors
    ///
    /// [`Reject::TooMany`] with the seconds until the next token.
    pub fn take(&mut self, client: IpAddr, now: u64) -> Result<(), Reject> {
        if !self.clients.contains_key(&client) && self.clients.len() >= Self::MAX_CLIENTS {
            let oldest = self
                .clients
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest {
                let _gone = self.clients.remove(&ip);
            }
        }
        let (tokens, at) = self.clients.entry(client).or_insert((self.burst, now));
        let elapsed = now.saturating_sub(*at);
        let earned = elapsed.checked_div(self.refill).unwrap_or(0);
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        if earned > 0 {
            *tokens = tokens.saturating_add(earned).min(self.burst);
            *at = at.saturating_add(u64::from(earned).saturating_mul(self.refill));
        }
        if *tokens == 0 {
            let next = at.saturating_add(self.refill).saturating_sub(now).max(1);
            return Err(Reject::TooMany(next));
        }
        *tokens = tokens.saturating_sub(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> Public {
        Public {
            origin: "https://gw.example".into(),
            host: "gw.example".into(),
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            let _ = h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn gateway_paths_need_their_method_and_everything_else_is_proxied() {
        assert_eq!(route(&Method::GET, "/.corten/login"), Ok(Route::Login));
        assert_eq!(
            route(&Method::GET, "/.corten/callback"),
            Ok(Route::Callback)
        );
        assert_eq!(route(&Method::POST, "/.corten/logout"), Ok(Route::Logout));
        assert_eq!(
            route(&Method::GET, "/.corten/logout"),
            Err(Reject::MethodNotAllowed)
        );
        assert_eq!(
            route(&Method::POST, "/.corten/login"),
            Err(Reject::MethodNotAllowed)
        );
        assert_eq!(route(&Method::GET, "/.corten/admin"), Err(Reject::NotFound));
        assert_eq!(route(&Method::GET, "/.corten/"), Err(Reject::NotFound));
        for (m, p) in [
            (Method::GET, "/"),
            (Method::POST, "/api/x"),
            (Method::GET, "/.cortenx/login"),
            (Method::DELETE, "/.corten"),
        ] {
            assert_eq!(route(&m, p), Ok(Route::Proxy), "{m} {p}");
        }
    }

    #[test]
    fn only_this_gateways_host_is_served() {
        assert_eq!(
            check_host(&headers(&[("host", "gw.example")]), &public()),
            Ok(())
        );
        assert_eq!(
            check_host(&headers(&[("host", "GW.EXAMPLE")]), &public()),
            Ok(())
        );
        for bad in [
            vec![("host", "evil.example")],
            vec![],
            vec![("host", "gw.example"), ("host", "evil.example")],
            vec![("host", "gw.example.evil")],
        ] {
            assert_eq!(
                check_host(&headers(&bad), &public()),
                Err(Reject::WrongHost),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_state_change_must_prove_it_is_same_origin() {
        let ok = |h: &[(&str, &str)]| check_same_origin(&headers(h), &public());
        assert_eq!(ok(&[("sec-fetch-site", "same-origin")]), Ok(()));
        assert_eq!(ok(&[("origin", "https://gw.example")]), Ok(()));
        for bad in [
            vec![("sec-fetch-site", "same-site")],
            vec![("sec-fetch-site", "cross-site")],
            vec![("sec-fetch-site", "none")],
            // Fetch Metadata decides when present, even with a matching Origin.
            vec![
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://gw.example"),
            ],
            vec![("origin", "https://gw.example/")],
            vec![("origin", "https://gw.example.evil")],
            vec![("origin", "http://gw.example")],
            vec![("origin", "null")],
            vec![],
        ] {
            assert_eq!(ok(&bad), Err(Reject::CrossSite), "{bad:?}");
        }
    }

    #[test]
    fn every_response_gets_the_baseline_once_and_loses_diagnostics() {
        let mut h = headers(&[
            ("server", "nginx/1.2"),
            ("x-powered-by", "PHP"),
            ("x-frame-options", "ALLOWALL"),
            ("x-frame-options", "SAMEORIGIN"),
            ("content-type", "text/plain"),
        ]);
        harden(&mut h);
        assert!(h.get("server").is_none() && h.get("x-powered-by").is_none());
        assert_eq!(h.get_all("x-frame-options").iter().count(), 1);
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["strict-transport-security"], "max-age=31536000");
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["content-security-policy"], "frame-ancestors 'none'");
        assert_eq!(h["cross-origin-opener-policy"], "same-origin");
        assert_eq!(h["cross-origin-resource-policy"], "same-origin");
        assert!(
            h["permissions-policy"]
                .to_str()
                .unwrap()
                .contains("camera=()")
        );
        assert_eq!(h["content-type"], "text/plain");
        no_store(&mut h);
        assert_eq!(h["cache-control"], "no-store");
    }

    #[test]
    fn the_program_gets_the_token_and_none_of_the_clients_credentials() {
        let incoming = headers(&[
            ("authorization", "Bearer forged"),
            ("cookie", "theme=dark; __Host-corten-session=SECRET"),
            ("cookie", "lang=cs"),
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("upgrade", "websocket"),
            ("x-forwarded-for", "10.0.0.1"),
            ("forwarded", "for=10.0.0.1"),
            ("accept", "text/html"),
        ]);
        let out = upstream_headers(&incoming, "corten-token-1.k.api.alice.1.ab").unwrap();
        assert_eq!(out.get_all("authorization").iter().count(), 1);
        assert_eq!(
            out["authorization"],
            "Bearer corten-token-1.k.api.alice.1.ab"
        );
        assert_eq!(out["cookie"], "theme=dark; lang=cs");
        for gone in [
            "connection",
            "x-secret-hop",
            "keep-alive",
            "upgrade",
            "x-forwarded-for",
            "forwarded",
        ] {
            assert!(out.get(gone).is_none(), "{gone}");
        }
        assert_eq!(out["accept"], "text/html");
        // Only the session cookie: no cookie header at all.
        let only =
            upstream_headers(&headers(&[("cookie", "__Host-corten-session=S")]), "t").unwrap();
        assert!(only.get("cookie").is_none());
    }

    #[test]
    fn sign_in_is_rate_limited_per_address() {
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let mut r = RateLimiter::new(3, 10);
        for _ in 0..3 {
            assert_eq!(r.take(a, 100), Ok(()));
        }
        assert_eq!(r.take(a, 100), Err(Reject::TooMany(10)));
        assert_eq!(r.take(a, 105), Err(Reject::TooMany(5)));
        assert_eq!(r.take(b, 105), Ok(()), "another address has its own bucket");
        assert_eq!(r.take(a, 110), Ok(()));
        assert_eq!(r.take(a, 110), Err(Reject::TooMany(10)));
        // A long pause refills to the burst, never beyond.
        for _ in 0..3 {
            assert_eq!(r.take(a, 10_000), Ok(()));
        }
        assert!(r.take(a, 10_000).is_err());
        assert_eq!(Reject::TooMany(1).status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn the_limiter_forgets_the_oldest_address_at_its_cap() {
        let mut r = RateLimiter::new(1, 60);
        for i in 0..u32::try_from(RateLimiter::MAX_CLIENTS).unwrap() {
            let _taken = r.take(IpAddr::from(i.to_be_bytes()), u64::from(i) + 1);
        }
        assert_eq!(r.clients.len(), RateLimiter::MAX_CLIENTS);
        let _taken = r.take("198.51.100.7".parse().unwrap(), 1_000_000);
        assert_eq!(r.clients.len(), RateLimiter::MAX_CLIENTS);
        assert!(!r.clients.contains_key(&IpAddr::from(0u32.to_be_bytes())));
    }
}
