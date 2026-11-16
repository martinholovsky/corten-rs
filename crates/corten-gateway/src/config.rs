//! The gateway's configuration file: one `key value` per line, `#` starts a
//! comment line, blank lines skipped. Every key is known and appears at most
//! once; an unknown or repeated key is an error, never ignored (a misspelt
//! setting must not fall back to a default unnoticed).
//!
//! ```text
//! origin https://gw.example            # required: the public HTTPS origin
//! listen 0.0.0.0:443                   # required
//! tls-cert /etc/corten/gw.crt          # required: PEM chain
//! tls-key /etc/corten/gw.key           # required: PEM key
//! issuer https://idp.example           # required
//! client-id corten-gateway             # required
//! client-key /etc/corten/client.key    # required: from `corten-gateway keygen-client`
//! client-key-id corten-gateway-1       # the `kid` registered with that key (its default)
//! mint-key /etc/corten/mint.key        # required: from `corten-manifest keygen`
//! authn-name api                       # required: the program's `authn NAME token` grant
//! upstream /run/app/http.sock          # required: the program's Unix socket
//! acr phr                              # phr (default) or phrh
//! algorithms ES256 RS256 EdDSA         # default: all three
//! token-lifetime 300                   # seconds, 1 to 900
//! upstream-timeout 30                  # seconds
//! idle-timeout 900                     # seconds
//! absolute-timeout 28800               # seconds
//! sessions-per-principal 10
//! login-burst 10
//! login-refill 6                       # seconds per further sign-in request
//! ```

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::edge::Public;
use crate::idtoken::{AcrPolicy, Alg};
use crate::session::SessionConfig;

/// The `kid` `keygen-client` and the configuration use when none is given.
pub const DEFAULT_KID: &str = "corten-gateway-1";

/// Largest configuration file read, in bytes.
pub const MAX_CONFIG: usize = 64 * 1024;

const REQUIRED: &[&str] = &[
    "origin",
    "listen",
    "tls-cert",
    "tls-key",
    "issuer",
    "client-id",
    "client-key",
    "mint-key",
    "authn-name",
    "upstream",
];
const OPTIONAL: &[&str] = &[
    "client-key-id",
    "acr",
    "algorithms",
    "token-lifetime",
    "upstream-timeout",
    "idle-timeout",
    "absolute-timeout",
    "sessions-per-principal",
    "login-burst",
    "login-refill",
];

/// A parsed configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// The public origin and host.
    pub public: Public,
    /// Where to listen.
    pub listen: SocketAddr,
    /// The TLS certificate chain (PEM).
    pub tls_cert: PathBuf,
    /// The TLS key (PEM).
    pub tls_key: PathBuf,
    /// The provider's issuer identifier.
    pub issuer: String,
    /// The client ID at the provider.
    pub client_id: String,
    /// The `private_key_jwt` key (PKCS#8, P-256).
    pub client_key: PathBuf,
    /// The `kid` the provider knows that key by.
    pub client_key_id: String,
    /// The token-minting key (`corten-manifest keygen`).
    pub mint_key: PathBuf,
    /// The program's `authn NAME token` grant name.
    pub authn_name: String,
    /// The program's Unix socket.
    pub upstream: PathBuf,
    /// Which authentication contexts count.
    pub acr: AcrPolicy,
    /// Allowed ID-token algorithms.
    pub algorithms: Vec<Alg>,
    /// Minted token lifetime, seconds.
    pub token_lifetime: u64,
    /// Longest wait for the program.
    pub upstream_timeout: Duration,
    /// Session lifetimes and limits.
    pub sessions: SessionConfig,
    /// Sign-in requests at once per address.
    pub login_burst: u32,
    /// Seconds per further sign-in request.
    pub login_refill: u64,
}

fn number<T: std::str::FromStr>(key: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{key}: {value:?} is not a number"))
}

fn positive(key: &str, value: &str) -> Result<u64, String> {
    let n: u64 = number(key, value)?;
    if n == 0 {
        return Err(format!("{key}: must be at least 1"));
    }
    Ok(n)
}

/// The `key value` pairs, refusing unknown and repeated keys and checking
/// that every required key is present.
fn entries(text: &str) -> Result<BTreeMap<&str, &str>, String> {
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for (number, line) in (1usize..).zip(text.lines()) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(char::is_whitespace)
            .map(|(k, v)| (k, v.trim()))
            .ok_or_else(|| format!("line {number}: expected `key value`"))?;
        if !REQUIRED.contains(&key) && !OPTIONAL.contains(&key) {
            return Err(format!("line {number}: unknown key {key:?}"));
        }
        if values.insert(key, value).is_some() {
            return Err(format!("line {number}: {key} given twice"));
        }
    }
    for key in REQUIRED {
        if !values.contains_key(key) {
            return Err(format!("missing required key {key}"));
        }
    }
    Ok(values)
}

/// The public origin and host from the `origin` value.
fn public_of(value: &str) -> Result<Public, String> {
    let origin = url::Url::parse(value).map_err(|_| "origin: not a URL".to_owned())?;
    if origin.scheme() != "https"
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
    {
        return Err("origin: must be https://HOST[:PORT] with no path".to_owned());
    }
    let host = origin
        .host_str()
        .ok_or_else(|| "origin: no host".to_owned())?;
    let host = match origin.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    };
    let public = Public {
        origin: origin.as_str().trim_end_matches('/').to_owned(),
        host,
    };
    Ok(public)
}

/// Parses configuration text.
///
/// # Errors
///
/// A message naming the line or key at fault.
pub fn parse(text: &str) -> Result<Config, String> {
    if text.len() > MAX_CONFIG {
        return Err(format!("larger than {MAX_CONFIG} bytes"));
    }
    let values = entries(text)?;
    let get = |k: &str| values.get(k).copied();
    let need = |k: &str| get(k).ok_or_else(|| format!("missing required key {k}"));
    let public = public_of(need("origin")?)?;
    let issuer = need("issuer")?;
    if !issuer.starts_with("https://") {
        return Err("issuer: must be an https URL".to_owned());
    }
    let client_key_id = get("client-key-id").unwrap_or(DEFAULT_KID);
    if !corten_std::authz::token_field(client_key_id) {
        return Err("client-key-id: use [A-Za-z0-9_-], 1 to 64 characters".to_owned());
    }
    let authn_name = need("authn-name")?;
    if !corten_std::authz::token_field(authn_name) {
        return Err("authn-name: not a valid grant name".to_owned());
    }
    let acr = match get("acr").unwrap_or("phr") {
        "phr" => AcrPolicy::PhishingResistant,
        "phrh" => AcrPolicy::HardwareProtected,
        other => return Err(format!("acr: {other:?} is neither phr nor phrh")),
    };
    let algorithms = match get("algorithms") {
        None => vec![Alg::Rs256, Alg::Es256, Alg::Ed25519],
        Some(list) => list
            .split_whitespace()
            .map(|a| match a {
                "RS256" => Ok(Alg::Rs256),
                "ES256" => Ok(Alg::Es256),
                "EdDSA" | "Ed25519" => Ok(Alg::Ed25519),
                other => Err(format!(
                    "algorithms: {other:?} is not RS256, ES256 or EdDSA"
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    if algorithms.is_empty() {
        return Err("algorithms: none given".to_owned());
    }
    let token_lifetime = positive("token-lifetime", get("token-lifetime").unwrap_or("300"))?;
    if token_lifetime > corten_std::authz::MAX_TOKEN_LIFETIME {
        return Err(format!(
            "token-lifetime: at most {}",
            corten_std::authz::MAX_TOKEN_LIFETIME
        ));
    }
    let defaults = SessionConfig::default();
    let idle = get("idle-timeout").map_or(Ok(defaults.idle), |v| positive("idle-timeout", v))?;
    let absolute = get("absolute-timeout")
        .map_or(Ok(defaults.absolute), |v| positive("absolute-timeout", v))?;
    if idle > absolute {
        return Err("idle-timeout: longer than absolute-timeout".to_owned());
    }
    let per_principal = get("sessions-per-principal").map_or(Ok(defaults.per_principal), |v| {
        positive("sessions-per-principal", v).and_then(|n| {
            usize::try_from(n).map_err(|_| "sessions-per-principal: too large".to_owned())
        })
    })?;
    let login_burst = get("login-burst").map_or(Ok(10), |v| {
        positive("login-burst", v)
            .and_then(|n| u32::try_from(n).map_err(|_| "login-burst: too large".to_owned()))
    })?;
    Ok(Config {
        public,
        listen: number("listen", need("listen")?)?,
        tls_cert: PathBuf::from(need("tls-cert")?),
        tls_key: PathBuf::from(need("tls-key")?),
        issuer: issuer.to_owned(),
        client_id: need("client-id")?.to_owned(),
        client_key: PathBuf::from(need("client-key")?),
        client_key_id: client_key_id.to_owned(),
        mint_key: PathBuf::from(need("mint-key")?),
        authn_name: authn_name.to_owned(),
        upstream: PathBuf::from(need("upstream")?),
        acr,
        algorithms,
        token_lifetime,
        upstream_timeout: Duration::from_secs(positive(
            "upstream-timeout",
            get("upstream-timeout").unwrap_or("30"),
        )?),
        sessions: SessionConfig {
            idle,
            absolute,
            per_principal,
        },
        login_burst,
        login_refill: positive("login-refill", get("login-refill").unwrap_or("6"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "\
# the gateway
origin https://gw.example
listen 0.0.0.0:443
tls-cert /etc/c/gw.crt
tls-key /etc/c/gw.key
issuer https://idp.example
client-id corten-gateway
client-key /etc/c/client.key
mint-key /etc/c/mint.key
authn-name api
upstream /run/app/http.sock
";

    #[test]
    fn a_minimal_file_gets_the_defaults() {
        let c = parse(FULL).unwrap();
        assert_eq!(
            c.public,
            Public {
                origin: "https://gw.example".into(),
                host: "gw.example".into()
            }
        );
        assert_eq!(c.acr, AcrPolicy::PhishingResistant);
        assert_eq!(c.client_key_id, "corten-gateway-1");
        assert_eq!(c.algorithms, [Alg::Rs256, Alg::Es256, Alg::Ed25519]);
        assert_eq!(
            (c.token_lifetime, c.login_burst, c.login_refill),
            (300, 10, 6)
        );
        assert_eq!(c.sessions, SessionConfig::default());
        assert_eq!(c.upstream_timeout, Duration::from_secs(30));
        let with_port =
            parse(&FULL.replace("https://gw.example", "https://gw.example:8443")).unwrap();
        assert_eq!(with_port.public.host, "gw.example:8443");
        let set = parse(&format!("{FULL}acr phrh\nalgorithms ES256\ntoken-lifetime 900\nidle-timeout 60\nabsolute-timeout 3600\nsessions-per-principal 3\nlogin-burst 2\nlogin-refill 30\nupstream-timeout 5\n")).unwrap();
        assert_eq!(
            (set.acr, set.algorithms.clone(), set.token_lifetime),
            (AcrPolicy::HardwareProtected, vec![Alg::Es256], 900)
        );
        assert_eq!(
            set.sessions,
            SessionConfig {
                idle: 60,
                absolute: 3600,
                per_principal: 3
            }
        );
    }

    #[test]
    fn unknown_repeated_and_missing_keys_are_errors_not_defaults() {
        for (text, want) in [
            (format!("{FULL}acrr phr\n"), "unknown key \"acrr\""),
            (format!("{FULL}acr phr\nacr phrh\n"), "acr given twice"),
            (
                FULL.replace("upstream /run/app/http.sock\n", ""),
                "missing required key upstream",
            ),
            (format!("{FULL}justakey\n"), "expected `key value`"),
        ] {
            let e = parse(&text).unwrap_err();
            assert!(e.contains(want), "{e}");
        }
    }

    #[test]
    fn each_malformed_value_is_refused() {
        for (key, line, want) in [
            ("origin", "origin http://gw.example", "origin"),
            ("origin", "origin https://gw.example/app", "origin"),
            ("origin", "origin https://u:p@gw.example", "origin"),
            ("issuer", "issuer http://idp.example", "issuer"),
            ("authn-name", "authn-name a.b", "authn-name"),
            ("listen", "listen nowhere", "listen"),
        ] {
            let text = FULL
                .lines()
                .map(|l| if l.starts_with(key) { line } else { l })
                .collect::<Vec<_>>()
                .join("\n");
            let e = parse(&text).unwrap_err();
            assert!(e.contains(want), "{line}: {e}");
        }
        for (extra, want) in [
            ("acr pwd", "acr"),
            ("client-key-id a.b", "client-key-id"),
            ("algorithms HS256", "algorithms"),
            ("token-lifetime 901", "token-lifetime"),
            ("token-lifetime 0", "token-lifetime"),
            ("idle-timeout 9000\nabsolute-timeout 60", "idle-timeout"),
            ("login-burst many", "login-burst"),
        ] {
            let e = parse(&format!("{FULL}{extra}\n")).unwrap_err();
            assert!(e.contains(want), "{extra}: {e}");
        }
        assert!(
            parse(&"#".repeat(MAX_CONFIG + 1))
                .unwrap_err()
                .contains("larger")
        );
    }
}
