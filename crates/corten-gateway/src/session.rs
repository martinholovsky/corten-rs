//! The gateway's browser sessions (`docs/gates/gateway-proposal.md`; the
//! session rules of sota-code-security rules/17 section 2). Pure logic: the
//! server reads and writes the cookie this module describes.
//!
//! - A session exists only after a successful sign-in ([`Sessions::start`]),
//!   so there is no pre-authentication session to fix (CWE-384).
//! - Its ID is 256 random bits; the store keeps only its SHA-256, so a dump
//!   of the store holds no usable cookie. An incoming ID is checked for shape
//!   before any lookup.
//! - Idle and absolute timeouts come from the server's clock
//!   ([`SessionConfig`]; defaults 15 minutes and 8 hours).
//! - An ended session (logout, revocation, timeout) is remembered for one
//!   absolute timeout after it ends, so a cookie presented after the end,
//!   even after an absolute timeout, is logged as such
//!   (`session.use_after_end`, high severity), not as an unknown ID.
//! - At most [`SessionConfig::per_principal`] sessions per principal: a new
//!   one ends the oldest, logged. At most [`MAX_SESSIONS`] in all.
//! - The cookie is `__Host-`prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`,
//!   `Path=/`.

use std::collections::BTreeMap;

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use corten_std::log::LogWriter;

/// The session cookie's name.
pub const COOKIE: &str = "__Host-corten-session";
/// Most live sessions in all.
pub const MAX_SESSIONS: usize = 100_000;
/// Length of a session ID: 32 bytes in unpadded base64url.
const ID_LEN: usize = 43;

/// Session lifetimes and limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// Seconds without a request after which a session ends.
    pub idle: u64,
    /// Seconds after sign-in after which a session ends whatever its use.
    pub absolute: u64,
    /// Most live sessions per principal.
    pub per_principal: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle: 15 * 60,
            absolute: 8 * 60 * 60,
            per_principal: 10,
        }
    }
}

/// Why a session could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// [`MAX_SESSIONS`] are live.
    Full,
    /// The random generator failed.
    Random,
}

/// What a presented cookie names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// A live session, now touched.
    Live {
        /// The principal.
        principal: String,
        /// The `acr` it signed in with.
        acr: String,
    },
    /// No cookie, or a well-formed one this gateway does not know
    /// (logged `session.unknown`: an ID it never issued, or one forgotten).
    None,
    /// A cookie value that cannot be a session ID; never looked up
    /// (logged `session.malformed`).
    Malformed,
    /// A session that ended (logout, revocation or timeout) and is
    /// presented again.
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Session {
    principal: String,
    acr: String,
    created: u64,
    last_seen: u64,
}

type Digest = [u8; 32];

fn digest(id: &str) -> Digest {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn well_formed(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The session store.
#[derive(Debug, Default)]
pub struct Sessions {
    config: SessionConfig,
    live: BTreeMap<Digest, Session>,
    /// Ended sessions, by digest, kept for one absolute timeout after they end.
    ended: BTreeMap<Digest, u64>,
}

impl Sessions {
    /// An empty store.
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    fn deadline(&self, s: &Session) -> u64 {
        let idle = s.last_seen.saturating_add(self.config.idle);
        let absolute = s.created.saturating_add(self.config.absolute);
        idle.min(absolute)
    }

    fn end_digest(&mut self, d: Digest, reason: &str, now: u64, log: &mut dyn LogWriter) {
        if let Some(s) = self.live.remove(&d) {
            let until = now.saturating_add(self.config.absolute);
            let _was = self.ended.insert(d, until);
            log.write(&corten_std::log_record!(
                "session.end",
                principal = s.principal,
                reason = reason
            ));
        }
    }

    /// Ends timed-out sessions and forgets ended ones past their absolute
    /// expiry.
    fn sweep(&mut self, now: u64, log: &mut dyn LogWriter) {
        let timed_out: Vec<Digest> = self
            .live
            .iter()
            .filter(|(_, s)| now >= self.deadline(s))
            .map(|(d, _)| *d)
            .collect();
        for d in timed_out {
            self.end_digest(d, "timeout", now, log);
        }
        self.ended.retain(|_, until| now < *until);
    }

    /// Starts a session for a principal who has just signed in, and returns
    /// the cookie value. Ends the principal's oldest session at the limit.
    ///
    /// # Errors
    ///
    /// [`SessionError::Full`] or [`SessionError::Random`].
    pub fn start(
        &mut self,
        principal: &str,
        acr: &str,
        now: u64,
        log: &mut dyn LogWriter,
    ) -> Result<String, SessionError> {
        self.sweep(now, log);
        if self.live.len() >= MAX_SESSIONS {
            return Err(SessionError::Full);
        }
        let mut mine: Vec<(u64, Digest)> = self
            .live
            .iter()
            .filter(|(_, s)| s.principal == principal)
            .map(|(d, s)| (s.created, *d))
            .collect();
        mine.sort_unstable();
        while mine.len() >= self.config.per_principal.max(1) {
            let (_, oldest) = mine.remove(0);
            log.write(&corten_std::log_record!(
                "session.limit",
                principal = principal,
                limit = self.config.per_principal
            ));
            self.end_digest(oldest, "limit", now, log);
        }
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| SessionError::Random)?;
        let id = URL_SAFE_NO_PAD.encode(bytes);
        let _new = self.live.insert(
            digest(&id),
            Session {
                principal: principal.to_owned(),
                acr: acr.to_owned(),
                created: now,
                last_seen: now,
            },
        );
        log.write(&corten_std::log_record!(
            "session.start",
            principal = principal,
            acr = acr
        ));
        Ok(id)
    }

    /// Looks up the session a cookie names and records the use.
    pub fn check(&mut self, cookie: Option<&str>, now: u64, log: &mut dyn LogWriter) -> Lookup {
        self.sweep(now, log);
        let Some(id) = cookie else {
            return Lookup::None;
        };
        if !well_formed(id) {
            log.write(&corten_std::log_record!("session.malformed"));
            return Lookup::Malformed;
        }
        let d = digest(id);
        if let Some(s) = self.live.get_mut(&d) {
            s.last_seen = now;
            return Lookup::Live {
                principal: s.principal.clone(),
                acr: s.acr.clone(),
            };
        }
        if self.ended.contains_key(&d) {
            // A cookie presented after its session ended: replay of a
            // stolen cookie looks exactly like this.
            log.write(&corten_std::log_record!(
                "session.use_after_end",
                severity = "high"
            ));
            return Lookup::Ended;
        }
        log.write(&corten_std::log_record!("session.unknown"));
        Lookup::None
    }

    /// Ends the session a cookie names (logout). Returns whether one was live.
    pub fn end(&mut self, cookie: Option<&str>, now: u64, log: &mut dyn LogWriter) -> bool {
        let Some(id) = cookie.filter(|id| well_formed(id)) else {
            return false;
        };
        let d = digest(id);
        let was_live = self.live.contains_key(&d);
        self.end_digest(d, "logout", now, log);
        was_live
    }

    /// Ends every session of a principal (revocation). Returns how many.
    pub fn end_all(&mut self, principal: &str, now: u64, log: &mut dyn LogWriter) -> usize {
        let theirs: Vec<Digest> = self
            .live
            .iter()
            .filter(|(_, s)| s.principal == principal)
            .map(|(d, _)| *d)
            .collect();
        let n = theirs.len();
        for d in theirs {
            self.end_digest(d, "revoked", now, log);
        }
        n
    }

    /// How many sessions are live.
    #[must_use]
    pub fn live(&self) -> usize {
        self.live.len()
    }
}

/// The `Set-Cookie` value that starts a session; it lasts no longer than the
/// session's absolute timeout.
#[must_use]
pub fn set_cookie(id: &str, config: &SessionConfig) -> String {
    format!(
        "{COOKIE}={id}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=Lax",
        config.absolute
    )
}

/// The `Set-Cookie` value that removes the cookie.
#[must_use]
pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax")
}

/// The session ID in a `Cookie` header, if it carries exactly one.
#[must_use]
pub fn from_header(header: &str) -> Option<&str> {
    let mut found = header
        .split(';')
        .filter_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='));
    let first = found.next()?;
    // Two values for the session cookie is ambiguous: use neither.
    if found.next().is_some() {
        None
    } else {
        Some(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corten_std::log::LogRecord;

    #[derive(Default)]
    struct Collect(Vec<String>);
    impl LogWriter for Collect {
        fn write(&mut self, record: &LogRecord) {
            self.0.push(record.render());
        }
    }

    const T0: u64 = 1_800_000_000;

    fn store() -> (Sessions, Collect) {
        (Sessions::new(SessionConfig::default()), Collect::default())
    }

    #[test]
    fn a_session_starts_only_on_sign_in_and_is_found_by_its_cookie() {
        let (mut s, mut log) = store();
        assert_eq!(s.check(None, T0, &mut log), Lookup::None);
        let id = s.start("alice", "phr", T0, &mut log).unwrap();
        assert_eq!(id.len(), 43);
        assert_eq!(
            s.check(Some(&id), T0 + 1, &mut log),
            Lookup::Live {
                principal: "alice".into(),
                acr: "phr".into()
            }
        );
        // The store holds only SHA-256 digests, never the cookie value
        // (computed here independently of the module's own helper).
        let expected = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, id.as_bytes());
        assert_eq!(
            s.live.keys().next().map(<[u8; 32]>::as_slice),
            Some(expected.as_ref())
        );
        assert!(
            log.0
                .iter()
                .any(|l| l.starts_with("session.start principal=\"alice\""))
        );
        // A malformed cookie is never looked up; a well-formed unknown one is
        // no session. Both are logged as suspicious.
        for bad in [
            "",
            "short",
            &format!("{id}x"),
            &format!("!{}", id.get(1..).unwrap()),
        ] {
            assert_eq!(
                s.check(Some(bad), T0 + 2, &mut log),
                Lookup::Malformed,
                "{bad:?}"
            );
        }
        assert_eq!(
            s.check(Some(&"A".repeat(43)), T0 + 2, &mut log),
            Lookup::None
        );
        assert!(log.0.iter().any(|l| l == "session.malformed"));
        assert!(log.0.iter().any(|l| l == "session.unknown"));
    }

    #[test]
    fn idle_and_absolute_timeouts_end_a_session() {
        let c = SessionConfig::default();
        let (mut s, mut log) = store();
        let id = s.start("alice", "phr", T0, &mut log).unwrap();
        assert!(matches!(
            s.check(Some(&id), T0 + c.idle - 1, &mut log),
            Lookup::Live { .. }
        ));
        // Idle from the last use, not from the start.
        assert_eq!(
            s.check(Some(&id), T0 + 2 * c.idle - 1, &mut log),
            Lookup::Ended
        );
        assert!(log.0.iter().any(|l| l.contains("reason=\"timeout\"")));
        // Absolute: ends even while in use.
        let (mut s, mut log) = store();
        let id = s.start("bob", "phr", T0, &mut log).unwrap();
        let mut t = T0;
        while t + c.idle / 2 < T0 + c.absolute {
            t += c.idle / 2;
            assert!(
                matches!(s.check(Some(&id), t, &mut log), Lookup::Live { .. }),
                "at {t}"
            );
        }
        assert_eq!(s.check(Some(&id), T0 + c.absolute, &mut log), Lookup::Ended);
        // Replayed after the absolute timeout, it is still recognised for one more.
        assert_eq!(
            s.check(Some(&id), T0 + 2 * c.absolute - 1, &mut log),
            Lookup::Ended
        );
        assert_eq!(
            s.check(Some(&id), T0 + 2 * c.absolute, &mut log),
            Lookup::None
        );
    }

    #[test]
    fn an_ended_cookie_presented_again_is_logged_until_its_absolute_expiry() {
        let c = SessionConfig::default();
        let (mut s, mut log) = store();
        let id = s.start("alice", "phr", T0, &mut log).unwrap();
        assert!(s.end(Some(&id), T0, &mut log));
        assert!(!s.end(Some(&id), T0, &mut log));
        assert_eq!(s.check(Some(&id), T0 + 5, &mut log), Lookup::Ended);
        assert!(
            log.0
                .iter()
                .any(|l| l == "session.use_after_end severity=\"high\"")
        );
        // One absolute timeout after the end, the record is gone: an unknown ID.
        assert_eq!(s.check(Some(&id), T0 + c.absolute, &mut log), Lookup::None);
    }

    #[test]
    fn revocation_ends_every_session_of_a_principal() {
        let (mut s, mut log) = store();
        let a1 = s.start("alice", "phr", T0, &mut log).unwrap();
        let a2 = s.start("alice", "phrh", T0, &mut log).unwrap();
        let b = s.start("bob", "phr", T0, &mut log).unwrap();
        assert_eq!(s.end_all("alice", T0, &mut log), 2);
        assert_eq!(s.check(Some(&a1), T0 + 1, &mut log), Lookup::Ended);
        assert_eq!(s.check(Some(&a2), T0 + 1, &mut log), Lookup::Ended);
        assert!(matches!(
            s.check(Some(&b), T0 + 1, &mut log),
            Lookup::Live { .. }
        ));
    }

    #[test]
    fn the_per_principal_limit_ends_the_oldest_and_the_store_is_bounded() {
        let config = SessionConfig {
            per_principal: 2,
            ..SessionConfig::default()
        };
        let mut s = Sessions::new(config);
        let mut log = Collect::default();
        let first = s.start("alice", "phr", T0, &mut log).unwrap();
        let second = s.start("alice", "phr", T0 + 1, &mut log).unwrap();
        let third = s.start("alice", "phr", T0 + 2, &mut log).unwrap();
        assert_eq!(s.check(Some(&first), T0 + 3, &mut log), Lookup::Ended);
        assert!(matches!(
            s.check(Some(&second), T0 + 3, &mut log),
            Lookup::Live { .. }
        ));
        assert!(matches!(
            s.check(Some(&third), T0 + 3, &mut log),
            Lookup::Live { .. }
        ));
        assert!(
            log.0
                .iter()
                .any(|l| l.starts_with("session.limit principal=\"alice\" limit=\"2\""))
        );
        // The global cap.
        let (mut full, mut log) = store();
        for i in 0..MAX_SESSIONS {
            let mut d = [0u8; 32];
            d[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
            let _ = full.live.insert(
                d,
                Session {
                    principal: format!("p{i}"),
                    acr: "phr".into(),
                    created: T0,
                    last_seen: T0,
                },
            );
        }
        assert_eq!(
            full.start("new", "phr", T0, &mut log),
            Err(SessionError::Full)
        );
    }

    #[test]
    fn the_cookie_carries_the_hardening_attributes() {
        let c = SessionConfig::default();
        assert_eq!(
            set_cookie("ID", &c),
            "__Host-corten-session=ID; Max-Age=28800; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
        assert!(
            clear_cookie()
                .starts_with("__Host-corten-session=; Max-Age=0; Path=/; Secure; HttpOnly")
        );
        assert_eq!(
            from_header("a=1; __Host-corten-session=XYZ; b=2"),
            Some("XYZ")
        );
        assert_eq!(
            from_header("__Host-corten-session=A; __Host-corten-session=B"),
            None
        );
        assert_eq!(from_header("__Host-corten-session2=X"), None);
        assert_eq!(from_header("corten-session=X"), None);
    }
}
