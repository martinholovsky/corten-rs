//! The listener capability (Phase 6, batch 6; spec section 8, question 25;
//! `docs/gates/listener-proposal.md`).
//!
//! A manifest line `listen NAME unix PATH authn AUTHN` grants one Unix
//! domain socket at `PATH`. [`crate::manifest::Capabilities::load`] binds it;
//! the program takes it with
//! [`take_listener`](crate::manifest::Capabilities::take_listener) and calls
//! [`Listener::serve`] with a plain function. Every request must carry
//! `Authorization: Bearer <token>` that the `AUTHN` grant's keys accept; a
//! request without one is answered 401 and runs no program code. This is the
//! program side of the exchange gateway's forwarding contract
//! (`docs/gates/gateway-proposal.md`, Q6).

use std::fmt;
use std::path::PathBuf;

use crate::http::{HeaderName, HeaderValue};

/// Largest request head read, in bytes.
pub const MAX_HEAD: usize = 64 * 1024;
/// Largest request body accepted, in bytes; larger is answered 413.
pub const MAX_BODY: usize = 1024 * 1024;
/// Seconds allowed to read a request head.
pub const HEAD_TIMEOUT_SECS: u64 = 10;
/// Handlers running at once; beyond it a request is answered 503.
pub const MAX_HANDLERS: usize = 64;
/// Handlers running at once for one principal; beyond it 429. Keyed to the
/// authenticated caller, so one principal cannot take every slot.
pub const MAX_PER_PRINCIPAL: usize = 8;
/// Open connections; a connection beyond it is closed at once.
pub const MAX_CONNECTIONS: usize = 256;
/// Seconds allowed to read a request body; slower is answered 408.
pub const BODY_TIMEOUT_SECS: u64 = 30;
/// Seconds a handler has to answer before the caller gets 504. Shorter than
/// the gateway's default upstream timeout (30 s), so the inner budget ends
/// first. The handler's thread runs on (it cannot be cancelled) and keeps
/// its slot until it returns, so the caps above still bound the threads.
pub const HANDLER_TIMEOUT_SECS: u64 = 25;

/// Why a listener could not be bound or served, or a response built.
#[derive(Debug)]
pub enum ListenError {
    /// The socket's directory is missing, not a directory, writable by
    /// group or others, or owned by another user.
    Directory(String),
    /// Something other than this user's socket is already at the path.
    Occupied(PathBuf),
    /// A system call failed.
    Io(String),
    /// A status code outside 100 to 599.
    Status(u16),
    /// A response header that framing owns (`content-length`,
    /// `transfer-encoding`, `connection` and the other hop-by-hop fields).
    Framing(String),
    /// Listening is not supported on this platform.
    Unsupported,
}

impl fmt::Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(why) => write!(f, "socket directory refused: {why}"),
            Self::Occupied(path) => write!(
                f,
                "{} exists and is not this user's socket; refusing to replace it",
                path.display()
            ),
            Self::Io(why) => f.write_str(why),
            Self::Status(code) => write!(f, "status {code} is not between 100 and 599"),
            Self::Framing(name) => {
                write!(f, "header {name:?} is set by the listener, not the program")
            }
            Self::Unsupported => f.write_str("listening sockets need a Unix platform"),
        }
    }
}

impl std::error::Error for ListenError {}

/// Response headers the listener owns: framing and hop-by-hop fields.
const FRAMING: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// One authenticated request, as the handler sees it. The `Authorization`
/// header is not included: the token was checked and is not the program's
/// to reuse.
#[derive(Debug)]
pub struct Request {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    /// The method, such as `GET`.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The path, percent-encoded as sent.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query string without its `?`, if any.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The first value of header `name` (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body, at most [`MAX_BODY`] bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// What a handler returns.
#[derive(Debug)]
pub struct Response {
    status: u16,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Vec<u8>,
}

impl Response {
    /// A 200 response.
    #[must_use]
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// A response with `status`.
    ///
    /// # Errors
    ///
    /// [`ListenError::Status`] outside 100 to 599.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Result<Self, ListenError> {
        if !(100..=599).contains(&status) {
            return Err(ListenError::Status(status));
        }
        Ok(Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        })
    }

    /// Adds a header. Names and values are already validated
    /// ([`crate::http`]: no CR, LF or NUL).
    ///
    /// # Errors
    ///
    /// [`ListenError::Framing`] for a framing or hop-by-hop field, which the
    /// listener sets itself.
    pub fn with_header(
        mut self,
        name: HeaderName,
        value: HeaderValue,
    ) -> Result<Self, ListenError> {
        if FRAMING
            .iter()
            .any(|f| f.eq_ignore_ascii_case(name.as_str()))
        {
            return Err(ListenError::Framing(name.as_str().to_owned()));
        }
        self.headers.push((name, value));
        Ok(self)
    }

    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }
}

#[cfg(unix)]
pub use imp::Listener;

#[cfg(unix)]
pub(crate) use imp::bind;

#[cfg(unix)]
mod imp {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::os::fd::OwnedFd;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use http_body_util::BodyExt as _;
    use hyper::body::{Bytes, Incoming};
    use hyper_util::rt::{TokioIo, TokioTimer};
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use tokio::net::UnixSocket;
    use tokio::sync::{Mutex, Semaphore};

    use super::{
        BODY_TIMEOUT_SECS, HANDLER_TIMEOUT_SECS, HEAD_TIMEOUT_SECS, ListenError, MAX_BODY,
        MAX_CONNECTIONS, MAX_HANDLERS, MAX_HEAD, MAX_PER_PRINCIPAL, Request, Response,
    };
    use crate::authz::{Authenticated, Token, TokenAuthenticator};
    use crate::log::LogWriter;

    type Body = http_body_util::Full<Bytes>;

    /// Pending connections the kernel queues before `accept`.
    const BACKLOG: u32 = 128;

    /// A bound socket and the authenticator its grant names. It is a
    /// `tokio::net::UnixSocket` (close-on-exec and non-blocking from
    /// creation): neither a `std::os::unix::net` type, which the profile bans
    /// in the prelude too, nor a raw descriptor, whose registration with
    /// tokio is either `unsafe` or deprecated, and the profile forbids both.
    /// It listens from the moment it is bound, so a connection that arrives
    /// before [`Listener::serve`] waits in the backlog.
    #[derive(Debug)]
    pub struct Listener {
        name: String,
        socket: UnixSocket,
        auth: TokenAuthenticator,
    }

    fn io(what: &Path, e: impl std::fmt::Display) -> ListenError {
        ListenError::Io(format!("{}: {e}", what.display()))
    }

    /// How the socket's directory is opened. On Linux `O_PATH`: Landlock
    /// does not check it, so the `listen` grant needs only `MakeSock` and
    /// `RemoveFile` (no `ReadDir`), and every later step (`fstat`, `statat`,
    /// `chmodat`, `renameat`, `unlinkat`) works on such a descriptor. Found
    /// by the podman deployment: a read-only open was refused under the grant.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const DIR_FLAGS: OFlags = OFlags::PATH
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW);

    /// Binds the grant's socket. The directory is opened once, without
    /// following a symbolic link, and checked on that descriptor: a
    /// directory, not writable by group or others. Every later step is
    /// relative to it, so a path swapped after the check cannot redirect
    /// them. The socket is created under a random name, checked to be in that
    /// directory and to belong to the directory's owner, set to 0660, then
    /// renamed over `path`; an existing `path` is replaced only when it is a
    /// socket of the same owner (a stale one from the last run).
    pub(crate) fn bind(
        name: String,
        path: &Path,
        auth: TokenAuthenticator,
    ) -> Result<Listener, ListenError> {
        let shown = path.display();
        let (Some(dir), Some(file)) = (path.parent(), path.file_name()) else {
            return Err(ListenError::Directory(format!(
                "{shown} has no directory or file name"
            )));
        };
        let dir_fd = rustix::fs::open(dir, DIR_FLAGS, Mode::empty())
            .map_err(|e| ListenError::Directory(format!("{}: {e}", dir.display())))?;
        let dir_stat = rustix::fs::fstat(&dir_fd).map_err(|e| io(dir, e))?;
        if Mode::from_raw_mode(dir_stat.st_mode).intersects(Mode::WGRP | Mode::WOTH) {
            return Err(ListenError::Directory(format!(
                "{} is writable by group or others",
                dir.display()
            )));
        }
        let suffix = crate::random::u64().map_err(|e| ListenError::Io(e.to_string()))?;
        // Short on purpose: a socket path is limited to about 104 bytes
        // (108 on Linux), and the temporary name must fit as well as `path`.
        let temp = format!(".{suffix:016x}");
        let socket = UnixSocket::new_stream().map_err(|e| io(path, e))?;
        socket.bind(dir.join(&temp)).map_err(|e| {
            ListenError::Io(format!(
                "{shown}: {e} (the directory plus 17 bytes for a temporary name must fit \
                 the platform's socket path limit, about 104 bytes)"
            ))
        })?;
        // Listening now, not in `serve`: a connection that arrives before the
        // program serves waits in the backlog instead of being refused (the
        // gateway would answer 502). tokio's own `listen` in `serve` only
        // sets the backlog again, which Linux and the BSDs allow.
        let placed = place(&dir_fd, &temp, file, dir_stat.st_uid).and_then(|()| {
            rustix::net::listen(&socket, i32::try_from(BACKLOG).unwrap_or(i32::MAX))
                .map_err(|e| io(path, e))
        });
        if let Err(e) = placed {
            // Best effort: the error being returned is the one that matters.
            let _removed = rustix::fs::unlinkat(&dir_fd, temp.as_str(), AtFlags::empty());
            return Err(match e {
                ListenError::Occupied(_) => ListenError::Occupied(path.to_path_buf()),
                other => other,
            });
        }
        Ok(Listener { name, socket, auth })
    }

    /// Checks the new socket landed in the checked directory under the
    /// directory owner's id, sets 0660 and renames it over `file`.
    fn place(
        dir: &OwnedFd,
        temp: &str,
        file: &std::ffi::OsStr,
        dir_uid: u32,
    ) -> Result<(), ListenError> {
        let at = |e: rustix::io::Errno| ListenError::Io(format!("{temp}: {e}"));
        // Not found here means the path no longer leads to the checked
        // directory: refuse.
        let mine = rustix::fs::statat(dir, temp, AtFlags::SYMLINK_NOFOLLOW).map_err(at)?;
        if mine.st_uid != dir_uid {
            return Err(ListenError::Directory(format!(
                "the directory belongs to uid {dir_uid}, not this user (uid {})",
                mine.st_uid
            )));
        }
        match rustix::fs::statat(dir, file, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(old)
                if FileType::from_raw_mode(old.st_mode) == FileType::Socket
                    && old.st_uid == mine.st_uid => {}
            Ok(_) => return Err(ListenError::Occupied(Path::new(file).to_path_buf())),
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(at(e)),
        }
        rustix::fs::chmodat(dir, temp, Mode::from_raw_mode(0o660), AtFlags::empty()).map_err(at)?;
        rustix::fs::renameat(dir, temp, dir, file).map_err(at)
    }

    struct Shared<H, L> {
        auth: TokenAuthenticator,
        handler: H,
        log: Mutex<L>,
        handlers: Arc<Semaphore>,
        in_flight: Mutex<BTreeMap<String, usize>>,
    }

    /// One principal's slot; released when the handler's thread finishes.
    struct Slot<H, L> {
        shared: Arc<Shared<H, L>>,
        principal: String,
    }

    impl<H, L> Drop for Slot<H, L> {
        /// Runs on the handler's worker thread only: a `Slot` is taken just
        /// before `spawn_blocking` and moved into its closure, so it is
        /// dropped there whether the handler returns or panics. That is a
        /// blocking context, where `blocking_lock` is allowed (it panics in
        /// an async one).
        fn drop(&mut self) {
            let mut map = self.shared.in_flight.blocking_lock();
            let now_zero = map.get_mut(&self.principal).is_some_and(|n| {
                *n = n.saturating_sub(1);
                *n == 0
            });
            if now_zero {
                map.remove(&self.principal);
            }
        }
    }

    fn plain(status: hyper::StatusCode, body: &'static str) -> hyper::Response<Body> {
        let mut r = hyper::Response::new(Body::new(Bytes::from_static(body.as_bytes())));
        *r.status_mut() = status;
        r
    }

    fn retry_later(status: hyper::StatusCode, body: &'static str) -> hyper::Response<Body> {
        let mut r = plain(status, body);
        r.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("1"),
        );
        r
    }

    impl Listener {
        /// The grant's manifest name.
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Serves requests until the process ends. Each request's Bearer
        /// token is checked first; `handler` runs only for an authenticated
        /// principal, on a worker thread, within the limits in
        /// [`crate::listen`]. A handler that panics produces a 500
        /// (`listen.panic` is logged); every answered request is logged as
        /// `listen.request` with the method, the status and the principal,
        /// never the path, query or token.
        ///
        /// # Errors
        ///
        /// [`ListenError::Io`] if the runtime cannot start or the socket
        /// cannot be registered. Once serving, it does not return.
        pub fn serve<H, L>(self, handler: H, log: L) -> Result<Infallible, ListenError>
        where
            H: Fn(&Authenticated, Request) -> Response + Send + Sync + 'static,
            L: LogWriter + Send + 'static,
        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| ListenError::Io(format!("runtime: {e}")))?;
            let shared = Arc::new(Shared {
                auth: self.auth,
                handler,
                log: Mutex::new(log),
                handlers: Arc::new(Semaphore::new(MAX_HANDLERS)),
                in_flight: Mutex::new(BTreeMap::new()),
            });
            let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
            let socket = self.socket;
            runtime.block_on(async move {
                let listener = socket
                    .listen(BACKLOG)
                    .map_err(|e| ListenError::Io(e.to_string()))?;
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        // Out of descriptors and the like: back off, carry on.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    // Over the cap: the stream is dropped, closing it.
                    let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                        continue;
                    };
                    let shared = Arc::clone(&shared);
                    let _connection = tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |req| {
                            let shared = Arc::clone(&shared);
                            async move { Ok::<_, Infallible>(answer(shared, req).await) }
                        });
                        let _served = hyper::server::conn::http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(Duration::from_secs(HEAD_TIMEOUT_SECS))
                            .max_buf_size(MAX_HEAD)
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                        drop(permit);
                    });
                }
            })
        }
    }

    /// The token from `Authorization: Bearer <token>`, if well-formed.
    fn bearer(req: &hyper::Request<Incoming>) -> Option<&str> {
        let value = req
            .headers()
            .get(hyper::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let token = value.strip_prefix("Bearer ")?;
        (!token.is_empty()).then_some(token)
    }

    /// Locks are tokio's, awaited: a `std::sync::Mutex` in async code is a
    /// blocking call (`corten_blocking_in_async`). None is held across an
    /// `.await`; the writer itself is a plain synchronous call.
    async fn log<H, L: LogWriter>(shared: &Shared<H, L>, record: &crate::log::LogRecord) {
        shared.log.lock().await.write(record);
    }

    /// Takes a slot for `principal`, or `None` at [`MAX_PER_PRINCIPAL`].
    async fn take_slot<H, L>(shared: &Arc<Shared<H, L>>, principal: &str) -> Option<Slot<H, L>> {
        let mut map = shared.in_flight.lock().await;
        let n = map.entry(principal.to_owned()).or_insert(0);
        if *n >= MAX_PER_PRINCIPAL {
            return None;
        }
        *n = n.checked_add(1)?;
        Some(Slot {
            shared: Arc::clone(shared),
            principal: principal.to_owned(),
        })
    }

    async fn answer<H, L>(
        shared: Arc<Shared<H, L>>,
        req: hyper::Request<Incoming>,
    ) -> hyper::Response<Body>
    where
        H: Fn(&Authenticated, Request) -> Response + Send + Sync + 'static,
        L: LogWriter + Send + 'static,
    {
        use hyper::StatusCode as S;
        // Authentication first: it is cheap, and nothing else runs without it.
        let checked = match bearer(&req) {
            Some(t) => Some(
                shared
                    .auth
                    .authenticate(Token(t), &mut *shared.log.lock().await),
            ),
            None => None,
        };
        let Some(Ok(who)) = checked else {
            let mut r = plain(S::UNAUTHORIZED, "unauthorized\n");
            r.headers_mut().insert(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static("Bearer"),
            );
            return r;
        };
        let principal = who.principal().to_owned();
        let (parts, body) = req.into_parts();
        let limited = http_body_util::Limited::new(body, MAX_BODY).collect();
        let body = match tokio::time::timeout(Duration::from_secs(BODY_TIMEOUT_SECS), limited).await
        {
            Err(_) => return plain(S::REQUEST_TIMEOUT, "body too slow\n"),
            Ok(Ok(b)) => b.to_bytes().to_vec(),
            Ok(Err(e))
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return plain(S::PAYLOAD_TOO_LARGE, "body too large\n");
            }
            Ok(Err(_)) => return plain(S::BAD_REQUEST, "unreadable body\n"),
        };
        let mut headers = Vec::new();
        for (name, value) in &parts.headers {
            if name == hyper::header::AUTHORIZATION {
                continue;
            }
            let Ok(value) = value.to_str() else {
                return plain(S::BAD_REQUEST, "header value is not visible ASCII\n");
            };
            headers.push((name.as_str().to_owned(), value.to_owned()));
        }
        let method = parts.method.as_str().to_owned();
        let request = Request {
            method: method.clone(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers,
            body,
        };
        let Ok(handler_permit) = Arc::clone(&shared.handlers).try_acquire_owned() else {
            return retry_later(S::SERVICE_UNAVAILABLE, "busy\n");
        };
        let Some(slot) = take_slot(&shared, &principal).await else {
            return retry_later(S::TOO_MANY_REQUESTS, "too many requests at once\n");
        };
        // The worker owns the handler slot and the principal slot until the
        // handler returns, whether or not the caller is still waiting.
        let worker = Arc::clone(&shared);
        let job = tokio::task::spawn_blocking(move || {
            let response = (worker.handler)(&who, request);
            drop(slot);
            drop(handler_permit);
            response
        });
        let response = match tokio::time::timeout(Duration::from_secs(HANDLER_TIMEOUT_SECS), job)
            .await
        {
            Err(_) => {
                log(
                    &shared,
                    &crate::log_record!("listen.timeout", method = method, principal = principal),
                )
                .await;
                return plain(S::GATEWAY_TIMEOUT, "handler timed out\n");
            }
            Ok(Err(_)) => {
                log(
                    &shared,
                    &crate::log_record!("listen.panic", method = method, principal = principal),
                )
                .await;
                return plain(S::INTERNAL_SERVER_ERROR, "internal error\n");
            }
            Ok(Ok(r)) => r,
        };
        log(
            &shared,
            &crate::log_record!(
                "listen.request",
                method = method,
                status = response.status,
                principal = principal
            ),
        )
        .await;
        to_hyper(response)
    }

    /// The handler's response as hyper's.
    ///
    /// Names and values were validated by `crate::http`, which is stricter
    /// than hyper's grammar; if hyper still refused one, the caller gets a
    /// 500 rather than a response with a header silently missing.
    fn to_hyper(response: Response) -> hyper::Response<Body> {
        let mut builder = hyper::Response::builder().status(response.status);
        for (name, value) in &response.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder
            .body(Body::new(Bytes::from(response.body)))
            .unwrap_or_else(|_| plain(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal error\n"))
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};

    use ed25519_compact::{KeyPair, Seed};

    use crate::authz::TokenAuthenticator;
    use crate::log::{LogRecord, LogWriter};

    fn kp() -> KeyPair {
        KeyPair::from_seed(Seed::new([3; 32]))
    }

    fn auth() -> TokenAuthenticator {
        TokenAuthenticator::new("api".into(), &[("k1".into(), *kp().pk)]).unwrap()
    }

    fn token(principal: &str) -> String {
        let crate::manifest::UnixTime(now) = crate::manifest::now().unwrap();
        let fields = format!(
            "corten-token-1.k1.api.{principal}.{}",
            now.checked_add(300).unwrap()
        );
        let sig = kp().sk.sign(fields.as_bytes(), None);
        let hex = sig.as_ref().iter().fold(String::new(), |mut s, b| {
            std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}")).unwrap();
            s
        });
        format!("{fields}.{hex}")
    }

    fn dir(tag: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        // Short: socket paths are limited to about 104 bytes.
        let d = std::env::temp_dir().join(format!("cl{}{tag}{n}", std::process::id()));
        let _gone = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<String>>>);
    impl LogWriter for Sink {
        fn write(&mut self, record: &LogRecord) {
            self.0.lock().unwrap().push(record.render());
        }
    }

    /// Sends one request (with `Connection: close`); returns the status and
    /// the whole response text.
    fn send(path: &Path, head: &str, body: &[u8]) -> (u16, String) {
        let mut s = UnixStream::connect(path).unwrap();
        let req = format!(
            "{head}\r\nHost: program\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status = out.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
        (status, out)
    }

    fn get(path: &Path, target: &str, token: Option<&str>) -> (u16, String) {
        let head = match token {
            Some(t) => format!("GET {target} HTTP/1.1\r\nAuthorization: Bearer {t}"),
            None => format!("GET {target} HTTP/1.1"),
        };
        send(path, &head, b"")
    }

    /// Binds and serves on a thread; returns the socket path and the log.
    fn serve<H>(tag: &str, handler: H) -> (PathBuf, Sink)
    where
        H: Fn(&Authenticated, Request) -> Response + Send + Sync + 'static,
    {
        let path = dir(tag).join("app.sock");
        let listener = bind("app".into(), &path, auth()).unwrap();
        let sink = Sink::default();
        let log = sink.clone();
        let _serving = std::thread::spawn(move || listener.serve(handler, log));
        (path, sink)
    }

    use crate::authz::Authenticated;

    #[test]
    fn only_an_authenticated_request_reaches_the_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (path, log) = serve("auth", move |who, req| {
            seen.fetch_add(1, Ordering::SeqCst);
            let body = format!(
                "{}|{}|{}|{:?}|{}|{}",
                who.principal(),
                req.method(),
                req.path(),
                req.query(),
                req.header("x-trace").unwrap_or("-"),
                req.header("authorization").unwrap_or("none"),
            );
            Response::ok(body)
        });
        let (status, text) = get(&path, "/hello", None);
        assert_eq!(status, 401);
        assert!(
            text.to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "{text}"
        );
        assert_eq!(
            get(&path, "/hello", Some("corten-token-1.k1.api.x.1.00")).0,
            401
        );
        assert_eq!(
            get(
                &path,
                "/hello",
                Some(&token("alice"))
                    .map(|t| format!("Basic {t}"))
                    .as_deref()
            )
            .0,
            401
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no handler ran without a valid token"
        );
        let t = token("alice");
        let (status, text) = send(
            &path,
            &format!("GET /hello?q=1 HTTP/1.1\r\nAuthorization: Bearer {t}\r\nX-Trace: abc"),
            b"",
        );
        assert_eq!(status, 200, "{text}");
        assert!(
            text.ends_with("alice|GET|/hello|Some(\"q=1\")|abc|none"),
            "{text}"
        );
        let lines = log.0.lock().unwrap().clone();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("listen.request") && l.contains("principal=\"alice\"")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .all(|l| !l.contains(&t) && !l.contains("/hello")),
            "no token or path in the log: {lines:?}"
        );
    }

    #[test]
    fn an_oversized_body_is_refused_and_a_panic_is_contained() {
        let (path, log) = serve("limits", |_, req| {
            assert!(req.body() != b"boom", "handler panicked on purpose");
            Response::ok(format!("{}", req.body().len()))
        });
        let t = token("bob");
        let head = format!("POST /up HTTP/1.1\r\nAuthorization: Bearer {t}");
        assert!(
            send(&path, &head, &vec![b'a'; MAX_BODY])
                .1
                .ends_with(&MAX_BODY.to_string())
        );
        assert_eq!(send(&path, &head, &vec![b'a'; MAX_BODY + 1]).0, 413);
        assert_eq!(send(&path, &head, b"boom").0, 500);
        assert!(
            log.0
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("listen.panic"))
        );
        assert_eq!(
            send(&path, &head, b"after").0,
            200,
            "the listener carries on"
        );
    }

    #[test]
    fn one_principal_cannot_take_every_slot() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let entered = Arc::new(AtomicUsize::new(0));
        let inside = Arc::clone(&entered);
        let (path, _log) = serve("slots", move |who, _| {
            if who.principal() == "carol" {
                inside.fetch_add(1, Ordering::SeqCst);
                let _released = release_rx.lock().unwrap().recv();
            }
            Response::ok("done")
        });
        let held: Vec<_> = (0..MAX_PER_PRINCIPAL)
            .map(|_| {
                let p = path.clone();
                let t = token("carol");
                std::thread::spawn(move || get(&p, "/", Some(&t)).0)
            })
            .collect();
        while entered.load(Ordering::SeqCst) < MAX_PER_PRINCIPAL {
            std::thread::yield_now();
        }
        let (status, text) = get(&path, "/", Some(&token("carol")));
        assert_eq!(status, 429, "{text}");
        assert!(text.to_ascii_lowercase().contains("retry-after: 1"));
        assert_eq!(
            get(&path, "/", Some(&token("dave"))).0,
            200,
            "another principal is still served"
        );
        for _ in 0..MAX_PER_PRINCIPAL {
            release_tx.send(()).unwrap();
        }
        for h in held {
            assert_eq!(h.join().unwrap(), 200);
        }
        assert_eq!(get(&path, "/", Some(&token("dave"))).0, 200);
    }

    #[test]
    fn beyond_the_handler_cap_requests_are_shed_with_503() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let entered = Arc::new(AtomicUsize::new(0));
        let inside = Arc::clone(&entered);
        let (path, _log) = serve("cap", move |_, _| {
            inside.fetch_add(1, Ordering::SeqCst);
            let _released = release_rx.lock().unwrap().recv();
            Response::ok("done")
        });
        // MAX_HANDLERS requests from distinct principals fill every slot
        // without reaching the per-principal cap.
        let held: Vec<_> = (0..MAX_HANDLERS)
            .map(|i| {
                let p = path.clone();
                let t = token(&format!("user{i}"));
                std::thread::spawn(move || get(&p, "/", Some(&t)).0)
            })
            .collect();
        while entered.load(Ordering::SeqCst) < MAX_HANDLERS {
            std::thread::yield_now();
        }
        let (status, text) = get(&path, "/", Some(&token("late")));
        assert_eq!(status, 503, "{text}");
        assert!(text.to_ascii_lowercase().contains("retry-after: 1"));
        for _ in 0..MAX_HANDLERS {
            release_tx.send(()).unwrap();
        }
        for h in held {
            assert_eq!(h.join().unwrap(), 200);
        }
    }

    #[test]
    fn the_socket_is_0660_and_only_a_stale_own_socket_is_replaced() {
        let d = dir("bind");
        let path = d.join("app.sock");
        let first = bind("app".into(), &path, auth()).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o660);
        drop(first);
        // The stale socket from the last run is replaced.
        let _second = bind("app".into(), &path, auth()).unwrap();
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            1,
            "no temporary socket left behind"
        );
        // Anything else at the path is not.
        let file = d.join("data");
        std::fs::write(&file, b"keep").unwrap();
        assert!(matches!(
            bind("app".into(), &file, auth()),
            Err(ListenError::Occupied(_))
        ));
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            2,
            "the refused attempt left nothing"
        );
        // A directory others may write to is refused.
        let open = dir("open");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            bind("app".into(), &open.join("s"), auth()),
            Err(ListenError::Directory(_))
        ));
    }

    #[test]
    fn responses_cannot_set_framing_headers_or_bad_statuses() {
        let name = |n: &str| crate::http::HeaderName::parse(n).unwrap();
        let value = crate::http::HeaderValue::parse("1").unwrap();
        for f in [
            "Content-Length",
            "transfer-encoding",
            "Connection",
            "upgrade",
        ] {
            assert!(matches!(
                Response::ok("x").with_header(name(f), value.clone()),
                Err(ListenError::Framing(_))
            ));
        }
        assert!(Response::ok("x").with_header(name("x-ok"), value).is_ok());
        assert!(matches!(
            Response::new(99, "x"),
            Err(ListenError::Status(99))
        ));
        assert!(matches!(
            Response::new(600, "x"),
            Err(ListenError::Status(600))
        ));
        assert_eq!(Response::new(204, "").unwrap().status(), 204);
    }
}
