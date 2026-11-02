//! `NetCap`: network authority from the signed manifest (Phase 6, batch 5,
//! strategy 7; design in `docs/netcap.md`).
//!
//! A manifest line `net NAME HOST:PORT [private]` grants one destination.
//! The program takes it with `Capabilities::take_net` and can reach nothing
//! else. [`NetCap::connect_tls`] is the only way to use it:
//!
//! 1. the destination's addresses are checked: IPv4-mapped IPv6 is
//!    canonicalized first, and loopback, private, shared, link-local (the
//!    cloud metadata address among them), unique-local, multicast,
//!    unspecified, NAT64 and 6to4 addresses are refused unless the grant says
//!    `private` (CWE-918, 923, 941). If any address is refused, all are;
//! 2. a TCP connection is made with a bounded connect timeout and read and
//!    write timeouts (CWE-1088), one pass over the checked addresses, no
//!    retry after data was sent;
//! 3. TLS 1.3 only, verified against the platform's root certificates and
//!    the granted host, with no way to turn verification off and no
//!    plaintext API (CWE-295, 297, 319, 757, 1428). Revocation is the
//!    caller's [`Revocation`]: operator-supplied CRLs enforced including
//!    their expiry, or an explicit `Unchecked` that is logged as a warning
//!    (spec section 8, question 18; CWE-299, 370).
//!
//! Every connection writes its security state to the caller's
//! [`LogWriter`] before data flows (CWE-778, 223).
//!
//! Host names are resolved by the resolver that question 17 chose
//! (`hickory-resolver`), which is not built yet: a grant naming a host
//! returns [`NetError::NoResolver`]. A grant naming an IP address works, and
//! its certificate must be issued for that address. Sockets are Linux-only,
//! like `DirCap`; elsewhere [`NetError::Unsupported`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::log::LogWriter;

/// The longest connect, read or write timeout a caller may set.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);
/// The default connect timeout.
pub const DEFAULT_CONNECT: Duration = Duration::from_secs(10);
/// The default read and write timeout.
pub const DEFAULT_IO: Duration = Duration::from_secs(30);

/// Why a connection was refused or failed.
#[derive(Debug)]
pub enum NetError {
    /// An address of the destination is not allowed by the grant.
    Refused {
        /// The address, canonicalized.
        address: IpAddr,
        /// The class that refused it.
        class: &'static str,
    },
    /// A timeout above [`MAX_TIMEOUT`] or of zero.
    Timeout,
    /// No address answered within the connect timeout.
    ConnectTimedOut,
    /// A socket call failed.
    Io(String),
    /// The TLS handshake, configuration or a CRL failed.
    Tls(String),
    /// The grant names a host, and name resolution is not built yet.
    NoResolver,
    /// Sockets are not supported on this platform.
    Unsupported,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { address, class } => {
                write!(
                    f,
                    "address {address} refused: {class}, and the grant is not private"
                )
            }
            Self::Timeout => write!(
                f,
                "timeouts must be between 1 ms and {} s",
                MAX_TIMEOUT.as_secs()
            ),
            Self::ConnectTimedOut => f.write_str("no address answered within the connect timeout"),
            Self::Io(e) => write!(f, "network error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::NoResolver => {
                f.write_str("this grant names a host; name resolution is not built yet")
            }
            Self::Unsupported => f.write_str("network sockets are not supported on this platform"),
        }
    }
}

impl std::error::Error for NetError {}

/// The connect timeout: a label, so it cannot be swapped with [`IoTimeout`].
#[derive(Debug, Clone, Copy)]
pub struct ConnectTimeout(pub Duration);

/// The read and write timeout.
#[derive(Debug, Clone, Copy)]
pub struct IoTimeout(pub Duration);

/// Connect, read and write timeouts, each at most [`MAX_TIMEOUT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    connect: Duration,
    io: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT,
            io: DEFAULT_IO,
        }
    }
}

impl Timeouts {
    /// Custom timeouts.
    ///
    /// # Errors
    ///
    /// [`NetError::Timeout`] if either is zero or above [`MAX_TIMEOUT`].
    pub fn new(
        ConnectTimeout(connect): ConnectTimeout,
        IoTimeout(io): IoTimeout,
    ) -> Result<Self, NetError> {
        let ok = |d: Duration| !d.is_zero() && d <= MAX_TIMEOUT;
        if ok(connect) && ok(io) {
            Ok(Self { connect, io })
        } else {
            Err(NetError::Timeout)
        }
    }
}

/// How the server certificate's revocation is checked (question 18).
#[derive(Debug, Clone)]
pub enum Revocation {
    /// DER-encoded CRLs from the operator. Every certificate in the chain is
    /// checked; a CRL past its next-update time fails the connection; a
    /// certificate no CRL covers fails it too.
    Crls(Vec<Vec<u8>>),
    /// No revocation check. Allowed, but logged as a warning at every
    /// connection, so the operator knows.
    Unchecked,
}

/// The destination a grant names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A DNS name, lower case.
    Name(String),
    /// An IP address.
    Ip(IpAddr),
}

/// Parses `HOST:PORT` from a manifest: a DNS name (letters, digits and
/// hyphens in labels of 1 to 63 bytes, at most 253 bytes, not all-numeric
/// in its last label), an IPv4 address, or `[IPv6]`. The port is 1 to 65535.
#[must_use]
pub fn parse_target(text: &str) -> Option<(Host, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|&p| p != 0 && !port.starts_with('0'))?;
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6
            .parse::<Ipv6Addr>()
            .ok()
            .map(|a| (Host::Ip(IpAddr::V6(a)), port));
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some((Host::Ip(IpAddr::V4(v4)), port));
    }
    let name_ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && host
            .rsplit('.')
            .next()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()));
    name_ok.then(|| (Host::Name(host.to_owned()), port))
}

/// The class of a non-public address, or `None` for a public one. Checks the
/// canonical form: an IPv4-mapped IPv6 address is checked as IPv4.
#[must_use]
pub fn restricted_class(address: IpAddr) -> Option<&'static str> {
    match address.to_canonical() {
        IpAddr::V4(a) => {
            let [o0, o1, ..] = a.octets();
            if a == Ipv4Addr::new(169, 254, 169, 254) {
                Some("cloud metadata")
            } else if a.is_loopback() {
                Some("loopback")
            } else if a.is_private() {
                Some("private")
            } else if o0 == 100 && (64..128).contains(&o1) {
                Some("shared (carrier-grade NAT)")
            } else if a.is_link_local() {
                Some("link-local")
            } else if a.is_unspecified() || o0 == 0 {
                Some("unspecified or this-network")
            } else if a.is_multicast() || a.is_broadcast() || o0 >= 240 {
                Some("multicast, broadcast or reserved")
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if a == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
                Some("cloud metadata")
            } else if a.is_loopback() {
                Some("loopback")
            } else if a.is_unspecified() {
                Some("unspecified")
            } else if s[0] & 0xfe00 == 0xfc00 {
                Some("unique-local")
            } else if s[0] & 0xffc0 == 0xfe80 {
                Some("link-local")
            } else if a.is_multicast() {
                Some("multicast")
            } else if s[0] == 0x0064 && s[1] == 0xff9b {
                Some("NAT64 (embeds an IPv4 address)")
            } else if s[0] == 0x2002 {
                Some("6to4 (embeds an IPv4 address)")
            } else if s[..6] == [0, 0, 0, 0, 0, 0] {
                Some("IPv4-compatible (deprecated)")
            } else {
                None
            }
        }
    }
}

/// Checks every address before any is used: one refused address refuses
/// them all, since a mixed answer is how DNS rebinding looks (CWE-367, 918).
///
/// # Errors
///
/// [`NetError::Refused`] for the first refused address.
pub fn check_addresses(addresses: &[IpAddr], private: bool) -> Result<Vec<IpAddr>, NetError> {
    let mut out = Vec::with_capacity(addresses.len());
    for &a in addresses {
        let canonical = a.to_canonical();
        if let (false, Some(class)) = (private, restricted_class(canonical)) {
            return Err(NetError::Refused {
                address: canonical,
                class,
            });
        }
        out.push(canonical);
    }
    Ok(out)
}

/// One granted destination. See the module documentation.
#[derive(Debug)]
pub struct NetCap {
    name: String,
    host: Host,
    port: u16,
    private: bool,
}

impl NetCap {
    pub(crate) fn new(name: String, host: Host, port: u16, private: bool) -> Self {
        Self {
            name,
            host,
            port,
            private,
        }
    }

    /// The manifest name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Connects with TLS 1.3 to the granted destination. Writes the
    /// connection's security state to `log` first.
    ///
    /// # Errors
    ///
    /// [`NetError`].
    pub fn connect_tls(
        &self,
        timeouts: &Timeouts,
        revocation: &Revocation,
        log: &mut dyn LogWriter,
    ) -> Result<tls::TlsStream, NetError> {
        self.connect_with(timeouts, revocation, log, tls::roots)
    }

    /// `connect_tls` with the trust anchors from `roots`; tests pass a test CA.
    fn connect_with(
        &self,
        timeouts: &Timeouts,
        revocation: &Revocation,
        log: &mut dyn LogWriter,
        roots: fn() -> Result<rustls::RootCertStore, NetError>,
    ) -> Result<tls::TlsStream, NetError> {
        let addresses = match &self.host {
            Host::Ip(a) => vec![*a],
            Host::Name(_) => return Err(NetError::NoResolver),
        };
        let checked = match check_addresses(&addresses, self.private) {
            Ok(c) => c,
            Err(e) => {
                log.write(&crate::log_record!(
                    "net.refused",
                    grant = self.name,
                    reason = e
                ));
                return Err(e);
            }
        };
        let revocation_mode = match revocation {
            Revocation::Crls(c) => format!("crls:{}", c.len()),
            Revocation::Unchecked => "unchecked".to_owned(),
        };
        log.write(&crate::log_record!(
            "net.connect",
            grant = self.name,
            port = self.port,
            dns_source = "none (address grant)",
            tls = "1.3",
            revocation = revocation_mode
        ));
        if matches!(revocation, Revocation::Unchecked) {
            log.write(&crate::log_record!(
                "net.warning",
                grant = self.name,
                risk = "certificate revocation is not checked: a revoked certificate is accepted"
            ));
        }
        let addrs: Vec<SocketAddr> = checked
            .iter()
            .map(|&a| SocketAddr::new(a, self.port))
            .collect();
        let socket = sock::connect(&addrs, timeouts)?;
        tls::handshake(socket, &self.host, revocation, roots()?)
    }
}

#[cfg(target_os = "linux")]
mod sock {
    use std::net::SocketAddr;
    use std::os::fd::OwnedFd;

    use rustix::event::{PollFd, PollFlags, poll};
    use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_error};
    use rustix::net::{
        AddressFamily, SocketFlags, SocketType, connect as sys_connect, socket_with,
    };

    use super::{NetError, Timeouts};

    /// A connected TCP socket with read and write timeouts.
    #[derive(Debug)]
    pub struct Socket(OwnedFd);

    impl std::io::Read for Socket {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            rustix::io::read(&self.0, buf).map_err(std::io::Error::from)
        }
    }

    impl std::io::Write for Socket {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            rustix::io::write(&self.0, buf).map_err(std::io::Error::from)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn io(e: rustix::io::Errno) -> NetError {
        NetError::Io(e.to_string())
    }

    /// One pass over `addrs`, sharing the connect timeout between them.
    pub fn connect(addrs: &[SocketAddr], timeouts: &Timeouts) -> Result<Socket, NetError> {
        let count = u32::try_from(addrs.len()).unwrap_or(u32::MAX).max(1);
        let share = timeouts
            .connect
            .checked_div(count)
            .unwrap_or(timeouts.connect);
        let mut last = NetError::ConnectTimedOut;
        for addr in addrs {
            match connect_one(addr, share) {
                Ok(fd) => {
                    rustix::io::ioctl_fionbio(&fd, false).map_err(io)?;
                    set_socket_timeout(&fd, Timeout::Recv, Some(timeouts.io)).map_err(io)?;
                    set_socket_timeout(&fd, Timeout::Send, Some(timeouts.io)).map_err(io)?;
                    return Ok(Socket(fd));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn connect_one(addr: &SocketAddr, limit: std::time::Duration) -> Result<OwnedFd, NetError> {
        let family = if addr.is_ipv4() {
            AddressFamily::INET
        } else {
            AddressFamily::INET6
        };
        let fd = socket_with(
            family,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(io)?;
        match sys_connect(&fd, addr) {
            Ok(()) => return Ok(fd),
            Err(e) if e == rustix::io::Errno::INPROGRESS => {}
            Err(e) => return Err(io(e)),
        }
        let limit = rustix::time::Timespec {
            tv_sec: i64::try_from(limit.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(limit.subsec_nanos()),
        };
        let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
        if poll(&mut fds, Some(&limit)).map_err(io)? == 0 {
            return Err(NetError::ConnectTimedOut);
        }
        socket_error(&fd).map_err(io)?.map_err(io)?;
        Ok(fd)
    }
}

#[cfg(not(target_os = "linux"))]
mod sock {
    use std::net::SocketAddr;

    use super::{NetError, Timeouts};

    /// Never constructed off Linux: `connect` refuses first.
    #[derive(Debug)]
    pub struct Socket(());

    fn unsupported() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::Unsupported)
    }

    impl std::io::Read for Socket {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(unsupported())
        }
    }

    impl std::io::Write for Socket {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(unsupported())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(unsupported())
        }
    }

    pub fn connect(_: &[SocketAddr], _: &Timeouts) -> Result<Socket, NetError> {
        Err(NetError::Unsupported)
    }
}

/// The TLS 1.3 client.
pub mod tls {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateRevocationListDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use super::sock::Socket;
    use super::{Host, NetError, Revocation};

    /// A TLS 1.3 connection to a granted destination.
    #[derive(Debug)]
    pub struct TlsStream(StreamOwned<ClientConnection, Socket>);

    impl std::io::Read for TlsStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl std::io::Write for TlsStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    fn tls(e: impl std::fmt::Display) -> NetError {
        NetError::Tls(e.to_string())
    }

    /// The platform's root certificates. A root that fails to parse is
    /// skipped; none at all is an error.
    pub(super) fn roots() -> Result<RootCertStore, NetError> {
        let mut store = RootCertStore::empty();
        let found = rustls_native_certs::load_native_certs();
        let (added, _ignored) = store.add_parsable_certificates(found.certs);
        if added == 0 {
            return Err(NetError::Tls(
                "no root certificates found on this platform".to_owned(),
            ));
        }
        Ok(store)
    }

    /// The client configuration: TLS 1.3 only, the given roots, and CRLs
    /// enforced including their expiry when supplied.
    pub(super) fn config(
        roots: RootCertStore,
        revocation: &Revocation,
    ) -> Result<ClientConfig, NetError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        );
        if let Revocation::Crls(crls) = revocation {
            verifier = verifier
                .with_crls(
                    crls.iter()
                        .map(|c| CertificateRevocationListDer::from(c.clone())),
                )
                .enforce_revocation_expiration();
        }
        let verifier = verifier.build().map_err(tls)?;
        Ok(ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls)?
            .with_webpki_verifier(verifier)
            .with_no_client_auth())
    }

    pub(super) fn handshake(
        socket: Socket,
        host: &Host,
        revocation: &Revocation,
        roots: RootCertStore,
    ) -> Result<TlsStream, NetError> {
        let name = match host {
            Host::Ip(a) => ServerName::IpAddress((*a).into()),
            Host::Name(n) => ServerName::try_from(n.clone()).map_err(tls)?,
        };
        let conn =
            ClientConnection::new(Arc::new(config(roots, revocation)?), name).map_err(tls)?;
        let mut stream = StreamOwned::new(conn, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).map_err(tls)?;
        }
        Ok(TlsStream(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn targets_parse_strictly() {
        assert_eq!(
            parse_target("api.example.com:443"),
            Some((Host::Name("api.example.com".into()), 443))
        );
        assert_eq!(
            parse_target("203.0.113.7:8443"),
            Some((Host::Ip(ip("203.0.113.7")), 8443))
        );
        assert_eq!(
            parse_target("[2001:db8::1]:443"),
            Some((Host::Ip(ip("2001:db8::1")), 443))
        );
        for bad in [
            "api.example.com",
            "api.example.com:0",
            "api.example.com:65536",
            "api.example.com:080",
            "API.example.com:443",
            "-a.example.com:443",
            "a..b:443",
            ":443",
            "a_b.com:443",
            "2001:db8::1:443",
            "[2001:db8::1]",
            "1.2.3:443",
            "a.123:443",
            "a.com:443 ",
        ] {
            assert_eq!(parse_target(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_restricted_range_is_refused_and_public_ones_pass() {
        let refused = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "169.254.1.1",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd00:ec2::254",
            "fe80::1",
            "ff02::1",
            "64:ff9b::a00:1",
            "2002:a00:1::",
            "::a00:1",
            // IPv4-mapped forms of refused IPv4 addresses (GHSA-4jwp-xjwm-333g).
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ];
        for a in refused {
            assert!(restricted_class(ip(a)).is_some(), "{a} must be refused");
            assert!(
                matches!(
                    check_addresses(&[ip(a)], false),
                    Err(NetError::Refused { .. })
                ),
                "{a}"
            );
            assert!(
                check_addresses(&[ip(a)], true).is_ok(),
                "{a} with a private grant"
            );
        }
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.7",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ] {
            assert_eq!(restricted_class(ip(a)), None, "{a} is public");
        }
        assert_eq!(
            restricted_class(ip("::ffff:169.254.169.254")),
            Some("cloud metadata")
        );
    }

    #[test]
    fn one_refused_address_refuses_the_whole_answer() {
        let mixed = [ip("93.184.216.34"), ip("10.0.0.5")];
        assert!(matches!(
            check_addresses(&mixed, false),
            Err(NetError::Refused { address, .. }) if address == ip("10.0.0.5")
        ));
        let canonical = check_addresses(&[ip("::ffff:8.8.8.8")], false).unwrap();
        assert_eq!(canonical, [ip("8.8.8.8")]);
    }

    #[test]
    fn timeouts_are_bounded() {
        assert_eq!(Timeouts::default().connect, DEFAULT_CONNECT);
        assert!(
            Timeouts::new(
                ConnectTimeout(Duration::from_secs(1)),
                IoTimeout(MAX_TIMEOUT)
            )
            .is_ok()
        );
        assert!(matches!(
            Timeouts::new(
                ConnectTimeout(MAX_TIMEOUT + Duration::from_millis(1)),
                IoTimeout(DEFAULT_IO)
            ),
            Err(NetError::Timeout)
        ));
        assert!(matches!(
            Timeouts::new(ConnectTimeout(DEFAULT_CONNECT), IoTimeout(Duration::ZERO)),
            Err(NetError::Timeout)
        ));
    }

    #[derive(Default)]
    struct Collect(Vec<String>);
    impl LogWriter for Collect {
        fn write(&mut self, r: &crate::log::LogRecord) {
            self.0.push(r.render());
        }
    }

    #[test]
    fn refusals_and_name_grants_are_reported_before_any_socket() {
        let mut log = Collect::default();
        let metadata = NetCap::new(
            "meta".into(),
            Host::Ip(ip("::ffff:169.254.169.254")),
            80,
            false,
        );
        let r = metadata.connect_tls(&Timeouts::default(), &Revocation::Unchecked, &mut log);
        assert!(matches!(
            r,
            Err(NetError::Refused {
                class: "cloud metadata",
                ..
            })
        ));
        assert_eq!(log.0.len(), 1);
        assert!(
            log.0[0].starts_with("net.refused grant=\"meta\""),
            "{}",
            log.0[0]
        );
        let named = NetCap::new(
            "api".into(),
            Host::Name("api.example.com".into()),
            443,
            false,
        );
        assert!(matches!(
            named.connect_tls(&Timeouts::default(), &Revocation::Unchecked, &mut log),
            Err(NetError::NoResolver)
        ));
    }

    #[test]
    fn the_tls_config_is_1_3_only_and_takes_crls() {
        let mut roots = rustls::RootCertStore::empty();
        // An empty root store is enough to build the verifier only with no CRLs.
        assert!(
            tls::config(roots.clone(), &Revocation::Unchecked).is_err(),
            "no roots: refused"
        );
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        // TLS 1.3 only is shown by a handshake (tests::linux below).
        assert!(tls::config(roots.clone(), &Revocation::Unchecked).is_ok());
        assert!(
            matches!(
                tls::config(roots, &Revocation::Crls(vec![vec![0u8; 4]])),
                Err(NetError::Tls(_))
            ),
            "a malformed CRL is refused"
        );
    }

    /// Handshakes against a local server (Linux: sockets are Linux-only).
    #[cfg(target_os = "linux")]
    mod linux {
        use std::io::{Read, Write};
        use std::sync::{Arc, OnceLock};

        use rcgen::{
            BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer,
            KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, date_time_ymd,
        };
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        use super::*;

        /// A test CA, a leaf for 127.0.0.1 (serial 7) signed by it, and two
        /// CRLs: one listing serial 7, one listing serial 8.
        struct Pki {
            ca: CertificateDer<'static>,
            leaf: CertificateDer<'static>,
            leaf_key: Vec<u8>,
            crl_revoking_leaf: Vec<u8>,
            crl_revoking_other: Vec<u8>,
            crl_expired: Vec<u8>,
        }

        fn pki() -> &'static Pki {
            static PKI: OnceLock<Pki> = OnceLock::new();
            PKI.get_or_init(|| {
                let ca_key = KeyPair::generate().unwrap();
                let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
                ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
                let ca = ca_params.self_signed(&ca_key).unwrap();
                let issuer = Issuer::new(ca_params, ca_key);
                let leaf_key = KeyPair::generate().unwrap();
                let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
                leaf_params.serial_number = Some(SerialNumber::from(7u64));
                let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
                let crl = |serial: u64, this_year: i32, next_year: i32| {
                    CertificateRevocationListParams {
                        this_update: date_time_ymd(this_year, 1, 1),
                        next_update: date_time_ymd(next_year, 1, 1),
                        crl_number: SerialNumber::from(1u64),
                        issuing_distribution_point: None,
                        revoked_certs: vec![RevokedCertParams {
                            serial_number: SerialNumber::from(serial),
                            revocation_time: date_time_ymd(this_year, 1, 1),
                            reason_code: None,
                            invalidity_date: None,
                        }],
                        key_identifier_method: KeyIdMethod::Sha256,
                    }
                    .signed_by(&issuer)
                    .unwrap()
                    .der()
                    .to_vec()
                };
                Pki {
                    ca: ca.der().clone(),
                    leaf: leaf.der().clone(),
                    leaf_key: leaf_key.serialize_der(),
                    crl_revoking_leaf: crl(7, 2026, 2099),
                    crl_revoking_other: crl(8, 2026, 2099),
                    crl_expired: crl(8, 2024, 2025),
                }
            })
        }

        fn test_roots() -> Result<rustls::RootCertStore, NetError> {
            let mut r = rustls::RootCertStore::empty();
            r.add(pki().ca.clone())
                .map_err(|e| NetError::Tls(e.to_string()))?;
            Ok(r)
        }

        /// Serves one connection with the given versions; echoes one line.
        static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

        fn serve(versions: &'static [&'static rustls::SupportedProtocolVersion]) -> u16 {
            let p = pki();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let cfg = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![p.leaf.clone(), p.ca.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.leaf_key.clone())),
                )
                .unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::spawn(move || {
                let (tcp, _) = listener.accept().unwrap();
                let conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut buf = [0u8; 5];
                if tls.read_exact(&mut buf).is_ok() {
                    let _ignored = tls.write_all(&buf);
                    let _ignored = tls.flush();
                }
            });
            port
        }

        fn local(port: u16) -> NetCap {
            NetCap::new(
                "local".into(),
                Host::Ip("127.0.0.1".parse().unwrap()),
                port,
                true,
            )
        }

        #[derive(Default)]
        struct Log(Vec<String>);
        impl LogWriter for Log {
            fn write(&mut self, r: &crate::log::LogRecord) {
                self.0.push(r.render());
            }
        }

        fn connect(
            port: u16,
            revocation: &Revocation,
            log: &mut Log,
        ) -> Result<tls::TlsStream, NetError> {
            local(port).connect_with(&Timeouts::default(), revocation, log, test_roots)
        }

        #[test]
        fn tls_1_3_round_trip_and_the_log() {
            let mut log = Log::default();
            let mut s = connect(serve(TLS13_ONLY), &Revocation::Unchecked, &mut log).unwrap();
            s.write_all(b"hello").unwrap();
            let mut back = [0u8; 5];
            s.read_exact(&mut back).unwrap();
            assert_eq!(&back, b"hello");
            assert!(
                log.0[0].starts_with("net.connect grant=\"local\""),
                "{}",
                log.0[0]
            );
            assert!(
                log.0[0].contains("revocation=\"unchecked\""),
                "{}",
                log.0[0]
            );
            assert!(log.0[1].starts_with("net.warning"), "{:?}", log.0);
        }

        #[test]
        fn a_tls_1_2_only_server_is_refused() {
            let r = connect(
                serve(TLS12_ONLY),
                &Revocation::Unchecked,
                &mut Log::default(),
            );
            assert!(matches!(r, Err(NetError::Tls(_))), "{r:?}");
        }

        #[test]
        fn a_certificate_for_another_address_is_refused() {
            let port = serve(TLS13_ONLY);
            let other = NetCap::new(
                "x".into(),
                Host::Ip("127.0.0.2".parse().unwrap()),
                port,
                true,
            );
            // 127.0.0.2 is loopback too; the server listens on 127.0.0.1 only,
            // so connect to it but name 127.0.0.2: a host mismatch.
            let r = tls::handshake(
                sock::connect(
                    &[std::net::SocketAddr::new(
                        "127.0.0.1".parse().unwrap(),
                        port,
                    )],
                    &Timeouts::default(),
                )
                .unwrap(),
                &other.host,
                &Revocation::Unchecked,
                test_roots().unwrap(),
            );
            assert!(
                matches!(r, Err(NetError::Tls(ref e)) if e.contains("not valid for name")),
                "{r:?}"
            );
        }

        #[test]
        fn crls_refuse_the_revoked_and_accept_the_rest() {
            let p = pki();
            let revoked = connect(
                serve(TLS13_ONLY),
                &Revocation::Crls(vec![p.crl_revoking_leaf.clone()]),
                &mut Log::default(),
            );
            assert!(
                matches!(revoked, Err(NetError::Tls(ref e)) if e.contains("Revoked")),
                "{revoked:?}"
            );
            let mut log = Log::default();
            let ok = connect(
                serve(TLS13_ONLY),
                &Revocation::Crls(vec![p.crl_revoking_other.clone()]),
                &mut log,
            );
            assert!(ok.is_ok(), "{ok:?}");
            assert!(log.0[0].contains("revocation=\"crls:1\""), "{}", log.0[0]);
            assert_eq!(log.0.len(), 1, "no warning when CRLs are checked");
            let expired = connect(
                serve(TLS13_ONLY),
                &Revocation::Crls(vec![p.crl_expired.clone()]),
                &mut Log::default(),
            );
            assert!(
                matches!(expired, Err(NetError::Tls(_))),
                "an expired CRL fails the connection: {expired:?}"
            );
        }

        #[test]
        fn a_closed_port_fails_within_the_budget() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let r = connect(port, &Revocation::Unchecked, &mut Log::default());
            assert!(
                matches!(r, Err(NetError::Io(_) | NetError::ConnectTimedOut)),
                "{r:?}"
            );
        }
    }
}
