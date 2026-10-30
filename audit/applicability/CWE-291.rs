//@ compiles: safe
// CWE-291, reliance on IP address for authentication: requests from the
// "office" address are treated as authenticated.
use std::net::IpAddr;
pub fn is_trusted(peer: IpAddr) -> bool {
    peer == IpAddr::from([10, 0, 0, 5])
}
