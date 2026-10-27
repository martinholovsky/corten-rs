//@ compiles: safe
// CWE-1327, binding to an unrestricted IP address: the admin listener binds
// 0.0.0.0, exposing it on every interface.
use std::net::TcpListener;
pub fn admin_listener() -> std::io::Result<TcpListener> {
    TcpListener::bind("0.0.0.0:9000")
}
