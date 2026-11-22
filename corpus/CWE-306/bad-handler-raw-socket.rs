//@ kind: checker
//@ expect: std::os::unix::net::UnixListener
// CWE-306 handler variant: serving requests on a socket the program binds itself,
// past the `listen` grant and its authentication. The checker bans `std`'s
// listening sockets; `corten_std::listen` is the only listener.
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

fn main() {
    let Ok(listener) = UnixListener::bind("/tmp/app.sock") else {
        return;
    };
    for mut stream in listener.incoming().flatten() {
        let mut request = [0_u8; 1024];
        if stream.read(&mut request).is_ok() {
            let _sent = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        }
    }
}
