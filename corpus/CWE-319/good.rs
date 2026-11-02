//@ deps: corten-std
// The destination is a manifest grant, and the connection is TLS 1.3 with
// verification that cannot be turned off.
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::net::{Revocation, Timeouts};
use std::io::Write;

struct Discard;

impl LogWriter for Discard {
    fn write(&mut self, record: &LogRecord) {
        let _rendered = record.render();
    }
}

pub fn send(caps: &mut Capabilities, body: &[u8]) -> bool {
    let Some(api) = caps.take_net("api") else {
        return false;
    };
    let Ok(mut stream) = api.connect_tls(&Timeouts::default(), &Revocation::Unchecked, &mut Discard) else {
        return false;
    };
    stream.write_all(body).is_ok()
}

fn main() {}
