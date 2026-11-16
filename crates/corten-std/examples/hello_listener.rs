//! A deployment demo, not a checked program: it serves "hello, PRINCIPAL"
//! on the socket its manifest's `listen app` grant names, behind the
//! exchange gateway (`scripts/gateway-keycloak-e2e.py --deployed`).
//!
//! It reads its own manifest and signature from files with `std::fs`, which
//! `cargo corten check` would refuse: Corten has no defined way yet for a
//! launcher to hand a program its manifest (`docs/gates/phase-6.md`). Run it
//! under `corten-sandbox --manifest`, which grants the socket.
//!
//! Usage: `hello_listener MANIFEST SIGNATURE KEY_ID=HEX_PUBLIC_KEY`

#![expect(
    clippy::print_stderr,
    reason = "a demo binary: errors go to standard error"
)]

use corten_std::listen::Response;
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::{Capabilities, KeyId, MinSerial, PublicKey, Signature, TrustedKeys};

/// Log records to standard error, one per line.
struct Stderr;

impl LogWriter for Stderr {
    fn write(&mut self, record: &LogRecord) {
        eprintln!("{}", record.render());
    }
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i.checked_add(2)?)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [manifest, signature, key] = args.as_slice() else {
        return Err("usage: hello_listener MANIFEST SIGNATURE KEY_ID=HEX".into());
    };
    let (id, key_hex) = key.split_once('=').ok_or("KEY_ID=HEX")?;
    let key = hex(key_hex).ok_or("the key is not hex")?;
    let mut trusted = TrustedKeys::new();
    trusted
        .add(KeyId(id), PublicKey(&key))
        .map_err(|e| e.to_string())?;
    let m = std::fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
    let s = std::fs::read(signature).map_err(|e| format!("{signature}: {e}"))?;
    let mut caps =
        Capabilities::load(&m, Signature(&s), &trusted, MinSerial(0)).map_err(|e| e.to_string())?;
    let listener = caps
        .take_listener("app")
        .ok_or("the manifest grants no `listen app`")?;
    eprintln!("hello_listener: serving");
    match listener.serve(
        |who, req| {
            Response::ok(format!(
                "hello, {} (method {}, path {}, token seen: {})\n",
                who.principal(),
                req.method(),
                req.path(),
                req.header("authorization").is_some()
            ))
        },
        Stderr,
    ) {
        Ok(never) => match never {},
        Err(e) => Err(e.to_string()),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hello_listener: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
