//! A deployment demo: it serves "hello, PRINCIPAL" on the socket its
//! manifest's `listen app` grant names, behind the exchange gateway
//! (`scripts/gateway-keycloak-e2e.py --deployed`).
//!
//! It takes its capabilities as a Corten program does: from the launch
//! document `corten-sandbox --manifest` puts on its standard input
//! (`Capabilities::from_launcher`; spec section 8, question 26). It reads no
//! file and no argument.

#![expect(
    clippy::print_stderr,
    reason = "a demo binary: errors go to standard error"
)]

use corten_std::listen::Response;
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;

/// Log records to standard error, one per line.
struct Stderr;

impl LogWriter for Stderr {
    fn write(&mut self, record: &LogRecord) {
        eprintln!("{}", record.render());
    }
}

fn run() -> Result<(), String> {
    let mut caps = Capabilities::from_launcher().map_err(|e| e.to_string())?;
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
