//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-117: a log line built by string formatting.
use corten_std::log::LogWriter;

pub fn audit<L: LogWriter>(log: &mut L, user: &str) {
    let line = format!("login failed for {user}");
    log.write(&line);
}

fn main() {}
