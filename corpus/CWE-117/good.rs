//@ deps: corten-std
use corten_std::log::LogWriter;

pub fn audit<L: LogWriter>(log: &mut L, user: &str) {
    log.write(&corten_std::log_record!("login.failed", user = user));
}

fn main() {}
