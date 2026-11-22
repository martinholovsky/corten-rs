//@ kind: language
//@ deps: corten-std
//@ expect: E0593
// CWE-306 handler variant: a request handler that runs without an authenticated
// principal. `Listener::serve` takes only a handler of `(&Authenticated, Request)`,
// and checks the Bearer token before calling it; a handler of the request alone
// does not type-check.
use corten_std::listen::{Request, Response};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;

struct Discard;

impl LogWriter for Discard {
    fn write(&mut self, record: &LogRecord) {
        let _rendered = record.render();
    }
}

pub fn open(caps: &mut Capabilities) -> Option<()> {
    let listener = caps.take_listener("app")?;
    let _never = listener.serve(|req: Request| Response::ok(req.body().to_vec()), Discard);
    None
}

fn main() {}
