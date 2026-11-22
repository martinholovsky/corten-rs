//@ deps: corten-std
// The matched benign program for strategy 2's cases: a principal from the
// manifest's token authenticator, a policy check, then a read of the path
// the proof names in a `protected` directory grant; and a request handler
// served through the manifest's `listen` grant.
use corten_std::authz::{Authenticated, DirKey, Policy, Read, Token, check};
use corten_std::listen::{Request, Response};
use corten_std::log::{LogRecord, LogWriter};
use corten_std::manifest::Capabilities;
use corten_std::path::RelPath;

struct Discard;

impl LogWriter for Discard {
    fn write(&mut self, record: &LogRecord) {
        let _rendered = record.render();
    }
}

/// Each principal reads only beneath a directory named after it.
struct OwnFiles;

impl Policy<Read, DirKey> for OwnFiles {
    fn allows(&self, who: &Authenticated, key: &DirKey) -> bool {
        key.path()
            .segments()
            .next()
            .is_some_and(|first| first.as_str() == who.principal())
    }
}

pub fn serve(caps: &mut Capabilities, token: Token<'_>, path: RelPath) -> Option<Vec<u8>> {
    let auth = caps.take_token_authenticator("api")?;
    let records = caps.take_protected_dir("records")?;
    let who = auth.authenticate(token, &mut Discard).ok()?;
    let proof = check(&who, Read, records.key(path), &OwnFiles, &mut Discard).ok()?;
    records.read(proof).ok()?.read_to_end(1_048_576).ok()
}

/// The handler-level benign program: requests reach the handler through the
/// manifest's `listen` grant, which authenticates each one first, so the
/// handler answers with the principal it was given.
pub fn listen(caps: &mut Capabilities) -> Option<()> {
    let listener = caps.take_listener("app")?;
    let _never = listener.serve(
        |who: &Authenticated, req: Request| {
            Response::ok(format!("{} {}", who.principal(), req.method()))
        },
        Discard,
    );
    None
}

fn main() {}
