//@ kind: language
//@ deps: corten-std
//@ expect: E0451
// CWE-306 handler variant: a handler that trusts a client-supplied header as the
// user's identity instead of the principal the listener authenticated.
// `Authenticated` has private fields, so a handler cannot build one from a header.
use corten_std::authz::Authenticated;
use corten_std::listen::{Request, Response};

pub fn as_user(req: &Request) -> Option<Authenticated> {
    let name = req.header("x-user")?;
    Some(Authenticated { principal: name.to_owned(), authenticator: String::from("api") })
}

pub fn handle(_who: &Authenticated, req: Request) -> Response {
    match as_user(&req) {
        Some(user) => Response::ok(user.principal().to_owned()),
        None => Response::ok(Vec::new()),
    }
}

fn main() {}
