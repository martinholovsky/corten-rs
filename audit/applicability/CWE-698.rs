//@ compiles: safe
// CWE-698, execution after redirect: the redirect is built for the
// unauthenticated user, but the function carries on and deletes anyway.
pub enum Response { Redirect(&'static str), Ok }
pub fn admin_purge(is_admin: bool, data: &mut Vec<u8>) -> Response {
    let mut resp = Response::Ok;
    if !is_admin {
        resp = Response::Redirect("/login");
    }
    data.clear();
    resp
}
