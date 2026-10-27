//@ compiles: safe
// CWE-454, external initialisation of trusted variables. The trusted
// is_admin flag is initialised from a client-supplied cookie value.
pub struct Request {
    pub cookies: Vec<(String, String)>,
}
pub fn is_admin(r: &Request) -> bool {
    r.cookies.iter().any(|(k, v)| k == "is_admin" && v == "1")
}
