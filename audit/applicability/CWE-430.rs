//@ compiles: safe
// CWE-430, deployment of wrong handler: any extension not listed as static is
// handed to the script executor, so "upload.jpg.sh" is executed.
pub enum Handler { Static, Execute }
pub fn handler_for(path: &str) -> Handler {
    match path.rsplit('.').next() {
        Some("html" | "css" | "png") => Handler::Static,
        _ => Handler::Execute,
    }
}
