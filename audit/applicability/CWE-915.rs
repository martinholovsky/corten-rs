//@ compiles: safe
// CWE-915, mass assignment. A generic "update from form" helper binds every
// known field name, including is_admin, from the request.
pub struct User {
    pub name: String,
    pub email: String,
    pub is_admin: bool,
}
pub fn update_from_form(u: &mut User, form: &[(String, String)]) {
    for (k, v) in form {
        match k.as_str() {
            "name" => u.name = v.clone(),
            "email" => u.email = v.clone(),
            "is_admin" => u.is_admin = v == "true",
            _ => {}
        }
    }
}
