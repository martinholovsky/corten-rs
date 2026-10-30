//@ compiles: safe
// CWE-1099, inconsistent naming: camelCase next to snake_case; rustc only
// warns (non_snake_case).
#[allow(non_snake_case)]
pub fn getUser(id: u32) -> u32 {
    id
}
pub fn set_user(id: u32) -> u32 {
    id
}
