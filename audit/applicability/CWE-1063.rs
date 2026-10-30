//@ rejected: cannot call non-const
// CWE-1063, creating an instance in a static block. Rust has no static
// initialiser blocks: a static's initialiser must be const-evaluable, so a
// runtime constructor is refused (E0015).
pub struct Registry {
    pub names: Vec<String>,
}
impl Registry {
    pub fn load() -> Registry {
        Registry { names: vec![String::from("default")] }
    }
}
pub static REGISTRY: Registry = Registry::load();
