//@ compiles: unsafe
// CWE-1063 in unsafe Rust: an #[unsafe(link_section)] constructor runs before
// main and builds the instance at load time, like a Java static block.
use std::sync::OnceLock;
pub struct Registry {
    pub names: Vec<String>,
}
pub static REGISTRY: OnceLock<Registry> = OnceLock::new();
extern "C" fn init() {
    let _ = REGISTRY.set(Registry { names: vec![String::from("default")] });
}
#[used]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
#[cfg_attr(not(target_os = "macos"), unsafe(link_section = ".init_array"))]
static CTOR: extern "C" fn() = init;
