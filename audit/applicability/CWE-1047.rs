//@ compiles: safe
// CWE-1047, circular module dependency: modules a and b call each other;
// rustc accepts cycles between modules of one crate.
pub mod a {
    pub fn ping(n: u32) -> u32 {
        if n == 0 { 0 } else { super::b::pong(n - 1) }
    }
}
pub mod b {
    pub fn pong(n: u32) -> u32 {
        if n == 0 { 0 } else { super::a::ping(n - 1) }
    }
}
