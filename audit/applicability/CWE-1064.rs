//@ compiles: safe
// CWE-1064, excessive parameters: rustc accepts any arity (clippy only
// lints above seven).
#[allow(clippy::too_many_arguments)]
pub fn create_user(
    a: &str, b: &str, c: &str, d: &str, e: u32, f: u32, g: bool, h: bool, i: bool, j: u64,
) -> usize {
    a.len() + b.len() + c.len() + d.len() + (e + f) as usize + (g && h && i) as usize + j as usize
}
