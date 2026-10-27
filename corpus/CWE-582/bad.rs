//@ expect: E0594
// CWE-582: a public static array whose contents can be changed.
pub static TABLE: [u32; 3] = [1, 2, 3];
fn main() {
    TABLE[0] = 9;
}
