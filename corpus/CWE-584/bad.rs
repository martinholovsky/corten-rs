//@ expect: expected
//@ absent
// CWE-584: return inside a finally block.
fn f() -> u32 {
    try {
        return 1;
    } finally {
        return 2;
    }
}
fn main() {}
