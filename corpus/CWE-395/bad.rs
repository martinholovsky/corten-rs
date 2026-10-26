//@ expect: cannot follow a `try` block
//@ absent
// CWE-395: catches NullPointerException to detect a null dereference.
fn main() {
    try {
        println!("x");
    } catch (NullPointerException e) {
        println!("null");
    }
}
