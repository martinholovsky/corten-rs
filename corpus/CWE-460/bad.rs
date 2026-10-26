//@ expect: expected
//@ absent
// CWE-460: cleanup skipped when an exception is thrown.
fn main() {
    try {
        throw Error;
    } finally {
        println!("cleanup");
    }
}
