//@ expect: E0268
// CWE-705: a jump out of the scope it belongs to.
fn main() {
    let i = 2;
    if i == 2 {
        break;
    }
}
