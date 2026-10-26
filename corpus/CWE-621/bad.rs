//@ expect: expected expression, found `$`
//@ absent
// CWE-621: extracts request variables into the local scope.
fn main() {
    extract($_GET);
}
