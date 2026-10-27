//@ fake-dep: my-backtracking-regex
//@ expect: banned
// CWE-1333 bypass-hunt variant: a backtracking engine under a name the
// ban list does not know. A name-based ban cannot see it; not detected.
fn main() {
    my_backtracking_regex::stub();
}
