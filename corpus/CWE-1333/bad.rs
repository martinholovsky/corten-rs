//@ fake-dep: fancy-regex
//@ expect: banned: backtracking regex engine
// CWE-1333: depends on a backtracking regex engine (stubbed by name).
fn main() {
    fancy_regex::stub();
}
