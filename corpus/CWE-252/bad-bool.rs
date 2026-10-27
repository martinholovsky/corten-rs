//@ expect: corten-must-use-return
// CWE-252: ignores a status returned as bool. Only Corten's must-use-on-every-
// non-unit-return lint (corten-driver, Phase 3b) sees it.
fn store(v: u32) -> bool {
    v <= 10
}
fn main() {
    store(30);
}
