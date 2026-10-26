//@ kind: language
//@ deps: corten-std
//@ absent
//@ expect: ssi
// CWE-97: server-side includes. The prelude has no SSI interpreter.
fn main() {
    let _out = corten_std::ssi::include_virtual("/etc/passwd");
}
