//@ kind: language
//@ deps: corten-std
//@ absent
//@ expect: E0599
// CWE-276 variant: a FileMode with other bits. FileMode is an enum of three modes with
// no constructor from bits (weakest evidence: the API is absent).
use corten_std::fs::FileMode;

pub fn wide() -> FileMode {
    FileMode::from_bits(0o666)
}

fn main() {}
