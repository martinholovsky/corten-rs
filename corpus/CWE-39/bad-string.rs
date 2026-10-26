//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// The prelude has no string-path open: a String is not a RelPath.
use corten_std::fs::{DirCap, OpenMode};

pub fn read_upload(uploads: &DirCap, name: String) -> bool {
    uploads.open_file(&name, OpenMode::Read).is_ok()
}

fn main() {}
