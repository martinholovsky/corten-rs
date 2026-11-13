//@ kind: language
//@ deps: corten-std
//@ expect: private
// CWE-288 variant: a protected directory value made without the manifest.
// `ProtectedDir::new` is not public.
use corten_std::authz::ProtectedDir;
use corten_std::fs::DirCap;

pub fn wrap(dir: DirCap) -> ProtectedDir {
    ProtectedDir::new(String::from("records"), dir)
}

fn main() {}
