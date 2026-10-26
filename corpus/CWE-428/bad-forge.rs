//@ kind: language
//@ deps: corten-std
//@ expect: private
// A ProcessInvocation cannot name a program the manifest did not grant.
fn main() {
    let job = corten_std::process::ProcessInvocation {
        program: std::path::PathBuf::from("/bin/sh"),
        argv: vec![String::from("-c")],
    };
    println!("{job:?}");
}
