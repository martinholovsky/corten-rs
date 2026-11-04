#![forbid(unsafe_code)]
// CWE-560: a chmod-style value passed to umask, in safe Rust.
fn main() {
    let old = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o644));
    println!("umask set to 0644 (was {:o})", old.bits());
}
