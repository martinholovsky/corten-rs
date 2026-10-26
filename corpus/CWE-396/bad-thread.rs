//@ expect: -F clippy::disallowed-methods
// CWE-396 through a thread: join() returns the panic as an Err, which works
// as a catch-all handler. Found by the Phase 1 bypass hunt; not detected.
fn main() {
    let result = std::thread::spawn(|| -> u32 { panic!("boom") }).join();
    println!("{}", result.is_err());
}
