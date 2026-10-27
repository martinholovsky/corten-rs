//@ expect: -F unsafe-code
// CWE-567: unsynchronised writes to shared data from two threads.
static mut HITS: u32 = 0;
fn bump() {
    unsafe { HITS = HITS.wrapping_add(1) };
}
fn main() {
    let handle = std::thread::spawn(bump);
    bump();
    println!("{:?}", handle.join());
}
