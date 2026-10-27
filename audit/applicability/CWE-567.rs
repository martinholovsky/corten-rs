//@ compiles: unsafe
// CWE-567, unsynchronized access to shared data: two threads increment a
// `static mut` with no lock (a data race).
static mut HITS: u64 = 0;
pub fn count() {
    let t = std::thread::spawn(|| unsafe { HITS += 1 });
    unsafe { HITS += 1 };
    let _ = t.join();
}
