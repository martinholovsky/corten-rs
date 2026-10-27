//@ expect: E0599
// CWE-572: calls a thread's run() instead of starting it. There is no run().
fn main() {
    let t = std::thread::current();
    t.run();
}
