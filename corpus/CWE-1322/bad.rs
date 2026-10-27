//@ expect: blocking
// CWE-1322: blocks inside a non-blocking async context. Needs the
// blocking effect (not implemented).
async fn handle(n: u32) -> u32 {
    std::thread::sleep(std::time::Duration::from_millis(10));
    n
}
fn main() {
    let _pending = handle(1);
}
