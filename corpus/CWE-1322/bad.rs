//@ expect: blocking
// CWE-1322: blocks inside a non-blocking async context. Caught by the
// inferred blocking effect (corten-driver, Phase 3b).
async fn handle(n: u32) -> u32 {
    std::thread::sleep(std::time::Duration::from_millis(10));
    n
}
fn main() {
    let _pending = handle(1);
}
