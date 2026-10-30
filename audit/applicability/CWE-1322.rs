//@ compiles: safe
// CWE-1322, blocking code in a non-blocking context: an async handler calls
// std's blocking sleep and file read, stalling the executor thread.
pub async fn handle(path: &str) -> Vec<u8> {
    std::thread::sleep(std::time::Duration::from_secs(1));
    std::fs::read(path).unwrap_or_default()
}
