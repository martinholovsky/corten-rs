// Matched benign program: the event loop never blocks.
async fn handle(n: u32) -> u32 {
    n
}
fn main() {
    let _pending = handle(1);
}
