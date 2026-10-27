//@ lint: corten_blocking_in_async
//@ expect: blocking call to `std::thread::sleep` inside an async body
//@ expect: blocking call to `wait_a_bit` inside an async body (it blocks through a local function)
//@ expect: blocking call to `std::sync::Mutex::<T>::lock` inside an async body
//@ count: 3
use std::sync::Mutex;
use std::time::Duration;
fn pause() {
    std::thread::sleep(Duration::from_millis(1));
}
fn wait_a_bit() {
    pause();
}
fn pure(n: u32) -> u32 {
    n.saturating_add(1)
}
async fn handler(m: &Mutex<u32>) -> u32 {
    std::thread::sleep(Duration::from_millis(1));
    wait_a_bit();
    let g = m.lock();
    pure(u32::from(g.is_ok()))
}
fn main() {
    // Not reported: blocking outside async code.
    wait_a_bit();
    let m = Mutex::new(1);
    let _pending = handler(&m);
}
