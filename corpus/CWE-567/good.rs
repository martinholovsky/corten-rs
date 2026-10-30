//@ deps: corten-std
use std::sync::atomic::{AtomicU32, Ordering};
static HITS: AtomicU32 = AtomicU32::new(0);
fn main() {
    let handle = corten_std::thread::spawn(|| HITS.fetch_add(1, Ordering::Relaxed));
    let _prev = HITS.fetch_add(1, Ordering::Relaxed);
    println!("{:?} {}", handle.join(), HITS.load(Ordering::Relaxed));
}
