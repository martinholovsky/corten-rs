//@ lint: corten_unsafe_from_macro
//@ count: 0
// Standard-library macros that use `unsafe` internally are part of the TCB.
use std::cell::Cell;
thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}
fn main() {
    let v = vec![1, 2, 3];
    let pinned = std::pin::pin!(async { 1 });
    DEPTH.with(|d| d.set(1));
    println!("{v:?} {}", format!("{:?}", pinned.as_ref().get_ref() as *const _ as usize > 0));
}
