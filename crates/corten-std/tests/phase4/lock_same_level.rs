//@ expect: expected `&mut LockToken<'_, Unlocked>`, found `&mut LockToken<'_, Accounts>`
use corten_std::sync::{LockRoot, OrderedMutex};
corten_std::lock_order!(Accounts, Ledger);
fn main() {
    let alice: OrderedMutex<Accounts, u32> = OrderedMutex::new(10);
    let bob: OrderedMutex<Accounts, u32> = OrderedMutex::new(20);
    let Some(mut root) = LockRoot::take() else { return };
    let mut t0 = root.token();
    if let Ok((a, mut t1)) = alice.lock(&mut t0) {
        if let Ok((b, _t2)) = bob.lock(&mut t1) {
            println!("{} {}", *a, *b);
        }
    }
}
