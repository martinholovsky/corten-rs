//@ expect: expected `&mut LockToken<'_, Unlocked>`, found `&mut LockToken<'_, Ledger>`
use corten_std::sync::{LockRoot, OrderedMutex};
corten_std::lock_order!(Accounts, Ledger);
fn main() {
    let accounts: OrderedMutex<Accounts, u32> = OrderedMutex::new(10);
    let ledger: OrderedMutex<Ledger, u32> = OrderedMutex::new(0);
    let Some(mut root) = LockRoot::take() else { return };
    let mut t0 = root.token();
    if let Ok((l, mut t1)) = ledger.lock(&mut t0) {
        if let Ok((a, _t2)) = accounts.lock(&mut t1) {
            println!("{} {}", *l, *a);
        }
    }
}
