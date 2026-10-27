//@ good
use corten_std::sync::{LockRoot, OrderedMutex};
corten_std::lock_order!(Accounts, Ledger, Audit);
fn main() {
    let accounts: OrderedMutex<Accounts, u32> = OrderedMutex::new(10);
    let audit: OrderedMutex<Audit, Vec<u32>> = OrderedMutex::new(Vec::new());
    let Some(mut root) = LockRoot::take() else { return };
    let mut t0 = root.token();
    if let Ok((a, mut t1)) = accounts.lock(&mut t0) {
        if let Ok((mut log, _t3)) = audit.lock(&mut t1) {
            log.push(*a);
            println!("{}", log.len());
        }
    }
}
