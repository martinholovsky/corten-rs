//! Lock-order contracts (spec 4.8 and the Phase 4 roadmap).
//!
//! A program declares one total order of lock levels with
//! [`lock_order!`](crate::lock_order!). An [`OrderedMutex<L, T>`] sits at
//! level `L`, and locking it takes a [`LockToken`] for the level held now
//! and returns one for `L`. `L` must come after the held level, which the
//! type checker decides (`L: LockAfter<Held>`), so `cargo check` rejects:
//!
//! - taking locks against the declared order;
//! - taking two locks of the same level at once (no level is after itself);
//! - moving a token to another thread (it is not `Send`).
//!
//! With every lock taken in one global order, no cycle of waiting threads
//! can form, so these locks cannot deadlock each other. One check is left to
//! run time: a thread has at most one [`LockRoot`] at a time, because two
//! roots would start two unordered chains on one thread. That is the three-
//! outcome rule (spec 4.13) applied to locking.
//!
//! What this does not cover: locks outside these types (a plain
//! `std::sync::Mutex`, a database lock), waits on other things (channels,
//! joins), and lock order across processes. Deadlock stays C (spec 4.8).
//!
//! ```
//! use corten_std::sync::{LockRoot, OrderedMutex};
//!
//! corten_std::lock_order!(Accounts, Ledger);
//!
//! let accounts: OrderedMutex<Accounts, u32> = OrderedMutex::new(10);
//! let ledger: OrderedMutex<Ledger, Vec<u32>> = OrderedMutex::new(Vec::new());
//!
//! let mut root = LockRoot::take().expect("one root per thread");
//! let mut t0 = root.token();
//! let (balance, mut t1) = accounts.lock(&mut t0).expect("not poisoned");
//! let (mut entries, _t2) = ledger.lock(&mut t1).expect("not poisoned");
//! entries.push(*balance);
//! ```
//!
//! ```compile_fail
//! use corten_std::sync::{LockRoot, OrderedMutex};
//! corten_std::lock_order!(Accounts, Ledger);
//! let accounts: OrderedMutex<Accounts, u32> = OrderedMutex::new(10);
//! let ledger: OrderedMutex<Ledger, u32> = OrderedMutex::new(0);
//! let mut root = LockRoot::take().unwrap();
//! let mut t0 = root.token();
//! let (_l, mut t1) = ledger.lock(&mut t0).unwrap();
//! let _a = accounts.lock(&mut t1); // Accounts is not after Ledger
//! ```

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Mutex, MutexGuard};

/// A lock level. Declare levels with [`lock_order!`](crate::lock_order!).
pub trait LockLevel {}

/// `Self` may be locked while `Held` is the highest level held.
pub trait LockAfter<Held: LockLevel>: LockLevel {}

/// The level before any lock is held.
#[derive(Debug)]
pub enum Unlocked {}
impl LockLevel for Unlocked {}

/// `lock_order!(A, B, C)`: declares the levels `A`, `B`, `C` (empty
/// enums) in that order: `A` is taken first. Each level may be locked while
/// any earlier level, or none, is held.
#[macro_export]
macro_rules! lock_order {
    ($($level:ident),+ $(,)?) => {
        $(
            #[derive(Debug)]
            pub enum $level {}
            impl $crate::sync::LockLevel for $level {}
        )+
        $crate::__lock_after!([$crate::sync::Unlocked] $($level),+);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __lock_after {
    ([$($held:ty),*]) => {};
    ([$($held:ty),*] $next:ident $(, $rest:ident)*) => {
        $( impl $crate::sync::LockAfter<$held> for $next {} )*
        $crate::__lock_after!([$($held,)* $next] $($rest),*);
    };
}

thread_local! {
    static ROOT_TAKEN: Cell<bool> = const { Cell::new(false) };
}

/// The start of this thread's lock chain. At most one per thread at a time.
#[derive(Debug)]
pub struct LockRoot {
    // Not `Send`: the chain belongs to the thread that took it.
    thread_bound: PhantomData<*const ()>,
}

impl LockRoot {
    /// This thread's root, or `None` if the thread already holds one.
    #[must_use]
    pub fn take() -> Option<Self> {
        let taken = ROOT_TAKEN.with(|t| t.replace(true));
        (!taken).then_some(Self {
            thread_bound: PhantomData,
        })
    }

    /// A token for holding nothing. The root is borrowed while it lives, so
    /// one chain is open at a time.
    pub fn token(&mut self) -> LockToken<'_, Unlocked> {
        LockToken {
            chain: PhantomData,
            level: PhantomData,
        }
    }
}

impl Drop for LockRoot {
    fn drop(&mut self) {
        ROOT_TAKEN.with(|t| t.set(false));
    }
}

/// Proof that `L` is the highest level this thread holds. Not `Send`.
#[derive(Debug)]
pub struct LockToken<'a, L: LockLevel> {
    chain: PhantomData<(&'a mut (), *const ())>,
    level: PhantomData<fn() -> L>,
}

/// The mutex was poisoned: a thread panicked holding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poisoned;

impl fmt::Display for Poisoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("lock poisoned: a thread panicked while holding it")
    }
}

impl std::error::Error for Poisoned {}

/// A mutex at lock level `L`.
#[derive(Debug)]
pub struct OrderedMutex<L: LockLevel, T> {
    inner: Mutex<T>,
    level: PhantomData<fn() -> L>,
}

impl<L: LockLevel, T> OrderedMutex<L, T> {
    /// A mutex at level `L` holding `value`.
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            level: PhantomData,
        }
    }

    /// Locks, given the token for the level held now; returns the guard and
    /// the token for `L`. The held token stays borrowed until both are
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] if a thread panicked holding the lock.
    pub fn lock<'a, Held: LockLevel>(
        &'a self,
        _held: &'a mut LockToken<'_, Held>,
    ) -> Result<(MutexGuard<'a, T>, LockToken<'a, L>), Poisoned>
    where
        L: LockAfter<Held>,
    {
        let guard = self.inner.lock().map_err(|_| Poisoned)?;
        Ok((
            guard,
            LockToken {
                chain: PhantomData,
                level: PhantomData,
            },
        ))
    }

    /// The value, consuming the mutex.
    ///
    /// # Errors
    ///
    /// [`Poisoned`] if a thread panicked holding the lock.
    pub fn into_inner(self) -> Result<T, Poisoned> {
        self.inner.into_inner().map_err(|_| Poisoned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::lock_order!(First, Second, Third);

    #[test]
    fn locks_follow_the_declared_order_and_may_skip_levels() {
        let a: OrderedMutex<First, u32> = OrderedMutex::new(1);
        let c: OrderedMutex<Third, u32> = OrderedMutex::new(3);
        let mut root = LockRoot::take().unwrap();
        let mut t0 = root.token();
        let (ga, mut t1) = a.lock(&mut t0).unwrap();
        let (gc, _t3) = c.lock(&mut t1).unwrap();
        assert_eq!(*ga + *gc, 4);
    }

    #[test]
    fn one_root_per_thread_at_a_time() {
        let root = LockRoot::take().unwrap();
        assert!(LockRoot::take().is_none());
        drop(root);
        let again = LockRoot::take();
        assert!(again.is_some());
        // Another thread has its own.
        let other = std::thread::spawn(|| LockRoot::take().is_some())
            .join()
            .unwrap();
        assert!(other);
    }

    #[test]
    fn a_poisoned_lock_is_an_error() {
        let m = std::sync::Arc::new(OrderedMutex::<First, u32>::new(0));
        let m2 = std::sync::Arc::clone(&m);
        let joined = std::thread::spawn(move || {
            let mut root = LockRoot::take().unwrap();
            let mut t0 = root.token();
            let _g = m2.lock(&mut t0).unwrap();
            panic!("poison");
        })
        .join();
        assert!(joined.is_err(), "the thread should have panicked");
        let mut root = LockRoot::take().unwrap();
        let mut t0 = root.token();
        assert!(matches!(m.lock(&mut t0), Err(Poisoned)));
    }
}
