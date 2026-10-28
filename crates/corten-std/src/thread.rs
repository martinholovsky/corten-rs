//! Threads whose panics cannot be caught (spec 4.7; CWE-396).
//!
//! `std::thread::JoinHandle::join` returns a child's panic as an `Err`,
//! which works as a catch-all handler: the caller inspects or drops the
//! failure and carries on. The checker bans it, with its scoped twin, in
//! application code. [`spawn`] and [`Handle::join`] take their place: `join`
//! returns the child's value, and if the child panicked, `join` panics too.
//! A component that must survive a failed child runs under
//! `corten-runtime`'s supervisor instead, which restarts it by policy.
//!
//! ```
//! let handle = corten_std::thread::spawn(|| 6 * 7);
//! assert_eq!(handle.join(), 42);
//! ```
//!
//! ```should_panic
//! let handle = corten_std::thread::spawn(|| -> u32 { panic!("boom") });
//! let _never = handle.join(); // panics: the child's failure propagates
//! ```

use std::sync::mpsc;

/// A running thread. Dropping it detaches the thread, as with `std`.
#[derive(Debug)]
#[must_use = "a handle that is never joined detaches its thread"]
pub struct Handle<T> {
    result: mpsc::Receiver<T>,
}

/// Starts `f` on a new thread.
pub fn spawn<T, F>(f: F) -> Handle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    // The std handle is dropped, detaching the thread: its result comes
    // back through the channel instead, so the panic is never caught.
    drop(std::thread::spawn(move || {
        // A send fails only when the Handle was dropped; nobody is waiting.
        let _unclaimed = tx.send(f()).is_err();
    }));
    Handle { result: rx }
}

impl<T> Handle<T> {
    /// Waits for the thread and returns its value.
    ///
    /// # Panics
    ///
    /// If the thread panicked. Its failure is not returned as a value, so it
    /// cannot be swallowed.
    #[must_use]
    pub fn join(self) -> T {
        match self.result.recv() {
            Ok(value) => value,
            // The sender is dropped without sending only while the child
            // unwinds from a panic.
            Err(mpsc::RecvError) => std::panic::resume_unwind(Box::new(
                "a thread joined through corten_std::thread panicked",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_returns_the_value() {
        assert_eq!(spawn(|| 41 + 1).join(), 42);
    }

    #[test]
    fn a_child_panic_propagates_to_the_joiner() {
        // The test harness runs each test on its own thread and reports a
        // panic as a failure; a child-side `std::thread` here observes it.
        let outer = std::thread::spawn(|| {
            spawn(|| -> u32 { std::panic::resume_unwind(Box::new("boom")) }).join()
        });
        assert!(outer.join().is_err());
    }
}
