//! A supervision tree (spec section 5, P2 "Supervision tree"; Phase 3).
//!
//! In Corten a panic ends a component, not the service: bounds and
//! arithmetic failures panic, and without supervision that turns every such
//! bug into a denial of service. A [`Supervisor`] runs each child in its own
//! thread, restarts it according to its [`Restart`] policy
//! (Erlang/OTP `one_for_one`), and gives up after a set number of restarts,
//! telling every child to stop.
//!
//! Children cooperate in shutdown: each receives a [`Shutdown`] token and
//! should return when it is set. A thread cannot be killed safely, so a child
//! that ignores the token keeps running until it returns.
//!
//! The crate passes the Corten profile: no `unsafe`, no `catch_unwind` (a
//! panic is contained by running each attempt on its own thread and
//! observing its join result), no clock (restart intensity is counted, not
//! timed).
//!
//! ```
//! use corten_runtime::{ChildSpec, Restart, Supervisor};
//!
//! let report = Supervisor::new(3)
//!     .child(ChildSpec::new("worker", Restart::Transient, |_stop| Ok(())))
//!     .run();
//! assert!(!report.gave_up);
//! ```

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;

/// When a child is restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// Always, even after a normal return.
    Permanent,
    /// After a panic or an error, not after a normal return.
    Transient,
    /// Never.
    Temporary,
}

/// How one run of a child ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// Returned `Ok(())`.
    Normal,
    /// Returned an error.
    Error(String),
    /// Panicked; the payload, when it was a string.
    Panic(String),
    /// Was not restarted because the supervisor gave up or shut down.
    Stopped,
}

/// A shutdown request shared by the supervisor and its children.
#[derive(Debug, Clone, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    /// Whether the supervisor asked children to stop.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

type Body = dyn Fn(&Shutdown) -> Result<(), String> + Send + Sync;

/// A child: its name, restart policy, and body.
pub struct ChildSpec {
    name: &'static str,
    restart: Restart,
    body: Arc<Body>,
}

impl ChildSpec {
    /// A child running `body` under `restart`.
    pub fn new(
        name: &'static str,
        restart: Restart,
        body: impl Fn(&Shutdown) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            restart,
            body: Arc::new(body),
        }
    }
}

impl fmt::Debug for ChildSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildSpec")
            .field("name", &self.name)
            .field("restart", &self.restart)
            .finish_non_exhaustive()
    }
}

/// What happened to one child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildReport {
    /// The child's name.
    pub name: &'static str,
    /// How many times it was restarted.
    pub restarts: u32,
    /// How its last run ended.
    pub last_exit: Exit,
}

/// The outcome of [`Supervisor::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// One entry per child, in the order they were added.
    pub children: Vec<ChildReport>,
    /// Whether the restart limit was reached and the supervisor stopped.
    pub gave_up: bool,
}

/// Supervises children; see the crate documentation.
#[derive(Debug)]
pub struct Supervisor {
    children: Vec<ChildSpec>,
    max_restarts: u32,
}

impl Supervisor {
    /// A supervisor that gives up after `max_restarts` restarts in total.
    #[must_use]
    pub fn new(max_restarts: u32) -> Self {
        Self {
            children: Vec::new(),
            max_restarts,
        }
    }

    /// Adds a child.
    #[must_use]
    pub fn child(mut self, spec: ChildSpec) -> Self {
        self.children.push(spec);
        self
    }

    /// Runs every child until each has stopped for good, and reports.
    #[must_use]
    pub fn run(self) -> Report {
        let shutdown = Shutdown::default();
        let restarts = Arc::new(AtomicU32::new(0));
        let max = self.max_restarts;
        let monitors: Vec<_> = self
            .children
            .into_iter()
            .map(|spec| {
                let shutdown = shutdown.clone();
                let restarts = Arc::clone(&restarts);
                thread::spawn(move || supervise(&spec, &shutdown, &restarts, max))
            })
            .collect();
        let children: Vec<ChildReport> = monitors
            .into_iter()
            .map(|m| {
                m.join().unwrap_or_else(|_| ChildReport {
                    name: "monitor",
                    restarts: 0,
                    last_exit: Exit::Panic("supervisor monitor failed".to_owned()),
                })
            })
            .collect();
        Report {
            children,
            gave_up: restarts.load(Ordering::SeqCst) > max,
        }
    }
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

/// Runs one child's attempts on fresh threads; a panic ends only its
/// attempt's thread.
fn supervise(spec: &ChildSpec, shutdown: &Shutdown, restarts: &AtomicU32, max: u32) -> ChildReport {
    let mut own_restarts = 0u32;
    loop {
        let body = Arc::clone(&spec.body);
        let token = shutdown.clone();
        let exit = match thread::spawn(move || body(&token)).join() {
            Ok(Ok(())) => Exit::Normal,
            Ok(Err(e)) => Exit::Error(e),
            Err(payload) => Exit::Panic(panic_text(payload.as_ref())),
        };
        let wanted = match spec.restart {
            Restart::Permanent => true,
            Restart::Transient => exit != Exit::Normal,
            Restart::Temporary => false,
        };
        if !wanted || shutdown.requested() {
            return ChildReport {
                name: spec.name,
                restarts: own_restarts,
                last_exit: exit,
            };
        }
        let total = restarts.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        if total > max {
            // Restart intensity exceeded: stop everything.
            shutdown.request();
            return ChildReport {
                name: spec.name,
                restarts: own_restarts,
                last_exit: exit,
            };
        }
        own_restarts = own_restarts.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_panicking_child_is_restarted_while_its_sibling_keeps_working() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        let work_done = Arc::new(AtomicUsize::new(0));
        let done = Arc::clone(&work_done);
        let report = Supervisor::new(5)
            .child(ChildSpec::new("flaky", Restart::Transient, move |_| {
                let n = seen.fetch_add(1, Ordering::SeqCst);
                assert!(n >= 2, "simulated bounds failure on attempt {n}");
                Ok(())
            }))
            .child(ChildSpec::new("steady", Restart::Transient, move |_| {
                done.fetch_add(10, Ordering::SeqCst);
                Ok(())
            }))
            .run();
        assert!(!report.gave_up);
        assert_eq!(report.children[0].restarts, 2);
        assert_eq!(report.children[0].last_exit, Exit::Normal);
        assert_eq!(report.children[1].restarts, 0);
        assert_eq!(work_done.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn restart_intensity_limit_stops_everything() {
        let report = Supervisor::new(2)
            .child(ChildSpec::new("always-fails", Restart::Permanent, |_| {
                Err("broken".to_owned())
            }))
            .child(ChildSpec::new("polite", Restart::Temporary, |stop| {
                while !stop.requested() {
                    thread::yield_now();
                }
                Ok(())
            }))
            .run();
        assert!(report.gave_up);
        assert_eq!(
            report.children[0].last_exit,
            Exit::Error("broken".to_owned())
        );
        assert_eq!(report.children[1].last_exit, Exit::Normal);
    }

    #[test]
    fn temporary_child_is_not_restarted() {
        let report = Supervisor::new(5)
            .child(ChildSpec::new("once", Restart::Temporary, |_| {
                Err("x".to_owned())
            }))
            .run();
        assert_eq!(report.children[0].restarts, 0);
        assert!(!report.gave_up);
    }

    #[test]
    fn panic_payload_is_reported() {
        let report = Supervisor::new(0)
            .child(ChildSpec::new("boom", Restart::Temporary, |_| {
                let v: Vec<u8> = Vec::new();
                // An out-of-bounds index: the C-bucket runtime check that
                // supervision turns from a crash into a contained failure.
                let x = v[3];
                Err(format!("unreachable {x}"))
            }))
            .run();
        let Exit::Panic(text) = &report.children[0].last_exit else {
            panic!("expected a panic, got {:?}", report.children[0].last_exit);
        };
        assert!(text.contains("index out of bounds"), "{text}");
    }
}
