//! Confidentiality labels checked at the sinks (spec 4.9 and P1 "flow-
//! sensitive labels"; Phase 4).
//!
//! A [`Labeled<T, L>`] holds a value at level `L`: [`Public`] <
//! [`Internal`] < [`Confidential`] < [`Secret`]. The rules, all checked by
//! the type checker, so `cargo check` sees them:
//!
//! - **No way out above `Public`.** Only `Labeled<T, Public>` has
//!   [`into_inner`](Labeled::into_inner). `Labeled` implements neither
//!   `Display` nor `Debug` with its contents, so the sink macros (`html!`,
//!   `log_record!`, `sql!` and the rest), which format their arguments,
//!   refuse it at compile time: a label is checked at write, log, respond
//!   and serialize because those all go through a sink.
//! - **Raising is free.** [`relabel`](Labeled::relabel) moves to any level
//!   at least as high.
//! - **Propagation.** [`map`](Labeled::map) keeps the level, and
//!   [`join`](Labeled::join) gives the higher of two. Both take `fn`
//!   pointers, which cannot capture a sink, so the value cannot leave
//!   through the closure into a writer the caller holds.
//! - **Declassification** to `Public` needs a [`DeclassifyCap`], which only
//!   the signed capability manifest grants (`declassify NAME`), and is
//!   recorded through a [`LogWriter`] before the value is released.
//!
//! What this does not do: a `fn` can still reach ambient output the profile
//! allows (standard output, panics), so labels check stated flows rather
//! than prove non-interference; levels are a fixed chain, without the
//! spec's principal sets; and labels are per value, not flow-sensitive
//! across control flow. These flows stay C (spec 6).
//!
//! ```
//! use corten_std::label::{Labeled, Public, Secret};
//!
//! let salary: Labeled<u32, Secret> = Labeled::new(91_000);
//! let band = salary.map(|s| if s > 90_000 { "high" } else { "normal" });
//! // `band` is still Secret: only a declassification can release it.
//! let shown: Labeled<&str, Public> = Labeled::new("hello");
//! assert_eq!(shown.into_inner(), "hello");
//! # let _ = band;
//! ```
//!
//! ```compile_fail
//! use corten_std::label::{Labeled, Secret};
//! let salary: Labeled<u32, Secret> = Labeled::new(91_000);
//! let _leak = salary.into_inner(); // no such method above Public
//! ```

use std::fmt;
use std::marker::PhantomData;

use crate::log::LogWriter;

mod sealed {
    pub trait Sealed {}
}

/// A confidentiality level. Sealed: the four below are the lattice.
pub trait Level: sealed::Sealed {
    /// The level's name, as recorded on declassification.
    const NAME: &'static str;
}

/// `Self` may flow to `To`: `To` is at least as high.
pub trait FlowsTo<To: Level>: Level {}

/// The higher of `Self` and `Other`.
pub trait Join<Other: Level>: Level {
    /// The result's level.
    type Out: Level;
}

macro_rules! levels {
    ($($name:ident),*) => {$(
        #[doc = concat!("The `", stringify!($name), "` level.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {}
        impl sealed::Sealed for $name {}
        impl Level for $name {
            const NAME: &'static str = stringify!($name);
        }
    )*};
}
levels!(Public, Internal, Confidential, Secret);

/// `flows!(A => B, C, ...)`: `A` flows to each listed level.
macro_rules! flows {
    ($($from:ident => $($to:ident),*;)*) => {$($(
        impl FlowsTo<$to> for $from {}
    )*)*};
}
flows! {
    Public => Public, Internal, Confidential, Secret;
    Internal => Internal, Confidential, Secret;
    Confidential => Confidential, Secret;
    Secret => Secret;
}

/// `joins!(A + B = C; ...)`: the join table, both orders.
macro_rules! joins {
    ($($a:ident + $b:ident = $out:ident;)*) => {$(
        impl Join<$b> for $a { type Out = $out; }
    )*};
}
joins! {
    Public + Public = Public; Public + Internal = Internal;
    Public + Confidential = Confidential; Public + Secret = Secret;
    Internal + Public = Internal; Internal + Internal = Internal;
    Internal + Confidential = Confidential; Internal + Secret = Secret;
    Confidential + Public = Confidential; Confidential + Internal = Confidential;
    Confidential + Confidential = Confidential; Confidential + Secret = Secret;
    Secret + Public = Secret; Secret + Internal = Secret;
    Secret + Confidential = Secret; Secret + Secret = Secret;
}

/// A value at confidentiality level `L`.
pub struct Labeled<T, L: Level> {
    value: T,
    level: PhantomData<L>,
}

impl<T, L: Level> fmt::Debug for Labeled<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Labeled<{}>(..)", L::NAME)
    }
}

impl<T, L: Level> Labeled<T, L> {
    /// Labels `value` at `L`. Labelling is always allowed: it can only
    /// restrict where the value goes.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            value,
            level: PhantomData,
        }
    }

    /// The same value at a level at least as high.
    #[must_use]
    pub fn relabel<To: Level>(self) -> Labeled<T, To>
    where
        L: FlowsTo<To>,
    {
        Labeled::new(self.value)
    }

    /// Transforms the value; the result keeps the label. `f` is a `fn`
    /// pointer, so it captures nothing to leak through.
    #[must_use]
    pub fn map<U>(self, f: fn(T) -> U) -> Labeled<U, L> {
        Labeled::new(f(self.value))
    }

    /// Combines two labelled values; the result has the higher label.
    #[must_use]
    pub fn join<U, M: Level, V>(
        self,
        other: Labeled<U, M>,
        f: fn(T, U) -> V,
    ) -> Labeled<V, <L as Join<M>>::Out>
    where
        L: Join<M>,
    {
        Labeled::new(f(self.value, other.value))
    }

    /// Releases the value as `Public`, after writing a `declassify` record
    /// naming the capability, the level it came from and `reason` to `log`.
    /// `reason` is a literal, so the record cannot carry the value itself.
    #[must_use]
    pub fn declassify(
        self,
        cap: &DeclassifyCap,
        log: &mut dyn LogWriter,
        reason: &'static str,
    ) -> Labeled<T, Public> {
        log.write(&crate::log_record!(
            "declassify",
            cap = cap.name,
            from = L::NAME,
            reason = reason
        ));
        Labeled::new(self.value)
    }
}

impl<T> Labeled<T, Public> {
    /// The value. Only `Public` values can be taken out.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// The right to declassify, granted by the signed manifest's
/// `declassify NAME` line and taken once with
/// [`Capabilities::take_declassify`](crate::manifest::Capabilities::take_declassify).
#[derive(Debug, PartialEq, Eq)]
pub struct DeclassifyCap {
    name: String,
}

impl DeclassifyCap {
    pub(crate) const fn new(name: String) -> Self {
        Self { name }
    }

    /// The grant's name, as recorded.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogRecord;

    #[derive(Default)]
    struct Recorder(Vec<String>);
    impl LogWriter for Recorder {
        fn write(&mut self, record: &LogRecord) {
            self.0.push(record.render());
        }
    }

    #[test]
    fn labels_propagate_and_join_upward() {
        let low: Labeled<u32, Internal> = Labeled::new(2);
        let high: Labeled<u32, Confidential> = Labeled::new(3);
        let joined: Labeled<u32, Confidential> = low.join(high, u32::saturating_add);
        let raised: Labeled<u32, Secret> = joined.relabel();
        assert_eq!(format!("{raised:?}"), "Labeled<Secret>(..)");
        let open: Labeled<u32, Public> = Labeled::new(5);
        let doubled: Labeled<u32, Public> = open.map(|x| x.saturating_mul(2));
        assert_eq!(doubled.into_inner(), 10);
    }

    #[test]
    fn declassify_records_before_release() {
        let cap = DeclassifyCap::new("report".to_owned());
        let mut log = Recorder::default();
        let secret: Labeled<&str, Secret> = Labeled::new("s3cr3t");
        let public = secret.declassify(&cap, &mut log, "annual report total");
        assert_eq!(public.into_inner(), "s3cr3t");
        assert_eq!(log.0.len(), 1);
        let line = log.0.first().map_or("", String::as_str);
        assert!(line.contains("declassify"), "{line}");
        assert!(line.contains("report") && line.contains("Secret"), "{line}");
        assert!(!line.contains("s3cr3t"), "{line}");
    }
}
