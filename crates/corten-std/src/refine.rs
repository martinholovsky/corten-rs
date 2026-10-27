//! Decidable refinements with the three-outcome rule (spec 4.13; Phase 4).
//!
//! Every obligation has exactly one of three outcomes:
//!
//! 1. **Proved statically.** A literal is checked by a plain `const` item,
//!    which `cargo check` evaluates, so `cargo corten check` sees it:
//!    [`bounded!`](crate::bounded!).
//! 2. **Lowered to a mandatory runtime check** that returns a `Result` the
//!    caller must handle: [`Bounded::new`], [`Bounded::checked_add`],
//!    [`copy_into`].
//! 3. **Rejected at compile time** when the static check fails: the
//!    `const` item does not evaluate.
//!
//! Nothing is lowered to an optimizer assumption: the crate has no `unsafe`,
//! so it cannot call `assume` or `unreachable_unchecked`.
//!
//! The fragment is integer ranges and lengths. Range arithmetic that
//! propagates bounds through types (`Bounded<0, 10> + Bounded<0, 5>` as
//! `Bounded<0, 15>`) needs `generic_const_exprs`, which stable Rust lacks, so
//! arithmetic is a runtime check.
//!
//! ```
//! use corten_std::refine::{Bounded, OutOfRange};
//!
//! type Percent = Bounded<0, 100>;
//! let p: Percent = corten_std::bounded!(0, 100, 42); // proved
//! assert_eq!(p.get(), 42);
//! assert_eq!(Percent::new(101), Err(OutOfRange { value: 101, min: 0, max: 100 })); // checked
//! assert!(p.checked_add(60).is_err());
//! ```
//!
//! ```compile_fail
//! // Rejected: 101 is outside 0..=100.
//! let _p = corten_std::bounded!(0, 100, 101);
//! ```

use std::fmt;

/// An `i64` known to lie in `MIN..=MAX`. The field is private: a value comes
/// from [`bounded!`](crate::bounded!) (proved) or [`Bounded::new`] (checked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bounded<const MIN: i64, const MAX: i64>(i64);

/// A value outside a [`Bounded`] range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfRange {
    /// The value that was refused, if it fit in an `i64`.
    pub value: i64,
    /// The range's lower bound.
    pub min: i64,
    /// The range's upper bound.
    pub max: i64,
}

impl fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is outside {}..={}", self.value, self.min, self.max)
    }
}

impl std::error::Error for OutOfRange {}

impl<const MIN: i64, const MAX: i64> Bounded<MIN, MAX> {
    /// The runtime check: `Ok` if `MIN <= value <= MAX`.
    ///
    /// # Errors
    ///
    /// [`OutOfRange`] otherwise.
    pub const fn new(value: i64) -> Result<Self, OutOfRange> {
        if MIN <= value && value <= MAX {
            Ok(Self(value))
        } else {
            Err(OutOfRange {
                value,
                min: MIN,
                max: MAX,
            })
        }
    }

    /// The value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// `self + rhs`, checked against the range (and against `i64`).
    ///
    /// # Errors
    ///
    /// [`OutOfRange`] if the sum leaves the range or overflows `i64`.
    pub const fn checked_add(self, rhs: i64) -> Result<Self, OutOfRange> {
        match self.0.checked_add(rhs) {
            Some(sum) => Self::new(sum),
            None => Err(OutOfRange {
                value: if rhs > 0 { i64::MAX } else { i64::MIN },
                min: MIN,
                max: MAX,
            }),
        }
    }

    /// `self - rhs`, checked as [`Bounded::checked_add`].
    ///
    /// # Errors
    ///
    /// [`OutOfRange`] if the difference leaves the range or overflows `i64`.
    pub const fn checked_sub(self, rhs: i64) -> Result<Self, OutOfRange> {
        match self.0.checked_sub(rhs) {
            Some(diff) => Self::new(diff),
            None => Err(OutOfRange {
                value: if rhs > 0 { i64::MIN } else { i64::MAX },
                min: MIN,
                max: MAX,
            }),
        }
    }
}

/// `bounded!(MIN, MAX, VALUE)`: a [`Bounded<MIN, MAX>`] from literals,
/// proved by evaluating [`Bounded::new`] in a `const` item, which
/// `cargo check` evaluates. Out of range, it does not compile. There is no
/// unchecked constructor to call instead.
#[macro_export]
macro_rules! bounded {
    ($min:literal, $max:literal, $value:literal) => {{
        const PROVED: $crate::refine::Bounded<$min, $max> =
            match $crate::refine::Bounded::<$min, $max>::new($value) {
                Ok(v) => v,
                Err(_) => panic!("bounded!: the value is outside the range"),
            };
        PROVED
    }};
}

/// A destination too short for its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthError {
    /// Bytes to copy.
    pub needed: usize,
    /// Bytes available.
    pub available: usize,
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "destination holds {} bytes, source has {}",
            self.available, self.needed
        )
    }
}

impl std::error::Error for LengthError {}

/// Copies `src` into the start of `dst`: the obligation
/// `dst.len() >= src.len()` lowered to a runtime check (spec 4.13's
/// `copy` example).
///
/// # Errors
///
/// [`LengthError`] if `dst` is shorter than `src`; `dst` is untouched.
pub fn copy_into(src: &[u8], dst: &mut [u8]) -> Result<(), LengthError> {
    let length_error = LengthError {
        needed: src.len(),
        available: dst.len(),
    };
    let target = dst.get_mut(..src.len()).ok_or(length_error)?;
    target.copy_from_slice(src);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_is_proved_and_runtime_values_are_checked() {
        let p: Bounded<0, 100> = crate::bounded!(0, 100, 100);
        assert_eq!(p.get(), 100);
        assert_eq!(Bounded::<0, 100>::new(0).map(Bounded::get), Ok(0));
        assert_eq!(
            Bounded::<0, 100>::new(-1),
            Err(OutOfRange {
                value: -1,
                min: 0,
                max: 100
            })
        );
        assert!(Bounded::<0, 100>::new(101).is_err());
    }

    #[test]
    fn arithmetic_is_checked_against_the_range_and_i64() {
        let p: Bounded<0, 100> = crate::bounded!(0, 100, 90);
        assert_eq!(p.checked_add(10).map(Bounded::get), Ok(100));
        assert!(p.checked_add(11).is_err());
        assert!(p.checked_sub(91).is_err());
        let wide = Bounded::<{ i64::MIN }, { i64::MAX }>::new(i64::MAX).unwrap();
        assert!(wide.checked_add(1).is_err());
    }

    #[test]
    fn copy_checks_the_length_and_leaves_dst_alone_on_error() {
        let mut dst = [0u8; 3];
        assert_eq!(copy_into(&[1, 2], &mut dst), Ok(()));
        assert_eq!(dst, [1, 2, 0]);
        assert_eq!(
            copy_into(&[9, 9, 9, 9], &mut dst),
            Err(LengthError {
                needed: 4,
                available: 3
            })
        );
        assert_eq!(dst, [1, 2, 0]);
    }
}
