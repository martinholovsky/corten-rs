//! Compile-time templates shared by every typed sink.
//!
//! A sink's text comes from a [`Template`]: a type whose associated
//! constant holds it. Associated constants are evaluated at compile time, so
//! no runtime value (a `String` built from input, or one laundered into a
//! `&'static str`) can ever become sink text. The macros (`sql!`, `html!`,
//! and the rest) define such a type for each call site from a string
//! literal. Values are passed separately and encoded by the sink.
//!
//! Placeholders are `{}`; every `{}` in a template is a placeholder.

/// A compile-time template. Implement it only through the sink macros, or
/// with a constant: the text must be known when the program is compiled.
pub trait Template {
    /// The template text, with `{}` for each value.
    const TEXT: &'static str;
}

/// Number of `{}` placeholders in `text`.
#[must_use]
pub const fn count_placeholders(text: &str) -> usize {
    let mut bytes = text.as_bytes();
    let mut n = 0usize;
    while let [first, rest @ ..] = bytes {
        if *first == b'{'
            && let [b'}', after @ ..] = rest
        {
            n = n.saturating_add(1);
            bytes = after;
            continue;
        }
        bytes = rest;
    }
    n
}

/// Splits `text` at its placeholders: `n + 1` literal pieces for `n`
/// placeholders.
#[must_use]
pub fn pieces(text: &str) -> Vec<&str> {
    text.split("{}").collect()
}

/// Counts a macro's arguments at compile time.
#[doc(hidden)]
#[macro_export]
macro_rules! __corten_count {
    ($($arg:expr),*) => { <[()]>::len(&[$($crate::__corten_unit!($arg)),*]) };
}

/// Maps any expression to `()`, for [`__corten_count`].
#[doc(hidden)]
#[macro_export]
macro_rules! __corten_unit {
    ($arg:expr) => {
        ()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_placeholders() {
        const N: usize = count_placeholders("SELECT {} FROM t WHERE id = {}");
        assert_eq!(count_placeholders(""), 0);
        assert_eq!(count_placeholders("a {} b {}"), 2);
        assert_eq!(count_placeholders("{}{}{}"), 3);
        assert_eq!(count_placeholders("{ } {x}"), 0);
        assert_eq!(N, 2);
    }

    #[test]
    fn splits_into_pieces() {
        assert_eq!(pieces("a{}b{}c"), ["a", "b", "c"]);
        assert_eq!(pieces("{}"), ["", ""]);
    }
}
