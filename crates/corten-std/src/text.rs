//! `TextMessage` and `text!` (spec 4.5, CWE-1336).
//!
//! A text template is fixed at compile time and values are inserted as
//! data. Nothing is ever evaluated, so a value like `{{7*7}}` stays text:
//! there is no server-side template engine to inject into.
//!
//! ```
//! let name = "{{ config.__class__ }}";
//! let m = corten_std::text!("Hello {}, welcome.", name);
//! assert_eq!(m.as_str(), "Hello {{ config.__class__ }}, welcome.");
//! ```

use crate::template::{Template, count_placeholders, pieces};

/// Text built from a compile-time template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMessage(String);

impl TextMessage {
    /// Fills `T::TEXT` with `values`. Use [`text!`](crate::text!).
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(values: [String; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "text!: the number of placeholders differs from the number of values"
            );
        }
        let mut out = String::with_capacity(T::TEXT.len());
        let mut values = values.into_iter();
        for (index, piece) in (0usize..).zip(pieces(T::TEXT)) {
            if index > 0
                && let Some(v) = values.next()
            {
                out.push_str(&v);
            }
            out.push_str(piece);
        }
        Self(out)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Builds a [`TextMessage`] from a string literal and its values.
#[macro_export]
macro_rules! text {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "text!: the number of placeholders differs from the number of values");
        struct CortenTextTemplate;
        impl $crate::template::Template for CortenTextTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::text::TextMessage::from_template::<CortenTextTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$(::std::string::ToString::to_string(&$arg)),*],
        )
    }};
}

/// What a message channel (mail, chat, SMS) implements. It accepts only a
/// [`TextMessage`].
pub trait TextSender {
    /// The channel's error.
    type Error;
    /// Sends `message`.
    ///
    /// # Errors
    ///
    /// The channel's error.
    fn send(&mut self, message: &TextMessage) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn values_are_not_reparsed() {
        let m = crate::text!("{} and {}", "{}", "x");
        assert_eq!(m.as_str(), "{} and x");
    }
}
