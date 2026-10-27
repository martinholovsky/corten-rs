//! `SqlQuery` and `sql!` (spec 4.5, CWE-89, 943, 564).
//!
//! The query text is a compile-time template; every value is a bind
//! parameter, never part of the text. There is no constructor from a runtime
//! string.
//!
//! ```
//! use corten_std::sql;
//! use corten_std::sql::Placeholder;
//! let id = 42;
//! let q = sql!("SELECT name FROM users WHERE id = {}", id);
//! assert_eq!(q.text(Placeholder::Dollar), "SELECT name FROM users WHERE id = $1");
//! ```
//!
//! A placeholder inside a quoted literal is rejected at compile time:
//!
//! ```compile_fail
//! let name = "x";
//! let _q = corten_std::sql!("SELECT 1 FROM t WHERE name = '{}'", name);
//! ```

use crate::template::{Template, count_placeholders, pieces};

/// A bind parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    /// SQL NULL.
    Null,
    /// A boolean.
    Bool(bool),
    /// A 64-bit signed integer.
    Int(i64),
    /// Text.
    Text(String),
    /// Bytes.
    Bytes(Vec<u8>),
}

macro_rules! int_from {
    ($($t:ty),*) => {$(
        impl From<$t> for SqlValue {
            fn from(v: $t) -> Self {
                Self::Int(i64::from(v))
            }
        }
    )*};
}
int_from!(i8, i16, i32, i64, u8, u16, u32);

impl From<bool> for SqlValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}
impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}
impl From<&String> for SqlValue {
    fn from(v: &String) -> Self {
        Self::Text(v.clone())
    }
}
impl From<Vec<u8>> for SqlValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}
impl From<&[u8]> for SqlValue {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(v.to_vec())
    }
}
impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}

/// How the driver spells a positional parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholder {
    /// `$1`, `$2`, ... (PostgreSQL).
    Dollar,
    /// `?` (SQLite, MySQL).
    Question,
}

/// A parameterised query whose text was fixed at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlQuery {
    template: &'static str,
    params: Vec<SqlValue>,
}

/// Whether every placeholder in `text` is outside quoted literals and
/// quoted identifiers, where a driver would not treat it as a parameter.
#[must_use]
pub const fn placeholders_outside_quotes(text: &str) -> bool {
    let mut bytes = text.as_bytes();
    let mut quote: u8 = 0;
    while let [first, rest @ ..] = bytes {
        if quote == 0 {
            if *first == b'\'' || *first == b'"' {
                quote = *first;
            } else if *first == b'{'
                && let [b'}', ..] = rest
            {
                // An unquoted placeholder: fine.
            }
        } else if *first == quote {
            quote = 0;
        } else if *first == b'{'
            && let [b'}', ..] = rest
        {
            return false;
        }
        bytes = rest;
    }
    true
}

impl SqlQuery {
    /// Builds a query from a compile-time template and `N` values. Use the
    /// [`sql!`](crate::sql!) macro rather than calling this directly.
    ///
    /// The template must have exactly `N` placeholders, none inside quotes;
    /// otherwise compilation fails.
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(params: [SqlValue; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "sql!: the number of placeholders differs from the number of values"
            );
            assert!(
                placeholders_outside_quotes(T::TEXT),
                "sql!: a placeholder is inside quotes; write it bare, values are bound as parameters"
            );
        }
        Self {
            template: T::TEXT,
            params: params.into(),
        }
    }

    /// The query text with driver-specific placeholders.
    #[must_use]
    pub fn text(&self, style: Placeholder) -> String {
        let mut out = String::with_capacity(self.template.len());
        for (index, piece) in (0usize..).zip(pieces(self.template)) {
            if index > 0 {
                match style {
                    Placeholder::Dollar => {
                        out.push('$');
                        out.push_str(&index.to_string());
                    }
                    Placeholder::Question => out.push('?'),
                }
            }
            out.push_str(piece);
        }
        out
    }

    /// The bind parameters, in placeholder order.
    #[must_use]
    pub fn params(&self) -> &[SqlValue] {
        &self.params
    }
}

/// Builds a [`SqlQuery`] from a string literal and its values.
#[macro_export]
macro_rules! sql {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "sql!: the number of placeholders differs from the number of values");
        const _: () = assert!($crate::sql::placeholders_outside_quotes($text), "sql!: a placeholder is inside quotes; write it bare, values are bound as parameters");
        struct CortenSqlTemplate;
        impl $crate::template::Template for CortenSqlTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::sql::SqlQuery::from_template::<CortenSqlTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$($crate::sql::SqlValue::from($arg)),*],
        )
    }};
}

/// What a database driver implements. It accepts only a [`SqlQuery`], so
/// application code cannot send a string as SQL.
pub trait SqlExecutor {
    /// The driver's error.
    type Error;
    /// Runs `query`, binding its parameters; returns the rows affected.
    ///
    /// # Errors
    ///
    /// The driver's error.
    fn execute(&mut self, query: &SqlQuery) -> Result<u64, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_never_enter_the_text() {
        let hostile = "1; DROP TABLE users; --";
        let q = crate::sql!(
            "SELECT name FROM users WHERE id = {} AND org = {}",
            hostile,
            7
        );
        assert_eq!(
            q.text(Placeholder::Dollar),
            "SELECT name FROM users WHERE id = $1 AND org = $2"
        );
        assert_eq!(
            q.text(Placeholder::Question),
            "SELECT name FROM users WHERE id = ? AND org = ?"
        );
        assert_eq!(
            q.params(),
            [SqlValue::Text(hostile.to_owned()), SqlValue::Int(7)]
        );
    }

    #[test]
    fn no_values_and_options() {
        let q = crate::sql!("SELECT 1");
        assert_eq!(q.text(Placeholder::Dollar), "SELECT 1");
        let none: Option<i32> = None;
        let q = crate::sql!("UPDATE t SET x = {}", none);
        assert_eq!(q.params(), [SqlValue::Null]);
    }

    #[test]
    fn quote_check() {
        assert!(placeholders_outside_quotes("a = {} AND b = 'x{'"));
        assert!(!placeholders_outside_quotes("a = '{}'"));
        assert!(!placeholders_outside_quotes("\"{}\" = 1"));
        assert!(placeholders_outside_quotes("a = 'it''s' AND b = {}"));
    }
}
