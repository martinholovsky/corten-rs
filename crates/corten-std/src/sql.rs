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
//! A placeholder must be where a driver reads a parameter, or compilation
//! fails: not in a quoted literal or identifier (including a backslash
//! escape inside one, as MySQL reads it), a backtick identifier, a
//! dollar-quoted string (`$$…$$`, `$tag$…$tag$`), or a `--` or `/* */`
//! comment, and not directly before a digit (`{}0` would render as `$10`).
//! Found by the encoder pre-review (`docs/gates/encoder-prereview.md`); no
//! value reached the text, but the driver dropped it or miscounted. `[ … ]`
//! is not refused: PostgreSQL arrays (`ARRAY[{}]`) use it.
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

const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    if bytes.len() < prefix.len() {
        return false;
    }
    let (head, _) = bytes.split_at(prefix.len());
    let (mut a, mut b) = (head, prefix);
    while let ([x, xs @ ..], [y, ys @ ..]) = (a, b) {
        if *x != *y {
            return false;
        }
        a = xs;
        b = ys;
    }
    true
}

/// The `$tag$` opener at the start of `bytes` (`$$` or `$name$`), if any.
const fn dollar_tag(bytes: &[u8]) -> Option<&[u8]> {
    let [b'$', rest @ ..] = bytes else {
        return None;
    };
    let mut len = 1usize;
    let mut tail = rest;
    while let [c, more @ ..] = tail {
        if *c == b'$' {
            let (tag, _) = bytes.split_at(len.saturating_add(1));
            return Some(tag);
        }
        if !(c.is_ascii_alphanumeric() || *c == b'_') || c.is_ascii_digit() && len == 1 {
            return None;
        }
        len = len.saturating_add(1);
        tail = more;
    }
    None
}

/// Whether every placeholder in `text` is where a driver reads a parameter
/// (see the module documentation). Stricter than
/// [`placeholders_outside_quotes`], which XPath shares.
#[must_use]
pub const fn placeholders_are_parameters(text: &str) -> bool {
    let mut bytes = text.as_bytes();
    let mut quote: u8 = 0;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut dollar: &[u8] = &[];
    while let [c, rest @ ..] = bytes {
        let placeholder = *c == b'{' && matches!(rest, [b'}', ..]);
        let normal = quote == 0 && !line_comment && !block_comment && dollar.is_empty();
        if placeholder {
            if !normal {
                return false;
            }
            if let [_, next, ..] = rest
                && next.is_ascii_digit()
            {
                return false;
            }
        }
        let mut step = 1usize;
        if quote != 0 {
            if *c == b'\\' {
                step = 2;
            } else if *c == quote {
                quote = 0;
            }
        } else if line_comment {
            if *c == b'\n' {
                line_comment = false;
            }
        } else if block_comment {
            if starts_with(bytes, b"*/") {
                block_comment = false;
                step = 2;
            }
        } else if !dollar.is_empty() {
            if starts_with(bytes, dollar) {
                step = dollar.len();
                dollar = &[];
            }
        } else if matches!(*c, b'\'' | b'"' | b'`') {
            quote = *c;
        } else if starts_with(bytes, b"--") {
            line_comment = true;
        } else if starts_with(bytes, b"/*") {
            block_comment = true;
            step = 2;
        } else if let Some(tag) = dollar_tag(bytes) {
            dollar = tag;
            step = tag.len();
        }
        let mut n = 0usize;
        while n < step {
            if let [_, after @ ..] = bytes {
                bytes = after;
            }
            n = n.saturating_add(1);
        }
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
                placeholders_are_parameters(T::TEXT),
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
        const _: () = assert!($crate::sql::placeholders_are_parameters($text), "sql!: a placeholder is inside quotes, a comment or a dollar-quoted string, or directly before a digit; write it bare, values are bound as parameters");
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

    /// Runs `query` and returns a cursor over its rows.
    ///
    /// The cursor borrows the connection exclusively: while it lives, the
    /// connection runs no other statement, and it cannot outlive the
    /// connection. Dropping it closes it, once (CWE-619).
    ///
    /// # Errors
    ///
    /// The driver's error.
    fn query(&mut self, query: &SqlQuery) -> Result<Rows<'_>, Self::Error>;
}

/// A cursor over the rows of one query, from [`SqlExecutor::query`].
///
/// Its lifetime is the connection's exclusive borrow, so the borrow checker
/// rejects a second statement on the connection while the cursor is open
/// (E0499) and a cursor that outlives its connection (E0515, E0597). There
/// is no `close`: the cursor is closed when it is dropped.
pub struct Rows<'c> {
    rows: Box<dyn Iterator<Item = Vec<SqlValue>> + 'c>,
}

impl<'c> Rows<'c> {
    /// Wraps a driver's row iterator. Each row is one value per column.
    pub fn new(rows: impl Iterator<Item = Vec<SqlValue>> + 'c) -> Self {
        Self {
            rows: Box::new(rows),
        }
    }
}

impl Iterator for Rows<'_> {
    type Item = Vec<SqlValue>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rows.next()
    }
}

impl std::fmt::Debug for Rows<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rows").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A driver that returns its stored rows.
    struct Fake {
        rows: Vec<Vec<SqlValue>>,
        statements: u32,
    }

    impl SqlExecutor for Fake {
        type Error = ();
        fn execute(&mut self, _query: &SqlQuery) -> Result<u64, ()> {
            self.statements = self.statements.saturating_add(1);
            Ok(0)
        }
        fn query(&mut self, _query: &SqlQuery) -> Result<Rows<'_>, ()> {
            self.statements = self.statements.saturating_add(1);
            Ok(Rows::new(self.rows.iter().cloned()))
        }
    }

    #[test]
    fn a_cursor_yields_rows_and_frees_the_connection_when_dropped() {
        let mut db = Fake {
            rows: vec![vec![SqlValue::Int(1)], vec![SqlValue::Int(2)]],
            statements: 0,
        };
        let ids: Vec<_> = db
            .query(&crate::sql!("SELECT id FROM t"))
            .unwrap()
            .collect();
        assert_eq!(ids.len(), 2);
        db.execute(&crate::sql!("DELETE FROM t")).unwrap();
        assert_eq!(db.statements, 2);
    }

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

    #[test]
    fn placeholders_must_be_parameters() {
        for t in [
            "SELECT id FROM t WHERE a = {} AND b = {}",
            "SELECT 'it''s', {}",
            "SELECT ARRAY[{}]",
            "SELECT $1x, {}",
            "SELECT {} -- trailing note\n",
            "SELECT /* note */ {}",
            "SELECT $$ x $$, {}",
        ] {
            assert!(placeholders_are_parameters(t), "{t}");
        }
        for t in [
            "SELECT $$ {} $$",
            "SELECT $fn$ {} $fn$",
            "SELECT 'a\\' , {} , '",
            "SELECT `{}`",
            "SELECT 1 -- {}",
            "SELECT /* {} */ 1",
            "SELECT {}0",
            "SELECT '{}'",
        ] {
            assert!(!placeholders_are_parameters(t), "{t}");
        }
    }
}
