//! `XPathExpr`, `XQueryExpr` and their macros (spec 4.5; CWE-91, 643, 652).
//!
//! A value always becomes one string literal of the target language. A
//! placeholder already inside quotes in the template is a compile error,
//! since the encoder supplies the quotes. So is one inside a `(: … :)`
//! comment (XPath 2 and later, XQuery), where the value could close it, and,
//! for XQuery, one inside a ``` ``[…]`` ``` string constructor or in any
//! template with a direct element constructor (`<r>{}</r>`): there `"` is
//! ordinary text and `{` starts an evaluated expression (encoder pre-review,
//! `docs/gates/encoder-prereview.md`).
//!
//! ```
//! let name = "x' or '1'='1";
//! let e = corten_std::xpath!("//user[name={}]", name);
//! assert_eq!(e.as_str(), "//user[name=\"x' or '1'='1\"]");
//! ```

use crate::template::{Template, count_placeholders, pieces};

/// An XPath 1.0 expression whose values are string literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPathExpr(String);

/// An XQuery expression whose values are string literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XQueryExpr(String);

/// An XPath 1.0 string literal for `value`. XPath 1.0 has no escape inside
/// a literal, so a value with both quote kinds becomes `concat(...)`.
#[must_use]
pub fn xpath_literal(value: &str) -> String {
    if !value.contains('\'') {
        return format!("'{value}'");
    }
    if !value.contains('"') {
        return format!("\"{value}\"");
    }
    let parts: Vec<String> = value.split('\'').map(|part| format!("'{part}'")).collect();
    format!("concat({})", parts.join(", \"'\", "))
}

/// An XQuery string literal for `value`: double-quoted, `"` doubled, and
/// `&` written as `&amp;` (XQuery reads entity references in literals).
#[must_use]
pub fn xquery_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('&', "&amp;").replace('"', "\"\""))
}

/// Whether every placeholder is outside a quoted literal.
#[must_use]
pub const fn placeholders_outside_quotes(text: &str) -> bool {
    crate::sql::placeholders_outside_quotes(text)
}

fn fill<T: Template, const N: usize>(values: [String; N], literal: fn(&str) -> String) -> String {
    let mut out = String::with_capacity(T::TEXT.len());
    let mut values = values.into_iter();
    for (index, piece) in (0usize..).zip(pieces(T::TEXT)) {
        if index > 0
            && let Some(v) = values.next()
        {
            out.push_str(&literal(&v));
        }
        out.push_str(piece);
    }
    out
}

const fn starts(bytes: &[u8], prefix: &[u8]) -> bool {
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

/// Whether every placeholder in `text` stands in expression context: not in
/// a quoted literal, not in a comment (nested comments counted), and, when
/// `xquery`, not in a string constructor, with no placeholder at all in a
/// template that has a direct element constructor.
#[must_use]
pub const fn placeholders_in_expression(text: &str, xquery: bool) -> bool {
    let mut bytes = text.as_bytes();
    let mut quote: u8 = 0;
    let mut comment = 0usize;
    let mut string_constructor = false;
    let mut constructor = false;
    let mut placeholders = 0usize;
    while let [c, rest @ ..] = bytes {
        let placeholder = *c == b'{' && matches!(rest, [b'}', ..]);
        if placeholder {
            placeholders = placeholders.saturating_add(1);
            if quote != 0 || comment > 0 || string_constructor {
                return false;
            }
        }
        if quote != 0 {
            if *c == quote {
                quote = 0;
            }
        } else if comment > 0 {
            if starts(bytes, b"(:") {
                comment = comment.saturating_add(1);
                bytes = rest;
            } else if starts(bytes, b":)") {
                comment = comment.saturating_sub(1);
                bytes = rest;
            }
        } else if string_constructor {
            if starts(bytes, b"]``") {
                string_constructor = false;
            }
        } else if starts(bytes, b"(:") {
            comment = 1;
            bytes = rest;
        } else if xquery && starts(bytes, b"``[") {
            string_constructor = true;
        } else if *c == b'\'' || *c == b'"' {
            quote = *c;
        } else if xquery
            && *c == b'<'
            && let [next, ..] = rest
            && (next.is_ascii_alphabetic() || matches!(*next, b'!' | b'?' | b'/' | b'_'))
        {
            constructor = true;
        }
        if let [_, after @ ..] = bytes {
            bytes = after;
        }
    }
    !(constructor && placeholders > 0)
}

impl XPathExpr {
    /// Fills a compile-time XPath template. Use [`xpath!`](crate::xpath!).
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(values: [String; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "xpath!: placeholder count differs from values"
            );
            assert!(
                placeholders_outside_quotes(T::TEXT),
                "xpath!: write the placeholder bare; the encoder adds the quotes"
            );
            assert!(
                placeholders_in_expression(T::TEXT, false),
                "xpath!: a placeholder is inside a comment"
            );
        }
        Self(fill::<T, N>(values, xpath_literal))
    }

    /// The expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl XQueryExpr {
    /// Fills a compile-time XQuery template. Use [`xquery!`](crate::xquery!).
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(values: [String; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "xquery!: placeholder count differs from values"
            );
            assert!(
                placeholders_outside_quotes(T::TEXT),
                "xquery!: write the placeholder bare; the encoder adds the quotes"
            );
            assert!(
                placeholders_in_expression(T::TEXT, true),
                "xquery!: a placeholder is inside a comment, a string constructor, or a template with a direct element constructor"
            );
        }
        Self(fill::<T, N>(values, xquery_literal))
    }

    /// The expression.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Builds an [`XPathExpr`] from a string literal and its values.
#[macro_export]
macro_rules! xpath {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "xpath!: placeholder count differs from values");
        const _: () = assert!($crate::xpath::placeholders_outside_quotes($text), "xpath!: write the placeholder bare; the encoder adds the quotes");
        const _: () = assert!($crate::xpath::placeholders_in_expression($text, false), "xpath!: a placeholder is inside a comment");
        struct CortenXPathTemplate;
        impl $crate::template::Template for CortenXPathTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::xpath::XPathExpr::from_template::<CortenXPathTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$(::std::string::ToString::to_string(&$arg)),*],
        )
    }};
}

/// Builds an [`XQueryExpr`] from a string literal and its values.
#[macro_export]
macro_rules! xquery {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "xquery!: placeholder count differs from values");
        const _: () = assert!($crate::xpath::placeholders_outside_quotes($text), "xquery!: write the placeholder bare; the encoder adds the quotes");
        const _: () = assert!($crate::xpath::placeholders_in_expression($text, true), "xquery!: a placeholder is inside a comment, a string constructor, or a template with a direct element constructor");
        struct CortenXQueryTemplate;
        impl $crate::template::Template for CortenXQueryTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::xpath::XQueryExpr::from_template::<CortenXQueryTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$(::std::string::ToString::to_string(&$arg)),*],
        )
    }};
}

/// What an XPath engine implements. It accepts only an [`XPathExpr`].
pub trait XPathEvaluator {
    /// The engine's error.
    type Error;
    /// Evaluates `expr` to strings.
    ///
    /// # Errors
    ///
    /// The engine's error.
    fn evaluate(&mut self, expr: &XPathExpr) -> Result<Vec<String>, Self::Error>;
}

/// What an XQuery engine implements. It accepts only an [`XQueryExpr`].
pub trait XQueryEvaluator {
    /// The engine's error.
    type Error;
    /// Evaluates `expr` to strings.
    ///
    /// # Errors
    ///
    /// The engine's error.
    fn evaluate(&mut self, expr: &XQueryExpr) -> Result<Vec<String>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_only_in_expression_context() {
        for (t, xq) in [
            ("//user[name={}]", false),
            ("//a[b = {}] | //c", false),
            ("doc('u.xml')//user[name = {}]", true),
            (
                "for $u in //user where $u/age < 5 and $u/name = {} return $u",
                true,
            ),
            ("(: note :) //user[name = {}]", true),
        ] {
            assert!(placeholders_in_expression(t, xq), "{t}");
        }
        for (t, xq) in [
            ("//user[name = 'a'] (: by {} :)", false),
            ("(: outer (: inner :) {} :)", true),
            ("<r>{}</r>", true),
            ("let $x := {} return <r>{$x}</r>", true),
            ("``[Hello {}]``", true),
            ("<!-- c -->{}", true),
        ] {
            assert!(!placeholders_in_expression(t, xq), "{t}");
        }
    }

    #[test]
    fn xpath_literals() {
        assert_eq!(xpath_literal("abc"), "'abc'");
        assert_eq!(xpath_literal("it's"), "\"it's\"");
        assert_eq!(xpath_literal("a'b\"c"), "concat('a', \"'\", 'b\"c')");
    }

    #[test]
    fn xquery_literals() {
        assert_eq!(xquery_literal("a\"b&c"), "\"a\"\"b&amp;c\"");
        let e = crate::xquery!("doc('u.xml')//user[name = {}]", "x\" or \"1\"=\"1");
        assert_eq!(
            e.as_str(),
            "doc('u.xml')//user[name = \"x\"\" or \"\"1\"\"=\"\"1\"]"
        );
    }
}
