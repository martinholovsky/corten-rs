//! `LdapFilter`, `LdapDn` and their macros (spec 4.5, CWE-90).
//!
//! Two contexts, two encoders: a search-filter value is escaped per
//! RFC 4515, a DN attribute value per RFC 4514. A placeholder may stand only
//! in value position: after the `=` of its filter item (`=`, `~=`, `>=`,
//! `<=`, `:=`) or of its DN component. In attribute position the value's
//! escaping does not apply (`({}=admin)` with `uid>` gives `(uid>=admin)`),
//! so the template does not compile (encoder pre-review,
//! `docs/gates/encoder-prereview.md`).
//!
//! ```
//! let user = "*)(uid=*";
//! let f = corten_std::ldap_filter!("(&(uid={})(objectClass=person))", user);
//! assert_eq!(f.as_str(), "(&(uid=\\2a\\29\\28uid=\\2a)(objectClass=person))");
//! ```

use crate::template::{Template, count_placeholders, pieces};

/// An LDAP search filter whose values were escaped per RFC 4515.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapFilter(String);

/// An LDAP distinguished name whose values were escaped per RFC 4514.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapDn(String);

/// Whether every placeholder in `text` stands in value position. In a filter
/// (`dn` false) an item starts at `(` or `)`; in a DN at `,` or `+`. A
/// backslash escapes the next template byte.
#[must_use]
pub const fn placeholders_in_values(text: &str, dn: bool) -> bool {
    let mut seen_eq = false;
    let mut bytes = text.as_bytes();
    while let [c, rest @ ..] = bytes {
        if *c == b'{'
            && let [b'}', after @ ..] = rest
        {
            if !seen_eq {
                return false;
            }
            bytes = after;
            continue;
        }
        match (*c, rest) {
            (b'\\', [_, after @ ..]) => {
                bytes = after;
                continue;
            }
            (b'(' | b')', _) if !dn => seen_eq = false,
            (b',' | b'+', _) if dn => seen_eq = false,
            (b'=', _) => seen_eq = true,
            _ => {}
        }
        bytes = rest;
    }
    true
}

fn fill<T: Template, const N: usize>(values: [String; N], escape: fn(&str) -> String) -> String {
    let mut out = String::with_capacity(T::TEXT.len());
    let mut values = values.into_iter();
    for (index, piece) in (0usize..).zip(pieces(T::TEXT)) {
        if index > 0
            && let Some(v) = values.next()
        {
            out.push_str(&escape(&v));
        }
        out.push_str(piece);
    }
    out
}

/// RFC 4515 section 3: `*`, `(`, `)`, `\` and NUL become `\XX`.
#[must_use]
pub fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// RFC 4514 section 2.4: `"`, `+`, `,`, `;`, `<`, `>`, `\`, `=` and NUL
/// anywhere, a leading space or `#`, and a trailing space are escaped.
#[must_use]
pub fn escape_dn_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (i, c) in value.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\00"),
            ' ' if i == 0 || i == last => out.push_str("\\ "),
            '#' if i == 0 => out.push_str("\\#"),
            c => out.push(c),
        }
    }
    out
}

impl LdapFilter {
    /// Fills a compile-time filter template. Use
    /// [`ldap_filter!`](crate::ldap_filter!).
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(values: [String; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "ldap_filter!: placeholder count differs from values"
            );
            assert!(
                placeholders_in_values(T::TEXT, false),
                "ldap_filter!: a placeholder is not in value position"
            );
        }
        Self(fill::<T, N>(values, escape_filter_value))
    }

    /// The filter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl LdapDn {
    /// Fills a compile-time DN template. Use [`ldap_dn!`](crate::ldap_dn!).
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(values: [String; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "ldap_dn!: placeholder count differs from values"
            );
            assert!(
                placeholders_in_values(T::TEXT, true),
                "ldap_dn!: a placeholder is not in value position"
            );
        }
        Self(fill::<T, N>(values, escape_dn_value))
    }

    /// The DN.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Builds an [`LdapFilter`] from a string literal and its values.
#[macro_export]
macro_rules! ldap_filter {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "ldap_filter!: placeholder count differs from values");
        const _: () = assert!($crate::ldap::placeholders_in_values($text, false), "ldap_filter!: a placeholder is not in value position");
        struct CortenLdapTemplate;
        impl $crate::template::Template for CortenLdapTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::ldap::LdapFilter::from_template::<CortenLdapTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$(::std::string::ToString::to_string(&$arg)),*],
        )
    }};
}

/// Builds an [`LdapDn`] from a string literal and its values.
#[macro_export]
macro_rules! ldap_dn {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "ldap_dn!: placeholder count differs from values");
        const _: () = assert!($crate::ldap::placeholders_in_values($text, true), "ldap_dn!: a placeholder is not in value position");
        struct CortenLdapDnTemplate;
        impl $crate::template::Template for CortenLdapDnTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::ldap::LdapDn::from_template::<CortenLdapDnTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$(::std::string::ToString::to_string(&$arg)),*],
        )
    }};
}

/// What an LDAP client implements. It accepts only typed DNs and filters.
pub trait LdapSearcher {
    /// The client's error.
    type Error;
    /// Searches beneath `base` with `filter`; returns matching DNs.
    ///
    /// # Errors
    ///
    /// The client's error.
    fn search(&mut self, base: &LdapDn, filter: &LdapFilter) -> Result<Vec<String>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_escaping() {
        assert_eq!(
            escape_filter_value("a*b(c)d\\e\0"),
            "a\\2ab\\28c\\29d\\5ce\\00"
        );
    }

    #[test]
    fn placeholders_only_in_value_position() {
        for t in [
            "(uid={})",
            "(&(uid={})(o=x))",
            "(cn~={})",
            "(age>={})",
            "(uid:dn:={})",
            "(cn=a{}*)",
            "(|(a=1)(b={}))",
        ] {
            assert!(placeholders_in_values(t, false), "{t}");
        }
        for t in [
            "({}=admin)",
            "(&(a=1)({}=x))",
            "(uid>{})",
            "{}",
            "(a=1)({})",
        ] {
            assert!(!placeholders_in_values(t, false), "{t}");
        }
        for t in ["uid={},ou=people", "cn={}+uid={},dc=x", "cn=a\\,{},dc=x"] {
            assert!(placeholders_in_values(t, true), "{t}");
        }
        for t in ["{}=admin,dc=x", "uid=x,{}=y", "cn=a+{}=b"] {
            assert!(!placeholders_in_values(t, true), "{t}");
        }
    }

    #[test]
    fn dn_escaping() {
        assert_eq!(escape_dn_value(" #a,b+c "), "\\ #a\\,b\\+c\\ ");
        assert_eq!(escape_dn_value("#x"), "\\#x");
        assert_eq!(escape_dn_value("a=b"), "a\\=b");
        let dn = crate::ldap_dn!("uid={},ou=people,dc=example", "x,ou=admins");
        assert_eq!(dn.as_str(), "uid=x\\,ou\\=admins,ou=people,dc=example");
    }
}
