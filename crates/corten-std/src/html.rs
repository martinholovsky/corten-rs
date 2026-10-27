//! `Html` and `html!` (spec 4.5, CWE-79 to 87, 692, 838).
//!
//! The markup is a compile-time template. A value may appear only where the
//! encoder knows its context: element text, or the quoted value of an
//! allowlisted attribute. Everywhere else (URL and event attributes,
//! `style`, unquoted values, tag or attribute names, comments, and any
//! template containing a raw-text element such as `<script>`) a placeholder
//! is a compile-time error. There is no `Html::raw`.
//!
//! ```
//! let name = "<script>alert(1)</script>";
//! let page = corten_std::html!("<p class=\"{}\">Hello, {}</p>", "x\" onload=\"y", name);
//! assert_eq!(
//!     page.as_str(),
//!     "<p class=\"x&quot; onload=&quot;y\">Hello, &lt;script&gt;alert(1)&lt;/script&gt;</p>"
//! );
//! ```
//!
//! ```compile_fail
//! let url = "javascript:alert(1)";
//! let _a = corten_std::html!("<a href=\"{}\">x</a>", url);
//! ```

use crate::template::{Template, count_placeholders, pieces};

/// HTML whose every interpolated value was escaped for its context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Html(String);

impl Html {
    /// The markup.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds markup from a compile-time template and `N` values. Use the
    /// [`html!`](crate::html!) macro rather than calling this directly.
    #[must_use]
    pub fn from_template<T: Template, const N: usize>(args: [HtmlArg; N]) -> Self {
        const {
            assert!(
                count_placeholders(T::TEXT) == N,
                "html!: the number of placeholders differs from the number of values"
            );
            assert!(
                all_placeholders_allowed(T::TEXT),
                "html!: a placeholder is in a context the encoder does not allow (URL or event attribute, style, unquoted value, tag or attribute name, comment, or a template with a raw-text element)"
            );
        }
        let mut out = String::with_capacity(T::TEXT.len());
        let mut args = args.into_iter();
        for (index, piece) in (0usize..).zip(pieces(T::TEXT)) {
            if index > 0
                && let Some(arg) = args.next()
            {
                match (arg, placeholder_context(T::TEXT, index)) {
                    // Already-escaped markup is kept only as element content.
                    (HtmlArg::Html(h), Context::Text) => out.push_str(&h.0),
                    (HtmlArg::Html(h), _) => escape_into(&h.0, &mut out),
                    (HtmlArg::Text(t), _) => escape_into(&t, &mut out),
                }
            }
            out.push_str(piece);
        }
        Self(out)
    }
}

/// A value interpolated into [`html!`](crate::html!).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtmlArg {
    /// Text, escaped at the point of use.
    Text(String),
    /// Markup built by `html!`, kept as is in element content.
    Html(Html),
}

impl From<&str> for HtmlArg {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}
impl From<String> for HtmlArg {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}
impl From<&String> for HtmlArg {
    fn from(v: &String) -> Self {
        Self::Text(v.clone())
    }
}
impl From<Html> for HtmlArg {
    fn from(v: Html) -> Self {
        Self::Html(v)
    }
}
macro_rules! display_from {
    ($($t:ty),*) => {$(
        impl From<$t> for HtmlArg {
            fn from(v: $t) -> Self {
                Self::Text(v.to_string())
            }
        }
    )*};
}
display_from!(
    i8, i16, i32, i64, u8, u16, u32, u64, usize, isize, bool, char
);

/// Escapes text for element content and quoted attribute values.
fn escape_into(text: &str, out: &mut String) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\0' => out.push('\u{FFFD}'),
            other => out.push(other),
        }
    }
}

/// Where a placeholder sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// Element content.
    Text,
    /// The quoted value of an allowlisted attribute.
    AttrValue,
    /// Anywhere the encoder cannot make safe.
    Refused,
}

/// Elements whose content the HTML parser does not treat as markup, plus
/// foreign content and comments. A template containing one may not have
/// placeholders at all.
const RAW_TEXT_OPENERS: &[&[u8]] = &[
    b"<script",
    b"<style",
    b"<!--",
    b"<textarea",
    b"<title",
    b"<iframe",
    b"<noscript",
    b"<xmp",
    b"<plaintext",
    b"<noembed",
    b"<noframes",
    b"<template",
    b"<svg",
    b"<math",
    b"<object",
    b"<embed",
];

/// Attributes whose quoted value may hold a placeholder: plain text values
/// with no URL, script or style meaning. Deny by default; `aria-*` and
/// `data-*` are allowed by prefix. `id` and `name` are left out: a value
/// chosen by input there can clobber DOM globals.
const ALLOWED_ATTRIBUTES: &[&[u8]] = &[
    b"class",
    b"title",
    b"alt",
    b"value",
    b"placeholder",
    b"lang",
    b"dir",
    b"for",
    b"type",
    b"role",
    b"width",
    b"height",
    b"colspan",
    b"rowspan",
    b"maxlength",
    b"minlength",
    b"min",
    b"max",
    b"step",
    b"rows",
    b"cols",
    b"size",
    b"label",
    b"summary",
    b"abbr",
    b"headers",
    b"scope",
    b"datetime",
    b"autocomplete",
    b"spellcheck",
    b"tabindex",
];

const fn lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

const fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let (mut a, mut b) = (a, b);
    while let ([x, xs @ ..], [y, ys @ ..]) = (a, b) {
        if lower(*x) != lower(*y) {
            return false;
        }
        a = xs;
        b = ys;
    }
    true
}

const fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
    if text.len() < prefix.len() {
        return false;
    }
    let (head, _) = text.split_at(prefix.len());
    eq_ignore_case(head, prefix)
}

const fn contains_ignore_case(mut text: &[u8], needle: &[u8]) -> bool {
    loop {
        if starts_with_ignore_case(text, needle) {
            return true;
        }
        match text {
            [_, rest @ ..] => text = rest,
            [] => return false,
        }
    }
}

const fn attribute_allowed(name: &[u8]) -> bool {
    if starts_with_ignore_case(name, b"aria-") || starts_with_ignore_case(name, b"data-") {
        return name.len() > 5;
    }
    let mut list = ALLOWED_ATTRIBUTES;
    while let [first, rest @ ..] = list {
        if eq_ignore_case(name, first) {
            return true;
        }
        list = rest;
    }
    false
}

const fn has_raw_text_element(text: &[u8]) -> bool {
    let mut list = RAW_TEXT_OPENERS;
    while let [first, rest @ ..] = list {
        if contains_ignore_case(text, first) {
            return true;
        }
        list = rest;
    }
    false
}

const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c')
}

/// Tokeniser state, for the subset of HTML a template may contain.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Text,
    TagName,
    BeforeAttr,
    AttrName,
    AfterAttrName,
    BeforeValue,
    ValueDouble,
    ValueSingle,
    ValueUnquoted,
}

/// The context of the `index`-th placeholder (1-based) in `text`.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one tokeniser state machine reads more clearly as one match than split across functions"
)]
pub const fn placeholder_context(text: &str, index: usize) -> Context {
    let all = text.as_bytes();
    if has_raw_text_element(all) {
        return Context::Refused;
    }
    let mut bytes = all;
    let mut state = State::Text;
    let mut seen = 0usize;
    // The current attribute's name: the slice where it started and its length.
    let mut name_start: &[u8] = &[];
    let mut name_len = 0usize;
    // The two bytes before the current one, to see `<{}` and `<!{}`, where
    // a value could finish a tag or comment opener.
    let mut last1: u8 = 0;
    let mut last2: u8 = 0;
    while let [first, rest @ ..] = bytes {
        let c = *first;
        if c == b'{'
            && let [b'}', after @ ..] = rest
        {
            seen = seen.saturating_add(1);
            let context = match state {
                State::Text
                    if last1 == b'<' || (last2 == b'<' && matches!(last1, b'!' | b'?' | b'/')) =>
                {
                    Context::Refused
                }
                State::Text => Context::Text,
                State::ValueDouble | State::ValueSingle => {
                    let (name, _) = name_start.split_at(if name_len <= name_start.len() {
                        name_len
                    } else {
                        name_start.len()
                    });
                    if attribute_allowed(name) {
                        Context::AttrValue
                    } else {
                        Context::Refused
                    }
                }
                _ => Context::Refused,
            };
            if seen == index {
                return context;
            }
            last2 = b'}';
            last1 = b'}';
            bytes = after;
            continue;
        }
        state = match state {
            State::Text => {
                if c == b'<'
                    && let [next, ..] = rest
                    && (next.is_ascii_alphabetic() || *next == b'/')
                {
                    State::TagName
                } else {
                    State::Text
                }
            }
            State::TagName => {
                if is_space(c) || c == b'/' {
                    State::BeforeAttr
                } else if c == b'>' {
                    State::Text
                } else {
                    State::TagName
                }
            }
            State::BeforeAttr => {
                if c == b'>' {
                    State::Text
                } else if is_space(c) || c == b'/' {
                    State::BeforeAttr
                } else {
                    name_start = bytes;
                    name_len = 1;
                    State::AttrName
                }
            }
            State::AttrName => {
                if c == b'=' {
                    State::BeforeValue
                } else if is_space(c) {
                    State::AfterAttrName
                } else if c == b'>' {
                    State::Text
                } else {
                    name_len = name_len.saturating_add(1);
                    State::AttrName
                }
            }
            State::AfterAttrName => {
                if c == b'=' {
                    State::BeforeValue
                } else if c == b'>' {
                    State::Text
                } else if is_space(c) {
                    State::AfterAttrName
                } else {
                    name_start = bytes;
                    name_len = 1;
                    State::AttrName
                }
            }
            State::BeforeValue => {
                if c == b'"' {
                    State::ValueDouble
                } else if c == b'\'' {
                    State::ValueSingle
                } else if is_space(c) {
                    State::BeforeValue
                } else if c == b'>' {
                    State::Text
                } else {
                    State::ValueUnquoted
                }
            }
            State::ValueDouble => {
                if c == b'"' {
                    State::BeforeAttr
                } else {
                    State::ValueDouble
                }
            }
            State::ValueSingle => {
                if c == b'\'' {
                    State::BeforeAttr
                } else {
                    State::ValueSingle
                }
            }
            State::ValueUnquoted => {
                if is_space(c) {
                    State::BeforeAttr
                } else if c == b'>' {
                    State::Text
                } else {
                    State::ValueUnquoted
                }
            }
        };
        last2 = last1;
        last1 = c;
        bytes = rest;
    }
    Context::Refused
}

/// Whether every placeholder in `text` has an allowed context.
#[must_use]
pub const fn all_placeholders_allowed(text: &str) -> bool {
    let total = count_placeholders(text);
    let mut index = 1usize;
    while index <= total {
        if matches!(placeholder_context(text, index), Context::Refused) {
            return false;
        }
        index = index.saturating_add(1);
    }
    true
}

/// Builds [`Html`] from a string literal and its values.
#[macro_export]
macro_rules! html {
    ($text:literal $(, $arg:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::template::count_placeholders($text) == $crate::__corten_count!($($arg),*), "html!: the number of placeholders differs from the number of values");
        const _: () = assert!($crate::html::all_placeholders_allowed($text), "html!: a placeholder is in a context the encoder does not allow");
        struct CortenHtmlTemplate;
        impl $crate::template::Template for CortenHtmlTemplate {
            const TEXT: &'static str = $text;
        }
        $crate::html::Html::from_template::<CortenHtmlTemplate, { $crate::__corten_count!($($arg),*) }>(
            [$($crate::html::HtmlArg::from($arg)),*],
        )
    }};
}

/// What an HTTP response writer implements. It accepts only [`Html`].
pub trait HtmlWriter {
    /// The writer's error.
    type Error;
    /// Sends `page` as the response body, `text/html; charset=utf-8`.
    ///
    /// # Errors
    ///
    /// The writer's error.
    fn write_html(&mut self, page: &Html) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts() {
        let t = "<p class=\"{}\" title='{}'>{}<b>{}</b></p>";
        assert_eq!(placeholder_context(t, 1), Context::AttrValue);
        assert_eq!(placeholder_context(t, 2), Context::AttrValue);
        assert_eq!(placeholder_context(t, 3), Context::Text);
        assert_eq!(placeholder_context(t, 4), Context::Text);
        assert!(all_placeholders_allowed(t));
    }

    #[test]
    fn refused_contexts() {
        for t in [
            "<a href=\"{}\">x</a>",
            "<img src='{}'>",
            "<div onclick=\"{}\">",
            "<div style=\"{}\">",
            "<div class={}>",
            "<{}>",
            "<div {}=\"x\">",
            "<script>var x = {};</script>",
            "<p>{}</p><script>1</script>",
            "<!-- {} -->",
            "<style>p {}</style>",
            "<svg><text>{}</text></svg>",
            "<div data-=\"{}\">",
            "<meta content=\"{}\">",
            "<div ONCLICK=\"{}\">",
            "<a HREF=\"{}\">",
            "<div id=\"{}\">",
            "<{}>",
            "x <{}",
            "<!{}",
            "<?{}",
            "</{}>",
            "<input name=\"{}\">",
        ] {
            assert!(!all_placeholders_allowed(t), "{t}");
        }
        for t in [
            "<div data-user=\"{}\">",
            "<div aria-label='{}'>",
            "<p>{}</p>",
            "{}",
        ] {
            assert!(all_placeholders_allowed(t), "{t}");
        }
    }

    #[test]
    fn escapes_every_breakout_character() {
        let page = crate::html!("<p title=\"{}\">{}</p>", "\"'<>&\0", "</p><script>");
        assert_eq!(
            page.as_str(),
            "<p title=\"&quot;&#39;&lt;&gt;&amp;\u{FFFD}\">&lt;/p&gt;&lt;script&gt;</p>"
        );
    }

    #[test]
    fn nested_html_is_kept_in_text_and_escaped_in_attributes() {
        let inner = crate::html!("<b>{}</b>", "x");
        let outer = crate::html!("<p>{}</p>", inner.clone());
        assert_eq!(outer.as_str(), "<p><b>x</b></p>");
        let attr = crate::html!("<p title=\"{}\"></p>", inner);
        assert_eq!(attr.as_str(), "<p title=\"&lt;b&gt;x&lt;/b&gt;\"></p>");
    }

    /// Property: whatever text is interpolated into element content, the
    /// output contains no `<` other than the template's own.
    #[test]
    fn interpolated_text_never_opens_a_tag() {
        let alphabet = ['<', '>', '"', '\'', '&', 'a', '/', '=', ' ', '\0'];
        let mut stack: Vec<String> = alphabet.iter().map(char::to_string).collect();
        let mut checked = 0usize;
        while let Some(s) = stack.pop() {
            checked = checked.saturating_add(1);
            let page = crate::html!("<p title=\"{}\">{}</p>", s.as_str(), s.as_str());
            assert_eq!(page.as_str().matches('<').count(), 2, "{s:?}");
            assert_eq!(page.as_str().matches('"').count(), 2, "{s:?}");
            if s.chars().count() < 4 {
                for c in alphabet {
                    let mut next = s.clone();
                    next.push(c);
                    stack.push(next);
                }
            }
        }
        assert!(checked > 10_000, "{checked}");
    }
}
