//! `LogRecord` and `log_record!` (spec 4.5, CWE-117).
//!
//! The event name and field names are compile-time; values are escaped so a
//! value cannot start a new log line, inject a field, or reorder text with
//! bidirectional controls.
//!
//! ```
//! let user = "alice\nlevel=admin";
//! let r = corten_std::log_record!("login", user = user, attempts = 3);
//! assert_eq!(r.render(), "login user=\"alice\\u{a}level=admin\" attempts=\"3\"");
//! ```

use crate::template::Template;

/// One structured log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    event: &'static str,
    fields: Vec<(&'static str, String)>,
}

/// Whether `name` is a valid event name: `[a-z0-9_.]`, 1 to 64 bytes.
#[must_use]
pub const fn valid_event(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let mut rest = bytes;
    while let [b, tail @ ..] = rest {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'.') {
            return false;
        }
        rest = tail;
    }
    true
}

impl LogRecord {
    /// Builds a record for the compile-time event `T::TEXT`. Use
    /// [`log_record!`](crate::log_record!).
    #[must_use]
    pub fn from_template<T: Template>(fields: Vec<(&'static str, String)>) -> Self {
        const {
            assert!(
                valid_event(T::TEXT),
                "log_record!: event names are [a-z0-9_.], 1 to 64 bytes"
            );
        }
        Self {
            event: T::TEXT,
            fields,
        }
    }

    /// The record as one line: `event key="value" ...`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(self.event);
        for (key, value) in &self.fields {
            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            escape_into(value, &mut out);
            out.push('"');
        }
        out
    }
}

/// Escapes backslash, quote, every control character and the Unicode
/// bidirectional and line-separator controls.
fn escape_into(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control()
                || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}') =>
            {
                out.push_str(&c.escape_unicode().to_string());
            }
            c => out.push(c),
        }
    }
}

/// Builds a [`LogRecord`]: `log_record!("event", key = value, ...)`.
#[macro_export]
macro_rules! log_record {
    ($event:literal $(, $key:ident = $value:expr)* $(,)?) => {{
        // Evaluated by `cargo check`, unlike the check inside
        // `from_template`, which runs only when the program is built.
        const _: () = assert!($crate::log::valid_event($event), "log_record!: event names are [a-z0-9_.], 1 to 64 bytes");
        struct CortenLogEvent;
        impl $crate::template::Template for CortenLogEvent {
            const TEXT: &'static str = $event;
        }
        $crate::log::LogRecord::from_template::<CortenLogEvent>(
            ::std::vec![$((::core::stringify!($key), ::std::string::ToString::to_string(&$value))),*],
        )
    }};
}

/// What a log backend implements. It accepts only [`LogRecord`].
pub trait LogWriter {
    /// Writes one record.
    fn write(&mut self, record: &LogRecord);
}

#[cfg(test)]
mod tests {
    #[test]
    fn values_cannot_forge_lines_or_fields() {
        let r = crate::log_record!(
            "auth.fail",
            user = "x\" admin=\"true",
            note = "a\r\nb\u{202E}c\\"
        );
        assert_eq!(
            r.render(),
            "auth.fail user=\"x\\\" admin=\\\"true\" note=\"a\\u{d}\\u{a}b\\u{202e}c\\\\\""
        );
        assert!(!r.render().contains('\n'));
    }

    #[test]
    fn event_name_check() {
        assert!(super::valid_event("user.login_2"));
        assert!(!super::valid_event("Login"));
        assert!(!super::valid_event("a b"));
        assert!(!super::valid_event(""));
    }
}
