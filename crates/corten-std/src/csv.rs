//! `CsvCell` (spec 4.5, CWE-1236).
//!
//! A cell that a spreadsheet would read as a formula (a leading `= + - @`,
//! tab, CR, LF, NUL, or a full-width `＝ ＋ － ＠`) gets a leading `'`, and
//! every field is quoted per RFC 4180.
//!
//! ```
//! use corten_std::csv::{CsvCell, render_row};
//! let row = [CsvCell::new("=HYPERLINK(\"x\")"), CsvCell::new("a,b")];
//! assert_eq!(render_row(&row), "\"'=HYPERLINK(\"\"x\"\")\",\"a,b\"\r\n");
//! ```

/// One neutralised CSV field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvCell(String);

impl CsvCell {
    /// Neutralises `text` for spreadsheet export.
    #[must_use]
    pub fn new(text: &str) -> Self {
        let risky = text.chars().next().is_some_and(|c| {
            matches!(
                c,
                '=' | '+' | '-' | '@' | '\t' | '\r' | '\n' | '\0' | '＝' | '＋' | '－' | '＠'
            )
        });
        if risky {
            Self(format!("'{text}"))
        } else {
            Self(text.to_owned())
        }
    }

    /// The neutralised text, before quoting.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One CSV record: every field quoted, `"` doubled, ended by CRLF.
#[must_use]
pub fn render_row(cells: &[CsvCell]) -> String {
    let fields: Vec<String> = cells
        .iter()
        .map(|c| format!("\"{}\"", c.0.replace('"', "\"\"")))
        .collect();
    let mut line = fields.join(",");
    line.push_str("\r\n");
    line
}

/// What a CSV export implements. It accepts only [`CsvCell`] rows.
pub trait CsvWriter {
    /// The writer's error.
    type Error;
    /// Writes one record.
    ///
    /// # Errors
    ///
    /// The writer's error.
    fn write_row(&mut self, row: &[CsvCell]) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_prefixes_are_neutralised() {
        for risky in [
            "=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx", "\nx", "\0x", "＝1", "＋1", "－1", "＠x",
        ] {
            assert!(CsvCell::new(risky).as_str().starts_with('\''), "{risky:?}");
        }
        assert_eq!(CsvCell::new("plain").as_str(), "plain");
        assert_eq!(CsvCell::new("").as_str(), "");
    }

    #[test]
    fn quoting() {
        assert_eq!(
            render_row(&[CsvCell::new("a\"b"), CsvCell::new("x\ny")]),
            "\"a\"\"b\",\"x\ny\"\r\n"
        );
    }
}
