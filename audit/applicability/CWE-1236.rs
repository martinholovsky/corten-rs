//@ compiles: safe
// CWE-1236, CSV formula injection. Quotes are escaped for CSV, but a comment
// starting with "=" (=HYPERLINK(...)) is not neutralized and runs as a formula
// when the export is opened in a spreadsheet.
use std::io::Write;
pub fn export_row<W: Write>(out: &mut W, user: &str, comment: &str) -> std::io::Result<()> {
    writeln!(out, "\"{}\",\"{}\"", user.replace('"', "\"\""), comment.replace('"', "\"\""))
}
