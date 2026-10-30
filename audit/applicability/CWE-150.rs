//@ compiles: safe
// CWE-150, escape/control sequences. A file name holding "\x1b]0;...\x07"
// or cursor-movement escapes is printed raw to the terminal.
use std::io::Write;
pub fn report<W: Write>(term: &mut W, file_name: &str) -> std::io::Result<()> {
    writeln!(term, "deleted {file_name}")
}
