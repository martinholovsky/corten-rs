//@ compiles: safe
// CWE-96, static code injection. The site title is written into a Lua
// config file that is later executed; a title of `"; os.execute("id") --`
// becomes code in that file.
use std::io::Write;
pub fn save_config<W: Write>(out: &mut W, title: &str) -> std::io::Result<()> {
    writeln!(out, "site_title = \"{title}\"")
}
