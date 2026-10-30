//@ compiles: safe
// CWE-59, link following. std::fs::write follows a symlink planted at the
// path, so a privileged process overwrites whatever the link points to.
pub fn write_report(user_dir: &str, body: &[u8]) -> std::io::Result<()> {
    std::fs::write(format!("{user_dir}/report.txt"), body)
}
