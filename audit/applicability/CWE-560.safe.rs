//@ rejected: requires unsafe block
// CWE-560: calling umask without unsafe is refused.
unsafe extern "C" {
    fn umask(mask: u32) -> u32;
}
pub fn set_file_mode() {
    umask(0o644);
}
