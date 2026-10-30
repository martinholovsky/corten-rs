//@ compiles: unsafe
// CWE-560, umask() with a chmod-style argument: 0o644 is meant as "rw-r--r--"
// but umask removes those bits. std has no umask; libc's needs unsafe.
// (mode_t width varies by platform; declared as u32 here.)
unsafe extern "C" {
    fn umask(mask: u32) -> u32;
}
pub fn set_file_mode() {
    unsafe {
        umask(0o644);
    }
}
