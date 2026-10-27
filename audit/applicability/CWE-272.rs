//@ compiles: safe
// CWE-272, least privilege violation: after chroot (which needs root) the
// process keeps root and goes on to handle untrusted requests.
pub fn serve(jail: &str, handle: impl Fn(&[u8]), requests: &[Vec<u8>]) -> std::io::Result<()> {
    std::os::unix::fs::chroot(jail)?;
    std::env::set_current_dir("/")?;
    // privileges should be dropped here; they are not
    for r in requests {
        handle(r);
    }
    Ok(())
}
