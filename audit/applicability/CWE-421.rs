//@ compiles: safe
// CWE-421, race condition during access to an alternate channel: the
// out-of-band handoff file is created with default permissions and only
// restricted afterwards, so another local user can open it in the window.
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
pub fn hand_off_token(path: &str, token: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(token)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
