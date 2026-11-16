//! Reading a private key file, refused as `corten-manifest` refuses its key
//! file: a symbolic link or anything but a regular file, a mode that lets
//! group or others in, a directory group or others can write, or an owner
//! other than the directory's. Used for the token-minting key
//! ([`crate::mint`]) and the provider client key ([`crate::cli`]).

use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// Reads at most `max` bytes of a private key file after the checks above.
///
/// # Errors
///
/// A message naming the file and the refusal.
pub fn read_private(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{shown} is accessible to group or others (mode {:o}); chmod 600 it",
            meta.mode() & 0o7777
        ));
    }
    let dir = path
        .parent()
        .ok_or_else(|| format!("{shown} has no directory"))?;
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let dir_meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if dir_meta.mode() & 0o022 != 0 {
        return Err(format!("{} is writable by group or others", dir.display()));
    }
    if meta.uid() != dir_meta.uid() {
        return Err(format!(
            "{shown} is owned by uid {}, not by its directory's owner (uid {})",
            meta.uid(),
            dir_meta.uid()
        ));
    }
    let mut bytes = Vec::new();
    let _read = std::fs::File::open(path)
        .map_err(|e| format!("{shown}: {e}"))?
        .take(max)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{shown}: {e}"))?;
    Ok(bytes)
}
