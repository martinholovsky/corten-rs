//@ compiles: safe
// CWE-274, improper handling of insufficient privileges: when the process may
// not open the audit log, it silently turns auditing off and continues.
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
pub fn open_audit_log(path: &str) -> Option<File> {
    match OpenOptions::new().append(true).open(path) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => None,
        Err(_) => None,
    }
}
