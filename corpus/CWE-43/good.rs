//@ deps: corten-std
// Matched benign program: one validated segment beneath a granted DirCap.
use corten_std::fs::{DirCap, OpenMode, rel};

pub fn read_upload(uploads: &DirCap, name: &str) -> Result<Vec<u8>, String> {
    let path = rel(name).map_err(|e| e.to_string())?;
    let file = uploads.open_file(&path, OpenMode::Read).map_err(|e| e.to_string())?;
    file.read_to_end(1_048_576).map_err(|e| e.to_string())
}

fn main() {
    let reader: fn(&DirCap, &str) -> Result<Vec<u8>, String> = read_upload;
    let _keep = reader;
}
