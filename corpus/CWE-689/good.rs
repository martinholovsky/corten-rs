//@ deps: corten-std
// CWE-689 matched benign program: a new file through a DirCap, with its mode named.
use corten_std::fs::{DirCap, FileMode, OpenMode, rel};

pub fn save(dir: &DirCap, body: &[u8]) -> Result<(), String> {
    let path = rel("report.txt").map_err(|e| e.to_string())?;
    let file = dir
        .open_file(&path, OpenMode::CreateExclusive(FileMode::OwnerOnly))
        .map_err(|e| e.to_string())?;
    file.write_all(body).map_err(|e| e.to_string())
}

fn main() {
    let f: fn(&DirCap, &[u8]) -> Result<(), String> = save;
    let _keep = f;
}
