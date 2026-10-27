//@ deps: corten-std
// Matched benign program: files opened through a DirCap are close-on-exec.
use corten_std::fs::{DirCap, OpenMode, rel};

pub fn open_log(dir: &DirCap) -> Result<(), String> {
    let path = rel("app.log").map_err(|e| e.to_string())?;
    let _file = dir.open_file(&path, OpenMode::Append).map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    let f: fn(&DirCap) -> Result<(), String> = open_log;
    let _keep = f;
}
