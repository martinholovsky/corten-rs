//@ deps: corten-std
use corten_std::fs::DirCap;

pub fn scratch(work: &DirCap) -> Result<String, String> {
    let (name, file) = work.create_temp().map_err(|e| e.to_string())?;
    file.write_all(b"draft").map_err(|e| e.to_string())?;
    Ok(name.to_string())
}

fn main() {
    let f: fn(&DirCap) -> Result<String, String> = scratch;
    let _keep = f;
}
