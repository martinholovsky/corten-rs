//@ compiles: safe
// CWE-1123, self-modifying code: on Linux a safe program can write its own
// code pages through /proc/self/mem, which std documents as outside Rust's
// safety guarantees. Here it patches `target` to return immediately.
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
pub fn target() -> u32 {
    1
}
pub fn patch() -> std::io::Result<()> {
    let addr = target as fn() -> u32 as usize as u64;
    let mut mem = OpenOptions::new().write(true).open("/proc/self/mem")?;
    mem.seek(SeekFrom::Start(addr))?;
    mem.write_all(&[0xc3])
}
