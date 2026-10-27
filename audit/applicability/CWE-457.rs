//@ rejected: isn't initialized
// CWE-457, use of an uninitialised variable. The natural C-style spelling,
// declare then read, is rejected by rustc (E0381).
pub fn checksum() -> u32 {
    let sum: u32;
    sum
}
