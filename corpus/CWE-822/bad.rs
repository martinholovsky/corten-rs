//@ expect: -F unsafe-code
// CWE-822: dereferences an address taken from input.
fn read_at(addr: usize) -> u32 {
    unsafe { *std::ptr::with_exposed_provenance::<u32>(addr) }
}
fn main() {
    println!("{}", read_at(0x1000));
}
