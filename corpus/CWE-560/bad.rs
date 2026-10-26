//@ expect: -F unsafe-code
// CWE-560: calls umask with a chmod-style argument.
unsafe extern "C" {
    fn umask(mask: u32) -> u32;
}
fn main() {
    let previous = unsafe { umask(0o644) };
    println!("{previous}");
}
