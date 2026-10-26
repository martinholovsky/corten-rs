//@ expect: expected one of
//@ absent
// CWE-484: a switch case that falls through. Rust has no switch.
fn main() {
    let v = 1;
    switch (v) {
        case 1: println!("one");
        case 2: println!("two");
    }
}
