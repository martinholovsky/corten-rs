//@ expect: labelled
// CWE-683: two same-typed parameters passed in the wrong order. Caught by
// the labelled-parameter lint (corten-driver, Phase 3b).
pub fn transfer(from_account: u32, to_account: u32) -> (u32, u32) {
    (from_account, to_account)
}
fn main() {
    let from = 1;
    let to = 2;
    println!("{:?}", transfer(to, from));
}
