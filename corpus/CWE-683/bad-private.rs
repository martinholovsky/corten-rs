//@ expect: labelled
// CWE-683 bypass-hunt variant: the same swap through a private function. The
// spec requires labels on public functions only (4.2), so the lint does not
// look here; requiring them everywhere falsely rejected 4 of 174 matched good
// programs (docs/gates/phase-3b.md). Not detected.
fn transfer(from_account: u32, to_account: u32) -> (u32, u32) {
    (from_account, to_account)
}
fn main() {
    let from = 1;
    let to = 2;
    println!("{:?}", transfer(to, from));
}
