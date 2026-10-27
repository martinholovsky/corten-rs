//@ lint: corten_labelled_params
//@ expect: parameters share a type (2 × `u32`)
//@ expect: parameters share a type (2 × `&[u8]`)
//@ count: 2
pub fn transfer(from: u32, to: u32) -> u32 {
    from.saturating_sub(to)
}
pub fn copy(src: &[u8], dst: &[u8]) -> bool {
    src == dst
}
pub struct Account;
impl Account {
    // Not reported: distinct types, and the receiver does not count.
    pub fn send(&self, amount: u32, fee: u64) -> u64 {
        u64::from(amount).saturating_add(fee)
    }
}
// Not reported: private.
fn swap(a: u32, b: u32) -> (u32, u32) {
    (b, a)
}
// Not reported: a trait implementation's signature is the trait's.
impl std::ops::Add for Account {
    type Output = Account;
    fn add(self, _other: Account) -> Account {
        self
    }
}
fn main() {
    println!("{:?} {}", swap(1, 2), transfer(3, 1));
    println!("{} {}", copy(&[1], &[1]), Account.send(1, 2));
    let _sum = Account + Account;
}
