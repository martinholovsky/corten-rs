//@ compiles: safe
// CWE-440, expected behavior violation: Ord promises a total order; this
// impl says every value is less than every other, so sort/BTreeMap misbehave.
use std::cmp::Ordering;
#[derive(PartialEq, Eq)]
pub struct Version(pub u32);
impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Version {
    fn cmp(&self, _o: &Self) -> Ordering {
        Ordering::Less
    }
}
