//@ compiles: safe
// CWE-581, equals and hashcode inconsistent: equality ignores ASCII case,
// the derived Hash does not, so equal keys hash differently.
#[derive(Hash)]
pub struct Email(pub String);
impl PartialEq for Email {
    fn eq(&self, o: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&o.0)
    }
}
impl Eq for Email {}
