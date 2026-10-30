//@ rejected: cannot be dereferenced
// CWE-476: the safe "nullable reference" is Option<&T>, which cannot be
// dereferenced without first handling None.
pub fn read(p: Option<&i32>) -> i32 {
    *p
}
