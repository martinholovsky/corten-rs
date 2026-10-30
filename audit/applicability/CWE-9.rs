//@ rejected: cannot find attribute
// CWE-9, J2EE weak access permissions for EJB methods. Rust has no EJB
// container or deployment descriptor; the closest spelling, a method
// permission annotation granting every role, is not an attribute rustc knows.
pub struct AccountBean;
impl AccountBean {
    #[method_permission(role = "*")]
    pub fn transfer(&self, _amount: u64) {}
}
