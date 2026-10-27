//@ rejected: after struct name, found `:`
// CWE-1055: a type cannot inherit from concrete types at all; only traits
// (which carry no fields) can be implemented. The spelling is refused.
pub struct A;
pub struct B;
pub struct C: A + B {}
