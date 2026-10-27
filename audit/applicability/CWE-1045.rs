//@ rejected: after struct name, found `:`
// CWE-1045: Rust has no class inheritance, so no parent/child destructor
// pair; the closest spelling, a struct deriving from another, is refused.
pub struct Parent;
pub struct Child: Parent {}
