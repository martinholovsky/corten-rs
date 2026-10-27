//@ compiles: safe
// CWE-1074, excessively deep inheritance: a supertrait chain eight levels
// deep; rustc sets no limit.
pub trait L1 {}
pub trait L2: L1 {}
pub trait L3: L2 {}
pub trait L4: L3 {}
pub trait L5: L4 {}
pub trait L6: L5 {}
pub trait L7: L6 {}
pub trait L8: L7 {}
pub struct Leaf;
impl L1 for Leaf {}
impl L2 for Leaf {}
impl L3 for Leaf {}
impl L4 for Leaf {}
impl L5 for Leaf {}
impl L6 for Leaf {}
impl L7 for Leaf {}
impl L8 for Leaf {}
