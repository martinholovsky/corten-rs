//@ compiles: safe
// CWE-1086, excessive number of children: eleven implementors of one trait
// (the Rust analog of child classes); rustc sets no limit.
pub trait Handler {}
macro_rules! children {
    ($($n:ident),*) => { $(pub struct $n; impl Handler for $n {})* };
}
children!(A, B, C, D, E, F, G, H, I, J, K);
