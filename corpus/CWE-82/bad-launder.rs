//@ kind: language
//@ deps: corten-std
//@ expect: E0015
// A template whose text comes from runtime data, laundered through a
// static: an associated const cannot read it.
use std::sync::OnceLock;
static INPUT: OnceLock<String> = OnceLock::new();
struct Runtime;
impl corten_std::template::Template for Runtime {
    const TEXT: &'static str = match INPUT.get() {
        Some(s) => s.as_str(),
        None => "",
    };
}
fn main() {
    let _q = corten_std::html::Html::from_template::<Runtime, 0>([]);
}
