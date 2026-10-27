//@ kind: language
//@ deps: corten-std
//@ expect: html!: a placeholder is in a context
// CWE-82: a value placed where escaping cannot make it safe.
fn main() {
    let value = "javascript:alert(1)";
    let _p = corten_std::html!("<img src=\"{}\">", value);
}
