//@ kind: language
//@ deps: corten-std
//@ expect: html!: a placeholder is in a context
// CWE-838 bypass-hunt variant: calling Html::from_template directly with a
// hand-written Template skips the macro's check-time assertion. The check
// inside from_template still fails the build, but `cargo check` (and so
// `cargo corten check`) does not evaluate it. Not detected under check;
// recorded in docs/gates/phase-2.md.
struct Link;
impl corten_std::template::Template for Link {
    const TEXT: &'static str = "<a href=\"{}\">x</a>";
}
fn main() {
    let url = corten_std::html::HtmlArg::from("javascript:alert(1)");
    let page = corten_std::html::Html::from_template::<Link, 1>([url]);
    println!("{}", page.as_str());
}
