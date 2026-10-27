//@ kind: checker
//@ deps: corten-std
//@ expect: called directly
// CWE-838 bypass-hunt variant: calling Html::from_template directly with a
// hand-written Template skips the macro's check-time assertion. The check
// inside from_template still fails the build, but `cargo check` does not
// evaluate it (docs/gates/phase-2.md). The direct-template lint
// (corten-driver, Phase 3b) refuses the call itself.
struct Link;
impl corten_std::template::Template for Link {
    const TEXT: &'static str = "<a href=\"{}\">x</a>";
}
fn main() {
    let url = corten_std::html::HtmlArg::from("javascript:alert(1)");
    let page = corten_std::html::Html::from_template::<Link, 1>([url]);
    println!("{}", page.as_str());
}
