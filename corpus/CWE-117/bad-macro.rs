//@ kind: language
//@ deps: corten-std
//@ expect: no rules expected
fn main() {
    let event = String::from("login");
    let _r = corten_std::log_record!(event, user = "x");
}
