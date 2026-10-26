//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let r = corten_std::log::LogRecord { event: "x", fields: Vec::new() };
    println!("{r:?}");
}
