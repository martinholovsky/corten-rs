//@ expect: bounded!: the value is outside the range
fn main() {
    let p = corten_std::bounded!(0, 100, 101);
    println!("{}", p.get());
}
