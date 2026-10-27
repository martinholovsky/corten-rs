//@ expect: private
fn main() {
    let p = corten_std::refine::Bounded::<0, 10>(50);
    println!("{}", p.get());
}
