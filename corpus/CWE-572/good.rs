//@ deps: corten-std
fn main() {
    let handle = corten_std::thread::spawn(|| 1u32);
    println!("{:?}", handle.join());
}
