fn main() {
    let handle = std::thread::spawn(|| 1u32);
    println!("{:?}", handle.join());
}
