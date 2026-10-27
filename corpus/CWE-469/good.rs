fn main() {
    let xs = [1u32, 2, 3, 4];
    let (head, _) = xs.split_at(2);
    println!("{}", head.len());
}
