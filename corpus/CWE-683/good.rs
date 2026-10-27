struct Src<'a>(&'a [u8]);
struct Dst<'a>(&'a mut [u8]);
fn copy_bytes(src: Src<'_>, dst: Dst<'_>) {
    dst.0.copy_from_slice(src.0);
}
fn main() {
    let input = [1u8, 2];
    let mut output = [0u8; 2];
    copy_bytes(Src(&input), Dst(&mut output));
    println!("{output:?}");
}
