struct Header {
    len: u8,
}
fn main() {
    let bytes = [3u8, 0, 0, 0];
    let [len, ..] = bytes;
    let h = Header { len };
    println!("{}", h.len);
}
