//@ kind: language
//@ deps: corten-std
//@ expect: xpath!: write the placeholder bare
fn main() {
    let name = "x' or '1'='1";
    let _e = corten_std::xpath!("//user[name='{}']", name);
}
