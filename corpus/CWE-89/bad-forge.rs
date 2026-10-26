//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let q = corten_std::sql::SqlQuery { template: "DROP TABLE users", params: Vec::new() };
    println!("{q:?}");
}
