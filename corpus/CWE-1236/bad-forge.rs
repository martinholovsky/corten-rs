//@ kind: language
//@ deps: corten-std
//@ expect: private
fn main() {
    let c = corten_std::csv::CsvCell(String::from("=HYPERLINK(\"x\")"));
    println!("{c:?}");
}
