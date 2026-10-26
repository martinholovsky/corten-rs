//@ kind: language
//@ deps: corten-std
//@ expect: mismatched types
// CWE-1236: a CSV field written as raw text.
use corten_std::csv::CsvWriter;

pub fn export<W: CsvWriter>(out: &mut W, name: &str) -> bool {
    let row = [name.to_owned()];
    out.write_row(&row).is_ok()
}

fn main() {}
