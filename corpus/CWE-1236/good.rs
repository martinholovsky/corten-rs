//@ deps: corten-std
use corten_std::csv::{CsvCell, CsvWriter};

pub fn export<W: CsvWriter>(out: &mut W, name: &str) -> Result<(), W::Error> {
    out.write_row(&[CsvCell::new(name), CsvCell::new("1")])
}

fn main() {}
