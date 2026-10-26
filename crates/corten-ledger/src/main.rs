//! `corten-ledger check|totals [PATH]`.
//!
//! Exit status: 0 the gate passes (or totals printed), 1 the ledger has
//! problems, 2 usage error or unreadable file.

use std::env;
use std::fs;
use std::process::ExitCode;

use corten_ledger::{Ledger, parse_csv};

const DEFAULT_PATH: &str = "ledger/cwe-ledger.csv";
const USAGE: &str =
    "Usage: corten-ledger <check|totals> [PATH]  (default PATH: ledger/cwe-ledger.csv)";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, path) = match args.as_slice() {
        [c] => (c.as_str(), DEFAULT_PATH),
        [c, p] => (c.as_str(), p.as_str()),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if !matches!(command, "check" | "totals") {
        eprintln!("unknown command {command:?}\n{USAGE}");
        return ExitCode::from(2);
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let ledger = match parse_csv(&text)
        .map_err(|e| e.to_string())
        .and_then(|records| Ledger::from_records(records).map_err(|e| e.to_string()))
    {
        Ok(ledger) => ledger,
        Err(e) => {
            eprintln!("error: {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if command == "totals" {
        print!("{}", ledger.totals());
        return ExitCode::SUCCESS;
    }
    let problems = ledger.check();
    for problem in &problems {
        eprintln!("{problem}");
    }
    let e_rows = ledger.e_rows().len();
    if problems.is_empty() {
        println!(
            "ledger gate passes: {} rows checked, {e_rows} E rows each name a mechanism, TCB assumption and proof test",
            ledger.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "ledger gate fails: {} problems in {} rows",
            problems.len(),
            ledger.len()
        );
        ExitCode::from(1)
    }
}
