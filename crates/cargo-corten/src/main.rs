//! `cargo corten`: builds a crate under the Corten profile.
//!
//! Exit status: 0 when the build passes, 1 when it fails (a rule or an
//! ordinary compile error), 2 for a usage or environment error.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use cargo_corten::{Toolchain, check_command};

const USAGE: &str = "\
Build a crate under the Corten profile, with flags the checker supplies itself.

Usage: cargo corten check [--manifest-path <PATH>]

Options:
      --manifest-path <PATH>  Path to Cargo.toml (default: search from the current directory)
  -h, --help                  Print help
  -V, --version               Print version

Exit status: 0 passed, 1 build failed, 2 usage or environment error.
";

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

enum Invocation {
    Help,
    Version,
    Check { manifest_path: Option<PathBuf> },
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut args = args.into_iter().peekable();
    // Cargo runs `cargo-corten corten <args>`; accept a direct call without it.
    if args.peek().is_some_and(|a| a == "corten") {
        args.next();
    }
    let mut subcommand = None;
    let mut manifest_path = None;
    while let Some(arg) = args.next() {
        let Some(text) = arg.to_str() else {
            return Err(format!("unexpected argument {}", arg.display()));
        };
        match text {
            "-h" | "--help" => return Ok(Invocation::Help),
            "-V" | "--version" => return Ok(Invocation::Version),
            "--manifest-path" => {
                let value = args.next().ok_or("--manifest-path needs a value")?;
                manifest_path = Some(PathBuf::from(value));
            }
            _ if text.starts_with("--manifest-path=") => {
                let value = text.trim_start_matches("--manifest-path=");
                manifest_path = Some(PathBuf::from(value));
            }
            "check" if subcommand.is_none() => subcommand = Some(()),
            _ => return Err(format!("unexpected argument '{text}'")),
        }
    }
    match subcommand {
        Some(()) => Ok(Invocation::Check { manifest_path }),
        None => Err("missing subcommand; the only one is `check`".to_owned()),
    }
}

fn main() -> ExitCode {
    let invocation = match parse(env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let manifest_path = match invocation {
        Invocation::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Invocation::Version => {
            println!("cargo-corten {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Invocation::Check { manifest_path } => manifest_path,
    };
    let toolchain = match Toolchain::from_env(env::var_os("CARGO"), env::var_os("RUSTC")) {
        Ok(toolchain) => toolchain,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    // No deadline: this is an interactive build, and Ctrl-C reaches cargo
    // through the shared process group. `status` waits, so no child outlives us.
    match check_command(&toolchain, manifest_path.as_deref()).status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => {
            eprintln!("cargo corten check: failed ({status})");
            ExitCode::from(EXIT_FAILED)
        }
        Err(e) => {
            eprintln!("error: could not run {}: {e}", toolchain.cargo.display());
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Invocation, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn accepts_cargo_subcommand_form() {
        assert!(matches!(
            run(&["corten", "check"]),
            Ok(Invocation::Check {
                manifest_path: None
            })
        ));
    }

    #[test]
    fn accepts_both_manifest_path_forms() {
        for args in [
            &["check", "--manifest-path", "a/Cargo.toml"][..],
            &["check", "--manifest-path=a/Cargo.toml"][..],
        ] {
            let Ok(Invocation::Check { manifest_path }) = run(args) else {
                panic!("{args:?} did not parse");
            };
            assert_eq!(manifest_path, Some(PathBuf::from("a/Cargo.toml")));
        }
    }

    #[test]
    fn rejects_unknown_and_missing_arguments() {
        assert!(run(&["check", "--release"]).is_err());
        assert!(run(&["build"]).is_err());
        assert!(run(&["corten"]).is_err());
        assert!(run(&["check", "--manifest-path"]).is_err());
        assert!(run(&["check", "check"]).is_err());
    }
}
