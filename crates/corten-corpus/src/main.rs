//! `corten-corpus`: runs the compile-fail corpus against `cargo corten check`
//! and reports detection and false rejection side by side (`AGENTS.md` rule 2).
//!
//! Each E row whose `proof_test` directory exists has a `bad.rs` (a program
//! exhibiting the weakness) and a `good.rs` (the matched benign program).
//! Header lines in either file configure the case:
//!
//! - `//@ expect: TEXT` (bad.rs, required): the checker's output must contain
//!   TEXT, so a rejection for an unrelated reason does not count.
//! - `//@ deps: corten-std` (either file): the case crate depends on the
//!   workspace's `corten-std`.
//!
//! A case passes when, for proof kind `checker`, plain cargo builds bad.rs
//! (the control), `cargo corten check` rejects it with the expected text and
//! accepts good.rs; for proof kind `language`, plain cargo rejects bad.rs with
//! the expected text and the checker accepts good.rs.
//!
//! Exit status: 0 every case passes, 1 a case fails, 2 usage or I/O error.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::thread;

use corten_ledger::{ERow, Ledger, parse_csv};

const USAGE: &str = "\
Usage: corten-corpus --checker <cargo-corten> [--root <repo>] [--phase <n>]
                     [--report <file.md>] [--mark-verified] [--jobs <n>]

Runs every corpus case named by an E row of ledger/cwe-ledger.csv.
  --mark-verified  set status=verified for passing rows and unverified for failing ones
";

struct Options {
    checker: PathBuf,
    root: PathBuf,
    phase: Option<String>,
    report: Option<PathBuf>,
    mark_verified: bool,
    jobs: usize,
}

fn parse_args() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let mut checker = None;
    let mut root = PathBuf::from(".");
    let mut phase = None;
    let mut report = None;
    let mut mark_verified = false;
    let mut jobs = thread::available_parallelism().map_or(2, std::num::NonZero::get);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--checker" => checker = Some(PathBuf::from(value("--checker")?)),
            "--root" => root = PathBuf::from(value("--root")?),
            "--phase" => phase = Some(value("--phase")?),
            "--report" => report = Some(PathBuf::from(value("--report")?)),
            "--jobs" => {
                jobs = value("--jobs")?
                    .parse()
                    .map_err(|e| format!("--jobs: {e}"))?;
            }
            "--mark-verified" => mark_verified = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    let checker = checker.ok_or("--checker is required")?;
    // Children run in their case directory, so a relative program path would
    // resolve there.
    let checker = std::fs::canonicalize(&checker)
        .map_err(|e| format!("--checker {}: {e}", checker.display()))?;
    Ok(Options {
        checker,
        root,
        phase,
        report,
        mark_verified,
        jobs: jobs.max(1),
    })
}

/// Header directives of one source file.
#[derive(Debug, Default, PartialEq, Eq)]
struct Directives {
    expect: Vec<String>,
    corten_std: bool,
    /// Overrides the row's proof kind for this file.
    kind: Option<String>,
    /// The bad program is written in syntax Rust does not have: the weakest
    /// form of a `language` proof, reported separately.
    absent: bool,
    /// Rust edition of the case crate (default 2024).
    edition: Option<String>,
}

fn directives(source: &str) -> Directives {
    let mut d = Directives::default();
    for line in source.lines() {
        let Some(rest) = line.trim_start().strip_prefix("//@") else {
            continue;
        };
        let rest = rest.trim();
        if let Some(text) = rest.strip_prefix("expect:") {
            d.expect.push(text.trim().to_owned());
        } else if rest
            .strip_prefix("deps:")
            .is_some_and(|v| v.trim() == "corten-std")
        {
            d.corten_std = true;
        } else if let Some(kind) = rest.strip_prefix("kind:") {
            d.kind = Some(kind.trim().to_owned());
        } else if rest == "absent" {
            d.absent = true;
        } else if let Some(edition) = rest.strip_prefix("edition:") {
            d.edition = Some(edition.trim().to_owned());
        }
    }
    d
}

/// Outcome of one build.
struct Build {
    code: Option<i32>,
    output: String,
}

impl Build {
    fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

/// One case's result.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Pass,
    /// Plain cargo did not build bad.rs, so the checker's rule is not shown
    /// to be what rejects it.
    ControlFailed(String),
    /// bad.rs built, or failed without the expected text.
    NotDetected(String),
    /// good.rs did not build under the checker.
    FalseRejection(String),
    /// The case is malformed.
    Broken(String),
}

impl Verdict {
    fn label(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ControlFailed(_) => "control failed",
            Self::NotDetected(_) => "not detected",
            Self::FalseRejection(_) => "false rejection",
            Self::Broken(_) => "broken case",
        }
    }
}

fn excerpt(text: &str) -> String {
    text.lines()
        .filter(|l| l.contains("error") || l.contains("warning"))
        .take(4)
        .collect::<Vec<_>>()
        .join(" | ")
}

struct Runner<'a> {
    opts: &'a Options,
    cargo: PathBuf,
    work: PathBuf,
}

impl Runner<'_> {
    fn write_crate(&self, dir: &Path, source: &str, d: &Directives) -> io::Result<()> {
        let corten_std = d.corten_std;
        let edition = d.edition.as_deref().unwrap_or("2024");
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        fs::create_dir_all(dir.join("src"))?;
        let deps = if corten_std {
            let std_path = fs::canonicalize(self.opts.root.join("crates/corten-std"))?;
            format!(
                "\n[dependencies]\ncorten-std = {{ path = {:?} }}\n",
                std_path.display().to_string()
            )
        } else {
            String::new()
        };
        let manifest = format!(
            "[package]\nname = \"case\"\nversion = \"0.0.0\"\nedition = \"{edition}\"\n\n[workspace]\n{deps}"
        );
        fs::write(dir.join("Cargo.toml"), manifest)?;
        fs::write(dir.join("src/main.rs"), source)
    }

    fn plain(&self, dir: &Path, target: &Path) -> io::Result<Build> {
        let out = Command::new(&self.cargo)
            .arg("check")
            .current_dir(dir)
            .env("CARGO_TARGET_DIR", target)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_BUILD_WARNINGS")
            .output()?;
        Ok(Build {
            code: out.status.code(),
            output: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn corten(&self, dir: &Path, target: &Path) -> io::Result<Build> {
        let out = Command::new(&self.opts.checker)
            .args(["corten", "check"])
            .current_dir(dir)
            .env("CARGO", &self.cargo)
            .env_remove("RUSTC")
            .env_remove("CARGO_BUILD_WARNINGS")
            .env("CARGO_TARGET_DIR", target)
            .output()?;
        Ok(Build {
            code: out.status.code(),
            output: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Checks one bad variant; `None` means it was rejected as required.
    fn check_bad(
        &self,
        row_kind: &str,
        dir: &Path,
        target: &Path,
        d: &Directives,
    ) -> io::Result<Option<Verdict>> {
        let expected_in = |b: &Build| d.expect.iter().all(|e| b.output.contains(e.as_str()));
        let kind = d.kind.as_deref().unwrap_or(row_kind);
        match kind {
            "checker" => {
                let control = self.plain(dir, target)?;
                if !control.ok() {
                    return Ok(Some(Verdict::ControlFailed(excerpt(&control.output))));
                }
                let checked = self.corten(dir, target)?;
                if checked.ok() || !expected_in(&checked) {
                    return Ok(Some(Verdict::NotDetected(format!(
                        "exit {:?}: {}",
                        checked.code,
                        excerpt(&checked.output)
                    ))));
                }
            }
            "language" => {
                let plain = self.plain(dir, target)?;
                if plain.ok() || !expected_in(&plain) {
                    return Ok(Some(Verdict::NotDetected(format!(
                        "plain exit {:?}: {}",
                        plain.code,
                        excerpt(&plain.output)
                    ))));
                }
            }
            other => {
                return Ok(Some(Verdict::Broken(format!(
                    "unknown proof kind {other:?}"
                ))));
            }
        }
        Ok(None)
    }

    fn run_case(&self, row: &ERow<'_>, target: &Path) -> io::Result<(Verdict, bool)> {
        let case = self.opts.root.join(row.proof_test);
        let mut bad_files: Vec<PathBuf> = fs::read_dir(&case)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "rs")
                    && p.file_stem()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("bad"))
            })
            .collect();
        bad_files.sort();
        let good = fs::read_to_string(case.join("good.rs"))?;
        let good_d = directives(&good);
        let work = self.work.join(row.id);
        let mut absent_only = true;
        for (i, file) in bad_files.iter().enumerate() {
            let source = fs::read_to_string(file)?;
            let d = directives(&source);
            let name = file
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            if d.expect.is_empty() {
                return Ok((
                    Verdict::Broken(format!("{name} has no //@ expect: line")),
                    false,
                ));
            }
            absent_only &= d.absent;
            let dir = work.join(format!("bad-{i}"));
            self.write_crate(&dir, &source, &d)?;
            if let Some(verdict) = self.check_bad(row.proof_kind, &dir, target, &d)? {
                let verdict = match verdict {
                    Verdict::NotDetected(why) => Verdict::NotDetected(format!("{name}: {why}")),
                    Verdict::ControlFailed(why) => Verdict::ControlFailed(format!("{name}: {why}")),
                    other => other,
                };
                return Ok((verdict, false));
            }
        }
        let good_dir = work.join("good");
        self.write_crate(&good_dir, &good, &good_d)?;
        let accepted = self.corten(&good_dir, target)?;
        if !accepted.ok() {
            return Ok((Verdict::FalseRejection(excerpt(&accepted.output)), false));
        }
        fs::remove_dir_all(&work)?;
        Ok((Verdict::Pass, absent_only))
    }
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("error: {message}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&opts) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// One case's outcome, with what the gate needs to judge it.
struct CaseResult {
    kind: String,
    verdict: Verdict,
    /// The row needs an independent encoder review before it may be
    /// verified, so a pass leaves it unverified.
    awaiting_review: bool,
    /// Every bad variant is written in syntax Rust does not have.
    absent_only: bool,
    /// The row's ledger status before this run.
    status: String,
}

type Results = BTreeMap<String, CaseResult>;

/// Counts the gate reports, each over the same denominator.
struct Summary {
    total: usize,
    passed: usize,
    detected: usize,
    false_rejections: usize,
    controls_failed: usize,
    broken: usize,
    absent_only: usize,
    awaiting_review: usize,
}

impl Summary {
    fn of(results: &Results) -> Self {
        let count = |f: &dyn Fn(&CaseResult) -> bool| results.values().filter(|c| f(c)).count();
        Self {
            total: results.len(),
            passed: count(&|c| c.verdict == Verdict::Pass),
            detected: count(&|c| {
                !matches!(
                    c.verdict,
                    Verdict::NotDetected(_) | Verdict::ControlFailed(_) | Verdict::Broken(_)
                )
            }),
            false_rejections: count(&|c| matches!(c.verdict, Verdict::FalseRejection(_))),
            controls_failed: count(&|c| matches!(c.verdict, Verdict::ControlFailed(_))),
            broken: count(&|c| matches!(c.verdict, Verdict::Broken(_))),
            absent_only: count(&|c| c.verdict == Verdict::Pass && c.absent_only),
            awaiting_review: count(&|c| c.verdict == Verdict::Pass && c.awaiting_review),
        }
    }

    /// False rejection above this share of cases stops new rules (owner
    /// threshold, spec section 11): 5 in 100.
    fn false_rejection_over_limit(&self) -> bool {
        // false_rejections / total > 5 / 100, in integers.
        self.false_rejections.saturating_mul(100) > self.total.saturating_mul(5)
    }
}

/// The markdown report: rates with their denominators, then one row per case.
fn render_report(
    scope: &str,
    e_rows: usize,
    without_case: usize,
    results: &Results,
) -> Result<String, std::fmt::Error> {
    use std::fmt::Write as _;
    let s = Summary::of(results);
    let total = s.total;
    let mut r = String::new();
    writeln!(
        r,
        "Corpus run ({scope}): {total} cases for {e_rows} E rows; {without_case} E rows have no case yet.\n"
    )?;
    writeln!(
        r,
        "- Detection: {} of {total} cases had every bad program rejected for the expected reason",
        s.detected
    )?;
    writeln!(
        r,
        "- False rejection: {} of {total} matched good programs failed to build (limit: 5%)",
        s.false_rejections
    )?;
    writeln!(
        r,
        "- Controls failed (plain cargo did not build a checker case's bad program): {}",
        s.controls_failed
    )?;
    writeln!(r, "- Broken cases: {}", s.broken)?;
    writeln!(
        r,
        "- Passed: {} of {total}; of those, {} rest only on syntax Rust does not have (weakest evidence)\n",
        s.passed, s.absent_only
    )?;
    writeln!(
        r,
        "- Passed but left unverified until the encoder is independently reviewed: {}\n",
        s.awaiting_review
    )?;
    writeln!(
        r,
        "| CWE | Proof kind | Result | Detail |\n| --- | --- | --- | --- |"
    )?;
    for (id, c) in results {
        let label = if c.verdict == Verdict::Pass && c.awaiting_review {
            "pass (awaiting encoder review)"
        } else if c.verdict == Verdict::Pass && c.absent_only {
            "pass (construct absent)"
        } else {
            c.verdict.label()
        };
        let detail = match &c.verdict {
            Verdict::Pass => String::new(),
            Verdict::ControlFailed(d)
            | Verdict::NotDetected(d)
            | Verdict::FalseRejection(d)
            | Verdict::Broken(d) => d.replace('|', "\\|"),
        };
        writeln!(r, "| {id} | {} | {label} | {detail} |", c.kind)?;
    }
    Ok(r)
}

/// Writes `status` for every row that has a case: verified when it passed.
fn mark_verified(
    ledger_path: &Path,
    text: &str,
    results: &Results,
) -> Result<(), Box<dyn std::error::Error>> {
    let pick = |want: bool| -> Vec<&str> {
        results
            .iter()
            .filter(|(_, c)| (c.verdict == Verdict::Pass && !c.awaiting_review) == want)
            .map(|(id, _)| id.as_str())
            .collect()
    };
    let (passing, failing) = (pick(true), pick(false));
    let updated = corten_ledger::set_status(text, &passing, &failing)?;
    fs::write(ledger_path, updated)?;
    let newly = results
        .values()
        .filter(|c| c.verdict == Verdict::Pass && !c.awaiting_review && c.status != "verified")
        .count();
    eprintln!(
        "ledger: {} rows verified ({newly} newly), {} unverified",
        passing.len(),
        failing.len()
    );
    Ok(())
}

fn run(opts: &Options) -> Result<bool, Box<dyn std::error::Error>> {
    let ledger_path = opts.root.join("ledger/cwe-ledger.csv");
    let text = fs::read_to_string(&ledger_path)?;
    let ledger = Ledger::from_records(parse_csv(&text)?)?;
    let rows: Vec<ERow<'_>> = ledger
        .e_rows()
        .into_iter()
        .filter(|r| opts.phase.as_deref().is_none_or(|p| p == r.phase))
        .collect();
    let (cases, missing): (Vec<_>, Vec<_>) = rows
        .iter()
        .partition(|r| opts.root.join(r.proof_test).join("good.rs").is_file());

    let cargo = env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from);
    let work = env::temp_dir().join(format!("corten-corpus-{}", std::process::id()));
    fs::create_dir_all(&work)?;
    let runner = Runner {
        opts,
        cargo,
        work: work.clone(),
    };

    let queue = Mutex::new(cases.clone());
    let results = Mutex::new(Results::new());
    thread::scope(|scope| {
        // One target directory per worker: dependencies (corten-std and its
        // crates) build once per worker, not once per case. Plain and
        // checker builds use different flags, so cargo never reuses one
        // for the other.
        let (runner, queue, results) = (&runner, &queue, &results);
        for worker in 0..opts.jobs {
            let target = work.join(format!("target-{worker}"));
            scope.spawn(move || {
                loop {
                    let next = queue.lock().ok().and_then(|mut q| q.pop());
                    let Some(row) = next else { break };
                    let (verdict, absent_only) = runner
                        .run_case(row, &target)
                        .unwrap_or_else(|e| (Verdict::Broken(format!("I/O: {e}")), false));
                    if let Ok(mut r) = results.lock() {
                        r.insert(
                            row.id.to_owned(),
                            CaseResult {
                                kind: row.proof_kind.to_owned(),
                                verdict,
                                awaiting_review: row.review == "required",
                                absent_only,
                                status: row.status.to_owned(),
                            },
                        );
                    }
                }
            });
        }
    });
    let results = results.into_inner().map_err(|_| "a worker panicked")?;
    if let Err(e) = fs::remove_dir_all(&work) {
        eprintln!("warning: could not remove {}: {e}", work.display());
    }

    let scope = opts
        .phase
        .as_deref()
        .map_or("all phases".to_owned(), |p| format!("phase {p}"));
    let report = render_report(&scope, rows.len(), missing.len(), &results)?;
    print!("{report}");
    if let Some(path) = &opts.report {
        fs::write(path, &report)?;
    }

    // Gate: a verified row must still pass, and nothing may be broken,
    // falsely rejected or uncontrolled. A not-yet-detected case on an
    // unverified row is reported, not failed: its mechanism is still to come.
    let summary = Summary::of(&results);
    let regressions: Vec<&str> = rows
        .iter()
        .filter(|r| r.status == "verified")
        .filter(|r| results.get(r.id).is_none_or(|c| c.verdict != Verdict::Pass))
        .map(|r| r.id)
        .collect();
    let mut gate_ok = true;
    if !regressions.is_empty() {
        eprintln!("gate: verified rows that no longer pass: {regressions:?}");
        gate_ok = false;
    }
    if summary.broken > 0 || summary.controls_failed > 0 || summary.false_rejections > 0 {
        eprintln!(
            "gate: {} broken, {} failed controls, {} false rejections",
            summary.broken, summary.controls_failed, summary.false_rejections
        );
        gate_ok = false;
    }
    if summary.false_rejection_over_limit() {
        eprintln!("gate: false rejection is above the 5% limit; fix rules before adding any");
    }

    if opts.mark_verified {
        mark_verified(&ledger_path, &text, &results)?;
    }
    Ok(gate_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directives_are_parsed() {
        let d = directives(
            "//@ kind: language\n//@ expect: E0381\n//@ expect: x\n//@ deps: corten-std\n//@ absent\nfn main() {}\n",
        );
        assert_eq!(
            d,
            Directives {
                expect: vec!["E0381".to_owned(), "x".to_owned()],
                corten_std: true,
                kind: Some("language".to_owned()),
                absent: true,
                edition: None,
            }
        );
    }
}
