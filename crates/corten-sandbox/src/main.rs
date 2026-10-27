//! `corten-sandbox`: confines itself with Landlock, then runs a program.
//!
//! ```text
//! corten-sandbox [--ro PATH]... [--rw PATH]... [--exec PATH]... [--system] [--allow-net]
//!                [--manifest FILE --signature FILE --public-key HEX]
//!                -- PROGRAM [ARGS]...
//! ```
//!
//! - `--ro PATH`: read files and list directories beneath `PATH`.
//! - `--rw PATH`: also create, write and remove beneath `PATH`.
//! - `--exec PATH`: read and execute beneath `PATH` (the program itself, at
//!   least).
//! - `--system`: read and execute the usual system directories (`/usr`,
//!   `/lib`, `/lib64`, `/bin`, `/etc/ld.so.cache`) that dynamically linked
//!   programs need.
//! - `--allow-net`: leave TCP bind and connect unrestricted. Without it, both
//!   are denied.
//! - `--manifest`, `--signature`, `--public-key`: the layer 5 mode. The
//!   signed capability manifest is verified (Ed25519, as in
//!   `corten_std::manifest`); each `dir` grant becomes a read-write rule and
//!   each `exec` grant an execute rule. A bad signature refuses the run.
//!
//! Every other filesystem access and, by default, all TCP bind and connect
//! are refused by the kernel for the program and everything it starts. The
//! sandbox uses Landlock ABI v4 as a hard requirement: on a kernel that
//! cannot enforce every rule, or off Linux, it refuses to run the program
//! (exit 3). A path that does not exist is an error, not a skipped rule.
//! A descriptor above 2 open without close-on-exec is refused the same way:
//! the program would inherit it, and Landlock does not restrict a descriptor
//! that is already open.
//!
//! This binary is part of Corten's trusted base (`docs/tcb.md`). It is used
//! by `corten-broker` and is the layer 5 runtime sandbox.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "Usage: corten-sandbox [--ro PATH]... [--rw PATH]... [--exec PATH]... [--system] [--allow-net] [--manifest FILE --signature FILE --public-key HEX] -- PROGRAM [ARGS]...";

/// Exit status when the arguments are wrong.
const EXIT_USAGE: u8 = 2;
/// Exit status when the sandbox cannot be enforced (fail closed).
const EXIT_UNENFORCEABLE: u8 = 3;

/// Directories a dynamically linked program needs, read-only and executable.
const SYSTEM_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/etc/ld.so.cache"];

#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    read_only: Vec<PathBuf>,
    read_write: Vec<PathBuf>,
    execute: Vec<PathBuf>,
    allow_net: bool,
    manifest: Option<ManifestArgs>,
    program: PathBuf,
    args: Vec<OsString>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ManifestArgs {
    manifest: PathBuf,
    signature: PathBuf,
    public_key: String,
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
}

/// Verifies the manifest and adds its grants to the plan.
fn apply_manifest(plan: &mut Plan) -> Result<(), String> {
    let Some(m) = &plan.manifest else {
        return Ok(());
    };
    let manifest =
        std::fs::read(&m.manifest).map_err(|e| format!("{}: {e}", m.manifest.display()))?;
    let signature =
        std::fs::read(&m.signature).map_err(|e| format!("{}: {e}", m.signature.display()))?;
    let key = hex_decode(&m.public_key).ok_or("--public-key must be hexadecimal")?;
    let grants = corten_std::manifest::verify(
        &manifest,
        corten_std::manifest::Signature(&signature),
        corten_std::manifest::PublicKey(&key),
    )
    .map_err(|e| e.to_string())?;
    for grant in grants {
        match grant {
            corten_std::manifest::Grant::Dir { path, .. } => plan.read_write.push(path),
            corten_std::manifest::Grant::Exec { path, .. } => plan.execute.push(path),
        }
    }
    Ok(())
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Plan, String> {
    let mut plan = Plan::default();
    let mut args = args.into_iter();
    let mut program = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--ro") => plan
                .read_only
                .push(args.next().ok_or("--ro needs a path")?.into()),
            Some("--rw") => plan
                .read_write
                .push(args.next().ok_or("--rw needs a path")?.into()),
            Some("--exec") => plan
                .execute
                .push(args.next().ok_or("--exec needs a path")?.into()),
            Some("--system") => plan.execute.extend(SYSTEM_PATHS.iter().map(PathBuf::from)),
            Some("--allow-net") => plan.allow_net = true,
            Some("--manifest") => {
                plan.manifest
                    .get_or_insert_with(ManifestArgs::default)
                    .manifest = args.next().ok_or("--manifest needs a file")?.into();
            }
            Some("--signature") => {
                plan.manifest
                    .get_or_insert_with(ManifestArgs::default)
                    .signature = args.next().ok_or("--signature needs a file")?.into();
            }
            Some("--public-key") => {
                let key = args.next().ok_or("--public-key needs a value")?;
                let key = key.to_str().ok_or("--public-key must be hexadecimal")?;
                key.clone_into(
                    &mut plan
                        .manifest
                        .get_or_insert_with(ManifestArgs::default)
                        .public_key,
                );
            }
            Some("--") => {
                program = Some(PathBuf::from(
                    args.next().ok_or("missing PROGRAM after --")?,
                ));
                plan.args = args.collect();
                break;
            }
            _ => return Err(format!("unexpected argument {}", arg.display())),
        }
    }
    plan.program = program.ok_or("missing -- PROGRAM")?;
    if !plan.program.is_absolute() {
        return Err("PROGRAM must be an absolute path: there is no PATH search".to_owned());
    }
    if let Some(m) = &plan.manifest
        && (m.manifest.as_os_str().is_empty()
            || m.signature.as_os_str().is_empty()
            || m.public_key.is_empty())
    {
        return Err("--manifest, --signature and --public-key go together".to_owned());
    }
    Ok(plan)
}

#[cfg(target_os = "linux")]
mod enforce {
    use super::Plan;
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    };
    use std::path::Path;

    const ABI_REQUIRED: ABI = ABI::V4;

    fn rule(
        path: &Path,
        access: landlock::BitFlags<AccessFs>,
    ) -> Result<PathBeneath<PathFd>, String> {
        let fd = PathFd::new(path).map_err(|e| format!("{}: {e}", path.display()))?;
        // File-only rights for a file; directories get the full set.
        let access = if path.is_dir() {
            access
        } else {
            access & AccessFs::from_file(ABI_REQUIRED)
        };
        Ok(PathBeneath::new(fd, access))
    }

    /// Applies the plan to this process; it holds for everything it execs.
    pub(super) fn apply(plan: &Plan) -> Result<(), String> {
        let read = AccessFs::from_read(ABI_REQUIRED);
        let write = AccessFs::from_all(ABI_REQUIRED);
        let exec = read | AccessFs::Execute;
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI_REQUIRED))
            .map_err(|e| e.to_string())?;
        if !plan.allow_net {
            ruleset = ruleset
                .handle_access(AccessNet::from_all(ABI_REQUIRED))
                .map_err(|e| e.to_string())?;
        }
        let mut created = ruleset.create().map_err(|e| e.to_string())?;
        for (paths, access) in [
            (&plan.read_only, read),
            (&plan.read_write, write),
            (&plan.execute, exec),
        ] {
            for path in paths {
                created = created
                    .add_rule(rule(path, access)?)
                    .map_err(|e| e.to_string())?;
            }
        }
        // No network rules are added: with AccessNet handled, every TCP bind
        // and connect is denied.
        let status = created.restrict_self().map_err(|e| e.to_string())?;
        if status.ruleset == RulesetStatus::FullyEnforced && status.no_new_privs {
            Ok(())
        } else {
            Err(format!("Landlock not fully enforced: {status:?}"))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod enforce {
    use super::Plan;
    pub(super) fn apply(_plan: &Plan) -> Result<(), String> {
        Err("Landlock is Linux only; refusing to run unconfined".to_owned())
    }
}

fn main() -> ExitCode {
    let mut plan = match parse(std::env::args_os().skip(1)) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("corten-sandbox: {e}\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if let Err(e) = apply_manifest(&mut plan) {
        eprintln!("corten-sandbox: manifest refused: {e}");
        return ExitCode::from(EXIT_UNENFORCEABLE);
    }
    // Before Landlock: afterwards /proc may be out of reach. (Off Linux,
    // enforce::apply refuses below.)
    #[cfg(target_os = "linux")]
    if let Err(e) = check_descriptors() {
        eprintln!("corten-sandbox: {e}");
        return ExitCode::from(EXIT_UNENFORCEABLE);
    }
    if let Err(e) = enforce::apply(&plan) {
        eprintln!("corten-sandbox: cannot enforce the sandbox: {e}");
        return ExitCode::from(EXIT_UNENFORCEABLE);
    }
    exec(&plan)
}

/// Refuses to run while a descriptor above 2 lacks close-on-exec: the program
/// would inherit it, and Landlock checks paths when they are opened, not
/// descriptors already open. Closing a descriptor this process does not own
/// needs `unsafe`, so the sandbox fails closed instead (owner decision,
/// 2026-10-27); the parent must close or mark its descriptors.
#[cfg(target_os = "linux")]
fn check_descriptors() -> Result<(), String> {
    const O_CLOEXEC: u32 = 0o2_000_000;
    let unreadable = |e: std::io::Error| format!("cannot read /proc/self/fdinfo: {e}");
    let mut leaked = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fdinfo").map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        let info = std::fs::read_to_string(entry.path()).map_err(unreadable)?;
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
            .ok_or_else(|| format!("no flags in /proc/self/fdinfo/{fd}"))?;
        if flags & O_CLOEXEC == 0 {
            leaked.push(fd);
        }
    }
    if leaked.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "descriptors {leaked:?} are open without close-on-exec and would reach the program; close them before starting the sandbox"
        ))
    }
}

#[cfg(unix)]
fn exec(plan: &Plan) -> ExitCode {
    use std::os::unix::process::CommandExt;
    // exec replaces this process, so the Landlock domain carries over; it
    // only returns on failure.
    let err = std::process::Command::new(&plan.program)
        .args(&plan.args)
        .exec();
    eprintln!(
        "corten-sandbox: cannot execute {}: {err}",
        plan.program.display()
    );
    ExitCode::from(EXIT_UNENFORCEABLE)
}

#[cfg(not(unix))]
fn exec(_plan: &Plan) -> ExitCode {
    ExitCode::from(EXIT_UNENFORCEABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Plan, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn parses_a_plan() {
        let plan = run(&[
            "--ro", "/data", "--rw", "/out", "--system", "--", "/bin/cat", "-n", "x",
        ])
        .unwrap();
        assert_eq!(plan.read_only, [PathBuf::from("/data")]);
        assert_eq!(plan.read_write, [PathBuf::from("/out")]);
        assert!(plan.execute.contains(&PathBuf::from("/usr")));
        assert!(!plan.allow_net);
        assert_eq!(plan.program, PathBuf::from("/bin/cat"));
        assert_eq!(plan.args, [OsString::from("-n"), OsString::from("x")]);
    }

    #[test]
    fn manifest_arguments_go_together() {
        assert!(run(&["--manifest", "/m", "--", "/bin/true"]).is_err());
        let plan = run(&[
            "--manifest",
            "/m",
            "--signature",
            "/s",
            "--public-key",
            "00",
            "--",
            "/bin/true",
        ])
        .unwrap();
        assert!(plan.manifest.is_some());
        assert_eq!(hex_decode("0aFF"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn refuses_relative_programs_and_bad_arguments() {
        assert!(run(&["--", "cat"]).is_err());
        assert!(run(&["--ro"]).is_err());
        assert!(run(&["--bogus", "--", "/bin/cat"]).is_err());
        assert!(run(&["--ro", "/x"]).is_err());
    }
}
