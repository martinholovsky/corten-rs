//! `corten-sandbox`: confines itself with Landlock, then runs a program.
//!
//! ```text
//! corten-sandbox [--ro PATH]... [--rw PATH]... [--exec PATH]... [--system] [--allow-net]
//!                [--manifest FILE --signature FILE --trusted-key ID=HEX... --serial-state FILE]
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
//! - `--manifest`, `--signature`, `--trusted-key`, `--serial-state`: the
//!   layer 5 mode. The signed capability manifest is verified as in
//!   `corten_std::manifest`: with the key its `key` line names among the
//!   `--trusted-key ID=HEX` keys (repeat the flag to rotate keys), refused
//!   at or after its `not-after`, and refused when its serial is below the
//!   one stored in the `--serial-state` file, so an older manifest cannot be
//!   replayed (spec section 8, question 19). The program's SHA-256 must
//!   equal the manifest's `program sha256` line: the launcher opens the
//!   program once, hashes that open file and executes the same file through
//!   `/proc/self/fd`, so the grants reach only the build they were signed for
//!   (finding F4). Only then is a higher serial written to the state file,
//!   atomically, before the program starts; a missing file counts as
//!   serial 0. Each `dir` grant becomes a read-write rule, each `exec`
//!   grant an execute rule, and each `net` grant a TCP connect rule for its
//!   port (Landlock filters by port; `corten_std::net` checks the address).
//!   Any refusal stops the run.
//!
//! Every other filesystem access and, by default, all TCP bind and connect
//! are refused by the kernel for the program and everything it starts. The
//! sandbox uses Landlock ABI v4 as a hard requirement: on a kernel that
//! cannot enforce every rule, or off Linux, it refuses to run the program
//! (exit 3). Where the kernel has ABI v6 (Linux 6.12), the program also
//! cannot signal a process outside the sandbox or connect to an abstract
//! UNIX socket created outside it; older kernels run without those scopes. A path that does not exist is an error, not a skipped rule.
//! A descriptor above 2 open without close-on-exec is refused the same way:
//! the program would inherit it, and Landlock does not restrict a descriptor
//! that is already open.
//!
//! This binary is part of Corten's trusted base (`docs/tcb.md`). It is used
//! by `corten-broker` and is the layer 5 runtime sandbox.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "Usage: corten-sandbox [--ro PATH]... [--rw PATH]... [--exec PATH]... [--system] [--allow-net] [--manifest FILE --signature FILE --trusted-key ID=HEX... --serial-state FILE] -- PROGRAM [ARGS]...";

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
    /// TCP ports the manifest's `net` grants may connect to.
    connect_ports: Vec<u16>,
    manifest: Option<ManifestArgs>,
    /// The program digest the verified manifest pins (manifest mode only).
    program_sha256: Option<[u8; 32]>,
    program: PathBuf,
    args: Vec<OsString>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ManifestArgs {
    manifest: PathBuf,
    signature: PathBuf,
    /// `(id, hex key)` pairs, in argument order.
    trusted_keys: Vec<(String, String)>,
    serial_state: PathBuf,
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

/// The high-water serial in `path`: 0 when the file does not exist. Any
/// other content than one decimal number (and an optional newline) is an
/// error, never 0, so a damaged file cannot reopen replay.
fn read_serial(path: &std::path::Path) -> Result<u64, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = text.strip_suffix('\n').unwrap_or(&text);
            let canonical = !text.is_empty()
                && text.bytes().all(|b| b.is_ascii_digit())
                && (text == "0" || !text.starts_with('0'));
            if !canonical {
                return Err(format!("{}: not a serial", path.display()));
            }
            text.parse()
                .map_err(|_| format!("{}: not a serial", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Writes `serial` to `path` atomically: a temporary file beside it, synced,
/// then renamed over it.
fn write_serial(path: &std::path::Path, serial: u64) -> Result<(), String> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let err = |e: std::io::Error| format!("{}: {e}", tmp.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(err)?;
    f.write_all(format!("{serial}\n").as_bytes()).map_err(err)?;
    f.sync_all().map_err(err)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Largest program file hashed against a manifest, in bytes: the whole file
/// is read, so the bound keeps a hostile path from exhausting memory.
const MAX_PROGRAM: u64 = 1 << 30;

/// Opens `program` and checks its SHA-256 against the manifest's
/// `program sha256` line (finding F4). The open file is returned and is
/// what [`exec`] runs, through `/proc/self/fd`, so the binary cannot be
/// swapped between this check and the exec. Off Linux nothing is executed
/// (the sandbox refuses), so the check is the same everywhere.
fn open_pinned(program: &std::path::Path, want: &[u8; 32]) -> Result<std::fs::File, String> {
    use std::io::Read;
    let file = std::fs::File::open(program).map_err(|e| format!("{}: {e}", program.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", program.display()))?
        .len();
    if len > MAX_PROGRAM {
        return Err(format!(
            "{} is {len} bytes, over the {MAX_PROGRAM}-byte limit for hashing",
            program.display()
        ));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_PROGRAM.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let got = corten_sha256::digest(&bytes);
    if &got != want {
        return Err(format!(
            "{} has SHA-256 {}, but the manifest is for {}: refusing to grant it the manifest's capabilities",
            program.display(),
            corten_sha256::hex(&got),
            corten_sha256::hex(want)
        ));
    }
    Ok(file)
}

/// Verifies the manifest, checks the program against its digest, and adds
/// its grants to the plan. Returns the opened program in manifest mode.
fn apply_manifest(plan: &mut Plan) -> Result<Option<std::fs::File>, String> {
    let Some(m) = &plan.manifest else {
        return Ok(None);
    };
    let manifest =
        std::fs::read(&m.manifest).map_err(|e| format!("{}: {e}", m.manifest.display()))?;
    let signature =
        std::fs::read(&m.signature).map_err(|e| format!("{}: {e}", m.signature.display()))?;
    let mut keys = corten_std::manifest::TrustedKeys::new();
    for (id, hex) in &m.trusted_keys {
        let key = hex_decode(hex).ok_or("--trusted-key must be ID=HEX")?;
        keys.add(
            corten_std::manifest::KeyId(id),
            corten_std::manifest::PublicKey(&key),
        )
        .map_err(|e| format!("--trusted-key {id}: {e}"))?;
    }
    let stored = read_serial(&m.serial_state)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the system clock is before 1970".to_owned())?
        .as_secs();
    let verified = corten_std::manifest::verify(
        &manifest,
        corten_std::manifest::Signature(&signature),
        &keys,
        corten_std::manifest::UnixTime(now),
        corten_std::manifest::MinSerial(stored),
    )
    .map_err(|e| e.to_string())?;
    // Before the serial is advanced: a refused binary leaves no trace.
    let program = open_pinned(&plan.program, &verified.program_sha256)?;
    plan.program_sha256 = Some(verified.program_sha256);
    if verified.serial > stored {
        write_serial(&m.serial_state, verified.serial)?;
    }
    for grant in verified.grants {
        match grant {
            corten_std::manifest::Grant::Dir { path, .. } => plan.read_write.push(path),
            corten_std::manifest::Grant::Exec { path, .. } => plan.execute.push(path),
            // Not a filesystem grant: nothing for Landlock.
            corten_std::manifest::Grant::Declassify { .. } => {}
            // Landlock filters TCP by port, not address: the address check is
            // corten_std::net's.
            corten_std::manifest::Grant::Net { port, host, .. } => {
                plan.connect_ports.push(port);
                // A host grant resolves through the system resolver, which
                // falls back to TCP port 53 for large answers (UDP is not
                // restricted by Landlock).
                if matches!(host, corten_std::net::Host::Name(_)) {
                    plan.connect_ports.push(53);
                }
            }
            // DNS over TLS to the manifest's public resolver.
            corten_std::manifest::Grant::DnsFallback { .. } => plan.connect_ports.push(853),
        }
    }
    Ok(Some(program))
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
            Some("--trusted-key") => {
                let value = args.next().ok_or("--trusted-key needs ID=HEX")?;
                let value = value.to_str().ok_or("--trusted-key must be ID=HEX")?;
                let (id, hex) = value
                    .split_once('=')
                    .ok_or("--trusted-key must be ID=HEX")?;
                plan.manifest
                    .get_or_insert_with(ManifestArgs::default)
                    .trusted_keys
                    .push((id.to_owned(), hex.to_owned()));
            }
            Some("--serial-state") => {
                plan.manifest
                    .get_or_insert_with(ManifestArgs::default)
                    .serial_state = args.next().ok_or("--serial-state needs a file")?.into();
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
            || m.trusted_keys.is_empty()
            || m.serial_state.as_os_str().is_empty())
    {
        return Err(
            "--manifest, --signature, --trusted-key and --serial-state go together".to_owned(),
        );
    }
    Ok(plan)
}

#[cfg(target_os = "linux")]
mod enforce {
    use super::Plan;
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, LandlockStatus, NetPort,
        PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, Scope,
    };
    use std::path::Path;

    const ABI_REQUIRED: ABI = ABI::V4;
    /// Scoping signals and abstract UNIX sockets to the sandbox's own domain
    /// needs ABI v6 (Linux 6.12). It is requested wherever the kernel has it;
    /// below v6 the v4 rules still hold and the scopes are absent
    /// (`docs/tcb.md`).
    const ABI_SCOPES: ABI = ABI::V6;

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
        // Best effort for the scopes only, then back to a hard requirement:
        // the created ruleset and its rules inherit the level set last.
        let ruleset = ruleset
            .set_compatibility(CompatLevel::BestEffort)
            .scope(Scope::from_all(ABI_SCOPES))
            .map_err(|e| e.to_string())?
            .set_compatibility(CompatLevel::HardRequirement);
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
        // With AccessNet handled, every TCP bind and connect is denied except
        // connects to the ports the manifest's `net` grants name.
        if !plan.allow_net {
            for &port in &plan.connect_ports {
                created = created
                    .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                    .map_err(|e| e.to_string())?;
            }
        }
        let status = created.restrict_self().map_err(|e| e.to_string())?;
        if enforced(&status) {
            Ok(())
        } else {
            Err(format!("Landlock not fully enforced: {status:?}"))
        }
    }

    /// Full enforcement, except that below ABI v6 the scopes may be the part
    /// left out: everything else was requested as a hard requirement, so a
    /// missing v4 right is an error before this point, never a partial status.
    fn enforced(status: &RestrictionStatus) -> bool {
        let below_scopes = matches!(
            status.landlock,
            LandlockStatus::Available { effective_abi, .. } if effective_abi < ABI_SCOPES
        );
        status.no_new_privs
            && match status.ruleset {
                RulesetStatus::FullyEnforced => true,
                RulesetStatus::PartiallyEnforced => below_scopes,
                RulesetStatus::NotEnforced => false,
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
    let pinned = match apply_manifest(&mut plan) {
        Ok(pinned) => pinned,
        Err(e) => {
            eprintln!("corten-sandbox: manifest refused: {e}");
            return ExitCode::from(EXIT_UNENFORCEABLE);
        }
    };
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
    exec(&plan, pinned.as_ref())
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

/// Executes the program: in manifest mode the file [`open_pinned`] checked,
/// through `/proc/self/fd/N` (the kernel resolves that link to the open
/// file, not to whatever the path names now), with `argv[0]` still the
/// program's path.
#[cfg(unix)]
fn exec(plan: &Plan, pinned: Option<&std::fs::File>) -> ExitCode {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let path = match pinned {
        Some(file) => PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        None => plan.program.clone(),
    };
    // exec replaces this process, so the Landlock domain carries over; it
    // only returns on failure.
    let err = std::process::Command::new(&path)
        .arg0(&plan.program)
        .args(&plan.args)
        .exec();
    eprintln!(
        "corten-sandbox: cannot execute {}: {err}",
        plan.program.display()
    );
    ExitCode::from(EXIT_UNENFORCEABLE)
}

#[cfg(not(unix))]
fn exec(_plan: &Plan, _pinned: Option<&std::fs::File>) -> ExitCode {
    ExitCode::from(EXIT_UNENFORCEABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_must_match_the_manifest_digest() {
        let dir = std::env::temp_dir().join(format!("corten-sandbox-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prog = dir.join("prog");
        std::fs::write(&prog, b"abc").unwrap();
        // SHA-256 of "abc" (FIPS 180-4, appendix B.1).
        let abc = corten_sha256::digest(b"abc");
        assert_eq!(
            corten_sha256::hex(&abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(open_pinned(&prog, &abc).is_ok());
        let mut other = abc;
        other[0] ^= 1;
        let e = open_pinned(&prog, &other).err().unwrap();
        assert!(e.contains("refusing") && e.contains("ba7816bf"), "{e}");
        let e = open_pinned(&dir.join("absent"), &abc).err().unwrap();
        assert!(e.contains("absent"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
        let full = [
            "--manifest",
            "/m",
            "--signature",
            "/s",
            "--trusted-key",
            "a=00",
            "--trusted-key",
            "b=11",
            "--serial-state",
            "/st",
            "--",
            "/bin/true",
        ];
        let plan = run(&full).unwrap();
        let m = plan.manifest.unwrap();
        assert_eq!(
            m.trusted_keys,
            [
                ("a".to_owned(), "00".to_owned()),
                ("b".to_owned(), "11".to_owned())
            ]
        );
        assert_eq!(m.serial_state, PathBuf::from("/st"));
        // Each of the four is required in manifest mode.
        for skip in ["--signature", "--trusted-key", "--serial-state"] {
            let mut partial: Vec<&str> = Vec::new();
            let mut it = full.iter();
            while let Some(a) = it.next() {
                if *a == skip {
                    it.next();
                    continue;
                }
                partial.push(a);
            }
            assert!(run(&partial).is_err(), "{skip}");
        }
        assert!(run(&["--trusted-key", "noequals", "--", "/bin/true"]).is_err());
        assert_eq!(hex_decode("0aFF"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn the_serial_state_round_trips_and_refuses_damage() {
        let dir = std::env::temp_dir().join(format!("corten-serial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("serial");
        assert_eq!(read_serial(&state), Ok(0), "a missing file is serial 0");
        write_serial(&state, 42).unwrap();
        assert_eq!(read_serial(&state), Ok(42));
        assert!(
            !state.with_extension("tmp").exists(),
            "the temporary file was renamed"
        );
        for bad in ["", "x", "-1", "01", "4 2", "18446744073709551616", "42\n\n"] {
            std::fs::write(&state, bad).unwrap();
            assert!(
                read_serial(&state).is_err(),
                "{bad:?} must not read as a serial"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_relative_programs_and_bad_arguments() {
        assert!(run(&["--", "cat"]).is_err());
        assert!(run(&["--ro"]).is_err());
        assert!(run(&["--bogus", "--", "/bin/cat"]).is_err());
        assert!(run(&["--ro", "/x"]).is_err());
    }
}
