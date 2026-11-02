//! `cargo corten`: builds a crate under the Corten profile.
//!
//! Exit status: 0 when the check passes, 1 when it fails (a dependency the
//! policy refuses, a profile rule, or an ordinary compile error), 2 for a
//! usage or environment error.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use cargo_corten::dep_policy::{self, DepPolicy};
use cargo_corten::json::Json;
use cargo_corten::provenance::{Artifact, BuildFacts};
use cargo_corten::{
    BuildSandbox, Toolchain, build_command, check_command, deps, lint_command, metadata_command,
    profile, profile_rustflags, provenance, sha256, vendor_command,
};

const USAGE: &str = "\
Build a crate under the Corten profile, with flags the checker supplies itself.

Usage: cargo corten check [--manifest-path <PATH>] [--dep-policy <FILE>] [--allow-dep <NAME>]...
       cargo corten build [--manifest-path <PATH>] [--dep-policy <FILE>] [--allow-dep <NAME>]...
                          [--sbom <FILE>] [--provenance <FILE>]

`build` builds --release --locked --offline inside corten-sandbox (Linux):
no network, sources and toolchain read-only, only the target directory
writable. It refuses to run where the sandbox cannot be enforced.

Options:
      --manifest-path <PATH>  Path to Cargo.toml (default: search from the current directory)
      --dep-policy <FILE>     The operator's dependency policy (also CORTEN_DEP_POLICY):
                              dependencies are refused unless it admits them (`allow NAME`),
                              and its `ban PATH REASON` lines are forbidden in local code.
                              Without one, every dependency is refused.
      --allow-dep <NAME>      Accept a dependency refused for its macros or the ban list
                              (NAME or NAME@VERSION); does not admit it. Also read,
                              comma-separated, from CORTEN_ALLOW_DEPS
      --sbom <FILE>           build: write a CycloneDX SBOM
      --provenance <FILE>     build: write an unsigned in-toto/SLSA provenance statement
  -h, --help                  Print help
  -V, --version               Print version

Exit status: 0 passed, 1 refused or failed to build, 2 usage or environment error.
";

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// The prelude this checker was built with: `crates/corten-std` beside the
/// checker's own source, fixed at compile time. Only a local package in this
/// directory has its dependencies exempt from admission (`deps.rs`).
const PRELUDE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../corten-std");

/// Largest `cargo metadata` output read.
const MAX_METADATA_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Help,
    Version,
    Check {
        manifest_path: Option<PathBuf>,
        dep_policy: Option<PathBuf>,
        allow_deps: Vec<String>,
    },
    Build {
        manifest_path: Option<PathBuf>,
        dep_policy: Option<PathBuf>,
        allow_deps: Vec<String>,
        sbom: Option<PathBuf>,
        provenance: Option<PathBuf>,
    },
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut args = args.into_iter().peekable();
    // Cargo runs `cargo-corten corten <args>`; accept a direct call without it.
    if args.peek().is_some_and(|a| a == "corten") {
        args.next();
    }
    let mut subcommand = None;
    let mut manifest_path = None;
    let mut allow_deps = Vec::new();
    let mut dep_policy = None;
    let mut sbom = None;
    let mut provenance = None;
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
            "--dep-policy" => {
                let value = args.next().ok_or("--dep-policy needs a file")?;
                dep_policy = Some(PathBuf::from(value));
            }
            _ if text.starts_with("--dep-policy=") => {
                dep_policy = Some(PathBuf::from(text.trim_start_matches("--dep-policy=")));
            }
            "--allow-dep" => {
                let value = args.next().ok_or("--allow-dep needs a value")?;
                let value = value.to_str().ok_or("--allow-dep value must be UTF-8")?;
                allow_deps.push(value.to_owned());
            }
            _ if text.starts_with("--allow-dep=") => {
                allow_deps.push(text.trim_start_matches("--allow-dep=").to_owned());
            }
            "--sbom" => sbom = Some(PathBuf::from(args.next().ok_or("--sbom needs a file")?)),
            "--provenance" => {
                provenance = Some(PathBuf::from(
                    args.next().ok_or("--provenance needs a file")?,
                ));
            }
            "check" | "build" if subcommand.is_none() => subcommand = Some(text.to_owned()),
            _ => return Err(format!("unexpected argument '{text}'")),
        }
    }
    match subcommand.as_deref() {
        Some("check") if sbom.is_none() && provenance.is_none() => Ok(Invocation::Check {
            manifest_path,
            dep_policy,
            allow_deps,
        }),
        Some("check") => Err("--sbom and --provenance belong to `build`".to_owned()),
        Some(_) => Ok(Invocation::Build {
            manifest_path,
            dep_policy,
            allow_deps,
            sbom,
            provenance,
        }),
        None => Err("missing subcommand: `check` or `build`".to_owned()),
    }
}

/// A directory only this process created, holding the checker's
/// `clippy.toml`; removed on drop.
struct ConfDir(PathBuf);

impl ConfDir {
    fn create(policy: &DepPolicy) -> io::Result<Self> {
        let base = env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let mut last_err = None;
        for attempt in 0..16u32 {
            let dir = base.join(format!(
                "cargo-corten-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            // create_dir fails if the name exists, so a planted directory or
            // link is never reused.
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            match builder.create(&dir) {
                Ok(()) => {
                    let conf = Self(dir);
                    fs::write(
                        conf.0.join("clippy.toml"),
                        policy.clippy_toml(profile::CLIPPY_TOML),
                    )?;
                    return Ok(conf);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no attempt made")))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ConfDir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.0) {
            eprintln!("warning: could not remove {}: {e}", self.0.display());
        }
    }
}

/// Layer 3: refuses dependencies the policy does not accept. `Ok(true)`
/// means the check may go on.
fn dependency_policy(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf: &Path,
    policy: &DepPolicy,
    allow: &BTreeSet<String>,
) -> Result<(bool, Json), String> {
    let mut cmd = metadata_command(toolchain, manifest_path, conf).map_err(|e| e.to_string())?;
    let out = cmd
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("could not run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo metadata failed ({})", out.status));
    }
    if out.stdout.len() > MAX_METADATA_BYTES {
        return Err("cargo metadata output is too large".to_owned());
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| "cargo metadata output is not UTF-8".to_owned())?;
    let metadata = Json::parse(&text).map_err(|e| e.to_string())?;
    let findings = deps::audit(
        &metadata,
        policy,
        Some(Path::new(PRELUDE_DIR)),
        allow,
        deps::Limits::default(),
    )
    .map_err(|e| e.to_string())?;
    if findings.is_empty() {
        return Ok((true, metadata));
    }
    eprintln!(
        "cargo corten check: dependency policy (layer 3) refused {} package(s):",
        findings.len()
    );
    for finding in &findings {
        eprintln!("  {finding}");
    }
    eprintln!(
        "Admit a dependency with `allow NAME` in the operator's --dep-policy file; accept a macro or ban-list finding with --allow-dep <NAME>. Review the crate first."
    );
    Ok((false, metadata))
}

/// The `corten-sandbox` to build in: `CORTEN_SANDBOX`, or the one installed
/// next to this binary.
fn find_sandbox() -> Result<PathBuf, String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "hermetic builds need Linux (Landlock); refusing to build unconfined".to_owned(),
        );
    }
    let path = match env::var_os("CORTEN_SANDBOX") {
        Some(p) => PathBuf::from(p),
        None => env::current_exe()
            .map_err(|e| e.to_string())?
            .with_file_name("corten-sandbox"),
    };
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "{} not found; install corten-sandbox or set CORTEN_SANDBOX",
            path.display()
        ))
    }
}

fn str_field<'a>(j: &'a Json, key: &str) -> Result<&'a str, String> {
    j.get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("cargo metadata has no {key}"))
}

/// Binaries the workspace members produce, with their digests.
fn artifacts(metadata: &Json, target_dir: &Path) -> Vec<Artifact> {
    let members: BTreeSet<&str> = metadata
        .get("workspace_members")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .collect();
    let mut out = Vec::new();
    for pkg in metadata
        .get("packages")
        .and_then(Json::as_array)
        .unwrap_or(&[])
    {
        if !pkg
            .get("id")
            .and_then(Json::as_str)
            .is_some_and(|id| members.contains(id))
        {
            continue;
        }
        for target in pkg.get("targets").and_then(Json::as_array).unwrap_or(&[]) {
            let is_bin = target
                .get("kind")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .any(|k| k.as_str() == Some("bin"));
            let Some(name) = target.get("name").and_then(Json::as_str) else {
                continue;
            };
            let rel = format!("release/{name}{}", env::consts::EXE_SUFFIX);
            if is_bin && let Ok(bytes) = fs::read(target_dir.join(&rel)) {
                out.push(Artifact {
                    name: rel,
                    sha256: sha256::hex_digest(&bytes),
                });
            }
        }
    }
    out
}

struct BuildRequest<'a> {
    toolchain: &'a Toolchain,
    manifest_path: Option<&'a Path>,
    conf: &'a Path,
    metadata: &'a Json,
    sbom: Option<&'a Path>,
    provenance: Option<&'a Path>,
}

/// Local packages (no `source`) outside `workspace_root`, and every
/// `Cargo.toml` above each of them: cargo reads those to find the package's
/// own workspace, for inherited fields. Registry and git packages are
/// vendored and need no grant.
fn local_paths(metadata: &Json, workspace_root: &Path) -> Vec<PathBuf> {
    let mut out = BTreeSet::new();
    for pkg in metadata
        .get("packages")
        .and_then(Json::as_array)
        .unwrap_or(&[])
    {
        if pkg.get("source").is_some_and(|s| *s != Json::Null) {
            continue;
        }
        let Some(dir) = pkg
            .get("manifest_path")
            .and_then(Json::as_str)
            .and_then(|m| Path::new(m).parent())
        else {
            continue;
        };
        if dir.starts_with(workspace_root) {
            continue;
        }
        out.insert(dir.to_path_buf());
        for ancestor in dir.ancestors().skip(1) {
            let manifest = ancestor.join("Cargo.toml");
            if manifest.is_file() {
                out.insert(manifest);
            }
        }
    }
    out.into_iter().collect()
}

/// The vendor root, held for one check or build: an exclusive lock on
/// `.lock` inside it, released when dropped, so two runs against the same
/// target directory never vendor into it at once.
struct VendorRoot {
    dir: PathBuf,
    _lock: fs::File,
}

/// The base of the per-user cache: `$XDG_CACHE_HOME` when it is absolute,
/// else `$HOME/.cache`, with the directory whose owner the vendor root must
/// share (`$HOME`).
fn cache_base() -> Result<(PathBuf, PathBuf), String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or("HOME is not set to an absolute path: no private place to vendor into")?;
    let base = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".cache"));
    Ok((base, home))
}

/// Refuses a directory another user could have planted or can write: it
/// must be a real directory (not a symlink), owned by `owner`'s owner, with
/// no write permission for group or others.
fn private_dir(dir: &Path, owner: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let uid = fs::metadata(owner)
        .map_err(|e| format!("{}: {e}", owner.display()))?
        .uid();
    if !meta.file_type().is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != uid {
        return Err(format!(
            "{} is owned by uid {}, not by {}'s owner (uid {uid})",
            dir.display(),
            meta.uid(),
            owner.display()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group or others (mode {:o})",
            dir.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// The private directory for the vendored sources, outside the target
/// directory so the sandboxed build cannot write it (F5).
///
/// Its path is stable per target directory (`<cache>/corten/vendor/<hash of
/// the target directory>`): build scripts record absolute paths into the
/// vendored sources (`rerun-if-changed`), so a new path on every run made
/// cargo rebuild every dependency on every check. Measured 2026-11-02 on
/// one corpus case: 68 s and 78 crates compiled on a repeat check with a
/// fresh path, 2 s and none with a stable one. Every component is created
/// with mode 0700 and refused on reuse unless it is a real directory owned
/// by `$HOME`'s owner with no group or other write, so another user cannot
/// plant or swap it. The cache base itself must pass the same check.
fn vendor_root(target_dir: &Path) -> Result<VendorRoot, String> {
    let (base, home) = cache_base()?;
    vendor_root_in(&base, &home, target_dir)
}

/// [`vendor_root`] under `base`, with `home` as the owner reference.
fn vendor_root_in(base: &Path, home: &Path, target_dir: &Path) -> Result<VendorRoot, String> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base)
        .map_err(|e| format!("{}: {e}", base.display()))?;
    private_dir(base, home)?;
    let name = sha256::hex_digest(target_dir.as_os_str().as_encoded_bytes());
    let mut dir = base.to_path_buf();
    for part in ["corten", "vendor", name.get(..32).unwrap_or(&name)] {
        dir.push(part);
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        }
        private_dir(&dir, home)?;
    }
    let lock_path = dir.join(".lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("{}: {e}", lock_path.display()))?;
    lock.lock()
        .map_err(|e| format!("{}: {e}", lock_path.display()))?;
    Ok(VendorRoot { dir, _lock: lock })
}

/// Vendors the dependencies (outside the sandbox: the only step with
/// network access) and returns where a sandboxed check or build runs.
/// `locked` is passed to `cargo vendor`.
fn prepare_sandbox(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf: &Path,
    metadata: &Json,
    locked: bool,
) -> Result<(BuildSandbox, VendorRoot), String> {
    let sandbox = find_sandbox()?;
    let workspace_root = PathBuf::from(str_field(metadata, "workspace_root")?);
    let target_dir = PathBuf::from(str_field(metadata, "target_directory")?);
    let toolchain_root = toolchain
        .cargo
        .parent()
        .and_then(Path::parent)
        .ok_or("cannot find the toolchain root")?
        .to_path_buf();
    let root = vendor_root(&target_dir)?;
    let vendor_dir = root.dir.join("vendor");
    let mut vendor = vendor_command(toolchain, manifest_path, conf, &vendor_dir, locked)
        .map_err(|e| e.to_string())?;
    let vendored = vendor
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("cannot run cargo vendor: {e}"))?;
    if !vendored.status.success() {
        return Err(format!("cargo vendor failed ({})", vendored.status));
    }
    let vendor_config = root.dir.join("config.toml");
    fs::write(&vendor_config, &vendored.stdout)
        .map_err(|e| format!("{}: {e}", vendor_config.display()))?;
    let local_paths = local_paths(metadata, &workspace_root);
    let plan = BuildSandbox {
        sandbox,
        toolchain_root,
        workspace_root,
        local_paths,
        target_dir,
        vendor_root: root.dir.clone(),
        vendor_config,
    };
    for dir in [plan.cargo_home(), plan.tmp_dir()] {
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok((plan, root))
}

/// Vendor, then build inside the sandbox, then write the SBOM and provenance.
fn hermetic_build(req: &BuildRequest<'_>) -> Result<(), String> {
    let (plan, _vendor_root) = prepare_sandbox(
        req.toolchain,
        req.manifest_path,
        req.conf,
        req.metadata,
        true,
    )?;
    let (workspace_root, target_dir) = (&plan.workspace_root, &plan.target_dir);
    // Corten's own lints first: the build pass applies only Clippy's. Each
    // pass starts from an empty CARGO_HOME.
    plan.fresh_cargo_home()?;
    if !lint_pass(
        req.toolchain,
        req.manifest_path,
        req.conf,
        Some(&plan),
        req.metadata,
    )? {
        return Err("Corten's own lints failed".to_owned());
    }
    plan.fresh_cargo_home()?;
    let mut build = build_command(req.toolchain, req.manifest_path, req.conf, Some(&plan))
        .map_err(|e| e.to_string())?;
    let build_status = build
        .status()
        .map_err(|e| format!("cannot run the sandboxed build: {e}"))?;
    if !build_status.success() {
        return Err(format!("sandboxed build failed ({build_status})"));
    }

    if let Some(path) = req.sbom {
        fs::write(path, provenance::sbom(req.metadata))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if let Some(path) = req.provenance {
        let lock =
            fs::read(workspace_root.join("Cargo.lock")).map_err(|e| format!("Cargo.lock: {e}"))?;
        let rustc = std::process::Command::new(&req.toolchain.rustc)
            .arg("-vV")
            .output()
            .map_err(|e| format!("rustc -vV: {e}"))?;
        let flags = profile_rustflags();
        let facts = BuildFacts {
            checker: env!("CARGO_PKG_VERSION"),
            rustc: &String::from_utf8_lossy(&rustc.stdout),
            profile_flags: &flags,
            lock_sha256: &sha256::hex_digest(&lock),
            sandboxed: true,
        };
        let statement = provenance::statement(&artifacts(req.metadata, target_dir), &facts);
        fs::write(path, statement).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

/// `cargo corten check` after the dependency policy passed.
fn run_check(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf: &ConfDir,
    metadata: &Json,
) -> ExitCode {
    // On Linux the check runs inside the sandbox, as the build does: build
    // scripts and procedural macros execute during a check. Elsewhere there
    // is no sandbox, and the check says so.
    let (plan, _vendor_root) = if cfg!(target_os = "linux") {
        match prepare_sandbox(toolchain, manifest_path, conf.path(), metadata, false) {
            Ok((plan, root)) => (Some(plan), Some(root)),
            Err(e) => {
                // Fail closed: no sandbox, no check.
                eprintln!("cargo corten check: {e}");
                return ExitCode::from(EXIT_FAILED);
            }
        }
    } else {
        eprintln!(
            "warning: no sandbox on this platform: build scripts and procedural macros run with your privileges"
        );
        (None, None)
    };
    let mut command = match check_command(toolchain, manifest_path, conf.path(), plan.as_ref()) {
        Ok(command) => command,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    // Each sandboxed pass starts from an empty CARGO_HOME.
    if let Some(p) = &plan
        && let Err(e) = p.fresh_cargo_home()
    {
        eprintln!("cargo corten check: {e}");
        return ExitCode::from(EXIT_FAILED);
    }
    // No deadline: this is an interactive build, and Ctrl-C reaches cargo
    // through the shared process group. `status` waits, so no child outlives us.
    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("cargo corten check: failed ({status})");
            return ExitCode::from(EXIT_FAILED);
        }
        Err(e) => {
            eprintln!("error: could not run {}: {e}", toolchain.cargo.display());
            return ExitCode::from(EXIT_USAGE);
        }
    }
    if let Some(p) = &plan
        && let Err(e) = p.fresh_cargo_home()
    {
        eprintln!("cargo corten check: {e}");
        return ExitCode::from(EXIT_FAILED);
    }
    match lint_pass(
        toolchain,
        manifest_path,
        conf.path(),
        plan.as_ref(),
        metadata,
    ) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(EXIT_FAILED),
        Err(e) => {
            // Fail closed: a driver that is installed but cannot run did not pass.
            eprintln!("cargo corten check: custom lints: {e}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// `corten-driver`: `CORTEN_DRIVER`, or the one installed beside this binary.
fn find_driver() -> Option<PathBuf> {
    let path = match env::var_os("CORTEN_DRIVER") {
        Some(p) => PathBuf::from(p),
        None => env::current_exe().ok()?.with_file_name("corten-driver"),
    };
    path.is_file().then_some(path)
}

/// The second pass, Corten's own lints. `Ok(true)`: passed. The driver is
/// required (owner decision 10): without it the check has not run its whole
/// profile, so a missing driver is an error.
fn lint_pass(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf: &Path,
    plan: Option<&BuildSandbox>,
    metadata: &Json,
) -> Result<bool, String> {
    let Some(driver) = find_driver() else {
        return Err(format!(
            "corten-driver is not installed (set CORTEN_DRIVER or install it beside cargo-corten), so Corten's own lints ({}) cannot run",
            profile::FORBIDDEN_CORTEN_LINTS.join(", ")
        ));
    };
    let out = std::process::Command::new(&driver)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", driver.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} --print sysroot failed ({})",
            driver.display(),
            out.status
        ));
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let target_dir = PathBuf::from(str_field(metadata, "target_directory")?).join("corten-lints");
    let plan = plan.map(|p| {
        let mut p = p.clone();
        p.local_paths.push(driver.clone());
        p.local_paths.push(sysroot.clone());
        p
    });
    let mut cmd = lint_command(
        toolchain,
        manifest_path,
        conf,
        &driver,
        &target_dir,
        plan.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let status = cmd
        .status()
        .map_err(|e| format!("cannot run the lint pass: {e}"))?;
    if status.success() {
        Ok(true)
    } else {
        eprintln!("cargo corten check: Corten's own lints failed ({status})");
        Ok(false)
    }
}

/// Reads the operator's dependency policy; none means every dependency is
/// refused.
fn load_dep_policy(path: Option<PathBuf>) -> Result<DepPolicy, String> {
    let Some(path) = path else {
        return Ok(DepPolicy::default());
    };
    let meta = fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > u64::try_from(dep_policy::MAX_LEN).unwrap_or(u64::MAX) {
        return Err(format!(
            "{}: larger than {} bytes",
            path.display(),
            dep_policy::MAX_LEN
        ));
    }
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    dep_policy::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The operator's inputs: the dependency policy (`--dep-policy` or
/// `CORTEN_DEP_POLICY`) and the accepted packages (`--allow-dep` and
/// `CORTEN_ALLOW_DEPS`).
fn operator_inputs(
    dep_policy: Option<PathBuf>,
    mut allow_deps: Vec<String>,
) -> Result<(DepPolicy, BTreeSet<String>), String> {
    let policy = load_dep_policy(
        // An empty variable (an unset action input) means no policy.
        dep_policy.or_else(|| {
            env::var_os("CORTEN_DEP_POLICY")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        }),
    )?;
    if let Some(list) = env::var_os("CORTEN_ALLOW_DEPS") {
        let list = list.to_str().ok_or("CORTEN_ALLOW_DEPS must be UTF-8")?;
        allow_deps.extend(
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
    }
    Ok((policy, allow_deps.into_iter().collect()))
}

fn main() -> ExitCode {
    let invocation = match parse(env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let (manifest_path, dep_policy, allow_deps, build) = match invocation {
        Invocation::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Invocation::Version => {
            println!("cargo-corten {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Invocation::Check {
            manifest_path,
            dep_policy,
            allow_deps,
        } => (manifest_path, dep_policy, allow_deps, None),
        Invocation::Build {
            manifest_path,
            dep_policy,
            allow_deps,
            sbom,
            provenance,
        } => (
            manifest_path,
            dep_policy,
            allow_deps,
            Some((sbom, provenance)),
        ),
    };
    let (policy, allow) = match operator_inputs(dep_policy, allow_deps) {
        Ok(inputs) => inputs,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let toolchain = match Toolchain::from_env(env::var_os("CARGO"), env::var_os("RUSTC")) {
        Ok(toolchain) => toolchain,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let conf = match ConfDir::create(&policy) {
        Ok(conf) => conf,
        Err(e) => {
            eprintln!("error: could not create the Clippy configuration directory: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let metadata = match dependency_policy(
        &toolchain,
        manifest_path.as_deref(),
        conf.path(),
        &policy,
        &allow,
    ) {
        Ok((true, metadata)) => metadata,
        Ok((false, _)) => return ExitCode::from(EXIT_FAILED),
        Err(e) => {
            // Fail closed: a policy that could not run did not pass.
            eprintln!("error: dependency policy could not run: {e}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    if let Some((sbom, provenance)) = build {
        let req = BuildRequest {
            toolchain: &toolchain,
            manifest_path: manifest_path.as_deref(),
            conf: conf.path(),
            metadata: &metadata,
            sbom: sbom.as_deref(),
            provenance: provenance.as_deref(),
        };
        return match hermetic_build(&req) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("cargo corten build: {e}");
                ExitCode::from(EXIT_FAILED)
            }
        };
    }
    run_check(&toolchain, manifest_path.as_deref(), &conf, &metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Invocation, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn accepts_cargo_subcommand_form() {
        assert_eq!(
            run(&["corten", "check"]),
            Ok(Invocation::Check {
                manifest_path: None,
                dep_policy: None,
                allow_deps: Vec::new()
            })
        );
    }

    #[test]
    fn accepts_both_manifest_path_and_allow_dep_forms() {
        let parsed = run(&[
            "check",
            "--manifest-path",
            "a/Cargo.toml",
            "--allow-dep",
            "serde_derive",
            "--allow-dep=x@1.0.0",
            "--dep-policy",
            "ops/deps.policy",
        ]);
        assert_eq!(
            parsed,
            Ok(Invocation::Check {
                manifest_path: Some(PathBuf::from("a/Cargo.toml")),
                dep_policy: Some(PathBuf::from("ops/deps.policy")),
                allow_deps: vec!["serde_derive".to_owned(), "x@1.0.0".to_owned()]
            })
        );
        let Ok(Invocation::Check { manifest_path, .. }) =
            run(&["check", "--manifest-path=b/Cargo.toml"])
        else {
            panic!("did not parse");
        };
        assert_eq!(manifest_path, Some(PathBuf::from("b/Cargo.toml")));
    }

    #[test]
    fn parses_build_with_outputs() {
        assert_eq!(
            run(&[
                "corten",
                "build",
                "--sbom",
                "s.json",
                "--provenance",
                "p.json"
            ]),
            Ok(Invocation::Build {
                manifest_path: None,
                dep_policy: None,
                allow_deps: Vec::new(),
                sbom: Some(PathBuf::from("s.json")),
                provenance: Some(PathBuf::from("p.json")),
            })
        );
        assert!(run(&["check", "--sbom", "s.json"]).is_err());
    }

    #[test]
    fn rejects_unknown_and_missing_arguments() {
        assert!(run(&["check", "--release"]).is_err());
        assert!(run(&["install"]).is_err());
        assert!(run(&["corten"]).is_err());
        assert!(run(&["check", "--manifest-path"]).is_err());
        assert!(run(&["check", "--allow-dep"]).is_err());
        assert!(run(&["check", "check"]).is_err());
    }

    /// A fresh private directory for one vendor-root test.
    fn vendor_test_dir(name: &str) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let dir = env::temp_dir().join(format!(
            "cargo-corten-vendor-test-{name}-{}",
            std::process::id()
        ));
        if let Err(e) = fs::remove_dir_all(&dir) {
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        }
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }

    #[test]
    fn vendor_root_is_stable_per_target_and_private() {
        use std::os::unix::fs::MetadataExt;
        let t = vendor_test_dir("stable");
        let base = t.join("cache");
        let first = vendor_root_in(&base, &t, Path::new("/w/a/target"))
            .unwrap()
            .dir;
        let again = vendor_root_in(&base, &t, Path::new("/w/a/target"))
            .unwrap()
            .dir;
        let other = vendor_root_in(&base, &t, Path::new("/w/b/target"))
            .unwrap()
            .dir;
        assert_eq!(first, again, "a new path per run rebuilds every dependency");
        assert_ne!(first, other);
        assert!(first.starts_with(base.join("corten/vendor")));
        for d in [&base, &base.join("corten"), &first] {
            assert_eq!(fs::metadata(d).unwrap().mode() & 0o777, 0o700, "{d:?}");
        }
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn vendor_root_refuses_a_shared_or_planted_directory() {
        use std::os::unix::fs::PermissionsExt;
        let t = vendor_test_dir("refuse");
        let base = t.join("cache");
        vendor_root_in(&base, &t, Path::new("/w/target")).unwrap();
        // Group-writable component: another user could swap what is below.
        fs::set_permissions(base.join("corten"), fs::Permissions::from_mode(0o770)).unwrap();
        let e = vendor_root_in(&base, &t, Path::new("/w/target"))
            .err()
            .unwrap();
        assert!(e.contains("writable by group or others"), "{e}");
        // A symlink in place of a component is refused, not followed.
        fs::remove_dir_all(base.join("corten")).unwrap();
        fs::create_dir(t.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(t.join("elsewhere"), base.join("corten")).unwrap();
        let e = vendor_root_in(&base, &t, Path::new("/w/target"))
            .err()
            .unwrap();
        assert!(e.contains("is not a directory"), "{e}");
        // A world-writable cache base (XDG_CACHE_HOME=/tmp, say) is refused.
        let open = t.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let e = vendor_root_in(&open, &t, Path::new("/w/target"))
            .err()
            .unwrap();
        assert!(e.contains("writable by group or others"), "{e}");
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn vendor_root_is_locked_while_held() {
        let t = vendor_test_dir("lock");
        let base = t.join("cache");
        let held = vendor_root_in(&base, &t, Path::new("/w/target")).unwrap();
        let other = fs::OpenOptions::new()
            .write(true)
            .open(held.dir.join(".lock"))
            .unwrap();
        assert!(
            other.try_lock().is_err(),
            "a second run could vendor at once"
        );
        drop(held);
        assert!(other.try_lock().is_ok(), "the lock outlived its run");
        fs::remove_dir_all(&t).unwrap();
    }
}
