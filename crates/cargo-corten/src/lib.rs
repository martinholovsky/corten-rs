//! Library behind the `cargo corten` subcommand.
//!
//! `cargo corten check` runs `cargo check` with Clippy as the workspace
//! compiler, flags and a lint configuration the checker supplies itself, and
//! overrides the ways the checked repository could weaken them
//! (`docs/spec.md` section 10, `AGENTS.md` rule 3). The crate README lists
//! what is neutralised today and what is not.

pub mod deps;
pub mod json;
pub mod profile;
pub mod provenance;
pub mod sha256;

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Separator cargo uses between flags in `CARGO_ENCODED_RUSTFLAGS`.
const ENCODED_FLAG_SEPARATOR: &str = "\u{1f}";

/// Variables removed from the child's environment. `CARGO_ENCODED_RUSTFLAGS`
/// already outranks them; removing them keeps the child's environment honest
/// about which flags it builds with.
const REMOVED_ENV: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CLIPPY_ARGS",
];

/// Set to the empty string. An empty value overrides a `[build]
/// rustc-workspace-wrapper` in any `.cargo/config.toml` the checked repository
/// or its ancestors carry; such a wrapper could drop the injected flags
/// (measured, see the README).
const EMPTIED_ENV: &[&str] = &["RUSTC_WORKSPACE_WRAPPER"];

/// Variables cargo would let a repository's `[env]` table override with
/// `force = true`, pinned through `--config`, which outranks configuration
/// files (measured, see the README).
const PINNED_CONFIG_ENV: &[&str] = &["CLIPPY_CONF_DIR", "RUSTC_BOOTSTRAP"];

/// `RUSTC_BOOTSTRAP=-1` makes nightly features fail on every channel.
const RUSTC_BOOTSTRAP_OFF: &str = "-1";

/// Where the checker finds the toolchain it drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    /// The `cargo` binary to run.
    pub cargo: PathBuf,
    /// The `rustc` binary cargo must use, overriding any `[build] rustc` in
    /// the checked repository's configuration.
    pub rustc: PathBuf,
    /// The `clippy-driver` that compiles workspace crates.
    pub clippy_driver: PathBuf,
}

/// Why the toolchain could not be located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolchainError {
    /// `CARGO` is unset, so this was not started as `cargo corten`.
    CargoUnknown,
    /// `RUSTC` is unset and no `rustc` sits beside the `cargo` binary.
    RustcNotBesideCargo(PathBuf),
    /// No `clippy-driver` sits beside the `cargo` binary.
    ClippyDriverNotBesideCargo(PathBuf),
}

impl fmt::Display for ToolchainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CargoUnknown => write!(
                f,
                "CARGO is not set; run this as `cargo corten`, or set CARGO to the cargo binary"
            ),
            Self::RustcNotBesideCargo(path) => write!(
                f,
                "RUSTC is not set and {} does not exist; set RUSTC to the rustc binary",
                path.display()
            ),
            Self::ClippyDriverNotBesideCargo(path) => write!(
                f,
                "{} does not exist; install the clippy component for this toolchain",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ToolchainError {}

fn sibling(cargo: &Path, name: &str) -> PathBuf {
    cargo.with_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

impl Toolchain {
    /// Locates the toolchain from the operator's environment.
    ///
    /// `CARGO` (set by cargo when it runs a subcommand) names cargo. `RUSTC`
    /// names rustc when the operator set it; otherwise the `rustc` beside
    /// cargo is used. `clippy-driver` is always the one beside cargo. Nothing
    /// is read from the checked repository.
    ///
    /// # Errors
    ///
    /// Returns [`ToolchainError`] when cargo, rustc or clippy-driver cannot be
    /// located.
    pub fn from_env(
        cargo: Option<OsString>,
        rustc: Option<OsString>,
    ) -> Result<Self, ToolchainError> {
        let cargo = PathBuf::from(cargo.ok_or(ToolchainError::CargoUnknown)?);
        let rustc = if let Some(rustc) = rustc {
            PathBuf::from(rustc)
        } else {
            let rustc = sibling(&cargo, "rustc");
            if !rustc.is_file() {
                return Err(ToolchainError::RustcNotBesideCargo(rustc));
            }
            rustc
        };
        let clippy_driver = sibling(&cargo, "clippy-driver");
        if !clippy_driver.is_file() {
            return Err(ToolchainError::ClippyDriverNotBesideCargo(clippy_driver));
        }
        Ok(Self {
            cargo,
            rustc,
            clippy_driver,
        })
    }
}

/// Every flag the profile passes to rustc and clippy-driver, in order.
#[must_use]
pub fn profile_rustflags() -> Vec<&'static str> {
    let mut flags = profile::CODEGEN_FLAGS.to_vec();
    for lint in profile::FORBIDDEN_RUSTC_LINTS
        .iter()
        .chain(profile::FORBIDDEN_CLIPPY_LINTS)
    {
        flags.push("-F");
        flags.push(lint);
    }
    flags
}

/// The configuration directory cannot be passed to cargo safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfDirError(pub PathBuf);

impl fmt::Display for ConfDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "configuration directory {} must be UTF-8 without quotes or line breaks",
            self.0.display()
        )
    }
}

impl std::error::Error for ConfDirError {}

/// `--config` arguments that pin `name` to `value`, overriding a forced
/// `[env]` entry in any configuration file.
fn pin_env(name: &str, value: &str) -> [String; 4] {
    [
        "--config".to_owned(),
        format!("env.{name}.value='{value}'"),
        "--config".to_owned(),
        format!("env.{name}.force=true"),
    ]
}

/// A cargo command with the checker's environment and `--config` pins,
/// before the subcommand: `cargo --config ... <args>`.
fn pinned_cargo(toolchain: &Toolchain, conf_dir: &Path) -> Result<Command, ConfDirError> {
    let conf = conf_dir
        .to_str()
        .filter(|s| !s.contains(['\'', '\n', '\r']))
        .ok_or_else(|| ConfDirError(conf_dir.to_path_buf()))?;
    let mut cmd = Command::new(&toolchain.cargo);
    for name in PINNED_CONFIG_ENV {
        let value = if *name == "CLIPPY_CONF_DIR" {
            conf
        } else {
            RUSTC_BOOTSTRAP_OFF
        };
        cmd.args(pin_env(name, value));
    }
    for name in REMOVED_ENV {
        cmd.env_remove(name);
    }
    for name in EMPTIED_ENV {
        cmd.env(name, "");
    }
    cmd.env("RUSTC", &toolchain.rustc);
    // clippy-driver wraps every crate, not only workspace members, so a local
    // path dependency outside the workspace is linted too. Clippy turns itself
    // off for crates built with --cap-lints allow (registry and git
    // dependencies). Setting the variable also overrides a configured
    // `[build] rustc-wrapper`.
    cmd.env("RUSTC_WRAPPER", &toolchain.clippy_driver);
    cmd.env("CLIPPY_CONF_DIR", conf_dir);
    cmd.env("RUSTC_BOOTSTRAP", RUSTC_BOOTSTRAP_OFF);
    // Highest-precedence flag source in cargo: it replaces RUSTFLAGS and every
    // `rustflags` key in configuration rather than adding to them.
    cmd.env(
        "CARGO_ENCODED_RUSTFLAGS",
        profile_rustflags().join(ENCODED_FLAG_SEPARATOR),
    );
    Ok(cmd)
}

/// One argument, so a path beginning with `-` cannot be read as a flag.
fn manifest_arg(path: &Path) -> OsString {
    let mut arg = OsString::from("--manifest-path=");
    arg.push(path);
    arg
}

/// The `cargo check` invocation that builds a crate under the Corten profile,
/// with Clippy reading its configuration from `conf_dir` (which must hold the
/// checker's `clippy.toml`).
///
/// The command inherits stdio; the caller runs it and reads its status.
/// With `sandbox`, cargo runs inside `corten-sandbox` from vendored sources
/// (`--locked --offline`), as [`build_command`] does, so build scripts and
/// procedural macros are confined during a check too.
///
/// # Errors
///
/// Returns [`ConfDirError`] if `conf_dir` cannot be written into a TOML
/// literal string.
pub fn check_command(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf_dir: &Path,
    sandbox: Option<&BuildSandbox>,
) -> Result<Command, ConfDirError> {
    let inner = pinned_cargo(toolchain, conf_dir)?;
    let mut cmd = match sandbox {
        None => inner,
        Some(s) => sandboxed(&inner, s, conf_dir),
    };
    cmd.args(["check", "--workspace", "--all-targets"]);
    if sandbox.is_some() {
        cmd.args(["--locked", "--offline"]);
    }
    if let Some(path) = manifest_path {
        cmd.arg(manifest_arg(path));
    }
    Ok(cmd)
}

/// Where a hermetic build may read and write (Linux, `corten-sandbox`).
///
/// Where a sandboxed check or build runs. Dependencies are vendored into
/// the target directory first (`cargo vendor`, outside the sandbox), so the sandboxed cargo reads only
/// the workspace, the vendored sources and the toolchain, uses a private
/// `CARGO_HOME` inside the target directory, and never sees the user's
/// `~/.cargo`, where a build script could otherwise plant a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSandbox {
    /// The `corten-sandbox` binary.
    pub sandbox: PathBuf,
    /// The toolchain root (cargo, rustc, clippy-driver and their libraries).
    pub toolchain_root: PathBuf,
    /// The workspace being built (read-only).
    pub workspace_root: PathBuf,
    /// Further read-only paths: local path dependencies outside the
    /// workspace, and the `Cargo.toml` files cargo reads above them to find
    /// their own workspace.
    pub local_paths: Vec<PathBuf>,
    /// The target directory (read-write; holds the vendored sources, the
    /// private cargo home and the temporary directory).
    pub target_dir: PathBuf,
    /// The source-replacement configuration `cargo vendor` printed.
    pub vendor_config: PathBuf,
}

impl BuildSandbox {
    /// The private `CARGO_HOME`.
    #[must_use]
    pub fn cargo_home(&self) -> PathBuf {
        self.target_dir.join("corten-home")
    }

    /// The private temporary directory.
    #[must_use]
    pub fn tmp_dir(&self) -> PathBuf {
        self.target_dir.join("corten-tmp")
    }
}

/// `inner` run inside `corten-sandbox` with the grants a cargo run needs:
/// the system directories, execute on the toolchain, read-only on the
/// workspace and `conf_dir`, read-write on the target directory, no network.
/// `inner`'s environment carries over, with a private `TMPDIR` and
/// `CARGO_HOME`, and cargo reads the vendored sources through
/// `--config <vendor_config>`.
fn sandboxed(inner: &Command, s: &BuildSandbox, conf_dir: &Path) -> Command {
    let mut outer = Command::new(&s.sandbox);
    outer
        .arg("--system")
        .arg("--exec")
        .arg(&s.toolchain_root)
        .arg("--ro")
        .arg(&s.workspace_root)
        .arg("--ro")
        .arg(conf_dir);
    for path in &s.local_paths {
        outer.arg("--ro").arg(path);
    }
    outer
        // cargo reads /proc/self and random bytes, and gives children
        // /dev/null; it reads nothing else of the host (strace, 2026-10-27).
        .args(["--ro", "/proc", "--ro", "/dev/urandom", "--rw", "/dev/null"])
        .arg("--rw")
        .arg(&s.target_dir)
        .arg("--")
        .arg(inner.get_program())
        .args(inner.get_args())
        .arg("--config")
        .arg(&s.vendor_config);
    for (key, value) in inner.get_envs() {
        match value {
            Some(v) => outer.env(key, v),
            None => outer.env_remove(key),
        };
    }
    outer.env("TMPDIR", s.tmp_dir());
    outer.env("CARGO_HOME", s.cargo_home());
    outer
}

/// The second pass: `cargo check` with `corten-driver` (rustc on a pinned
/// nightly, with Corten's own lints registered) as the compiler and only
/// [`profile::FORBIDDEN_CORTEN_LINTS`] as flags. It writes to
/// `target_dir`, apart from the first pass's artifacts, which a different
/// compiler built. `RUSTC_BOOTSTRAP=-1` stays pinned, so the nightly
/// compiler refuses `#![feature]` in the checked code like a stable one.
/// With `sandbox`, it runs there; `sandbox.local_paths` must also grant the
/// driver and its sysroot.
///
/// # Errors
///
/// As [`check_command`].
pub fn lint_command(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf_dir: &Path,
    driver: &Path,
    target_dir: &Path,
    sandbox: Option<&BuildSandbox>,
) -> Result<Command, ConfDirError> {
    let mut inner = pinned_cargo(toolchain, conf_dir)?;
    inner.env("RUSTC", driver);
    // Empty overrides a configured `[build] rustc-wrapper` as well.
    inner.env("RUSTC_WRAPPER", "");
    let mut flags = Vec::new();
    for lint in profile::FORBIDDEN_CORTEN_LINTS {
        flags.push("-F");
        flags.push(lint);
    }
    inner.env(
        "CARGO_ENCODED_RUSTFLAGS",
        flags.join(ENCODED_FLAG_SEPARATOR),
    );
    let mut cmd = match sandbox {
        None => inner,
        Some(s) => sandboxed(&inner, s, conf_dir),
    };
    cmd.args(["check", "--workspace", "--all-targets", "--target-dir"])
        .arg(target_dir);
    if sandbox.is_some() {
        cmd.args(["--locked", "--offline"]);
    }
    if let Some(path) = manifest_path {
        cmd.arg(manifest_arg(path));
    }
    Ok(cmd)
}

/// `cargo build --workspace --release --locked --offline` under the profile.
/// With `sandbox`, cargo runs inside `corten-sandbox`: no network, the
/// toolchain, registry cache and sources read-only, only the target
/// directory writable. Build scripts and procedural macros run inside it.
///
/// # Errors
///
/// As [`check_command`].
pub fn build_command(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf_dir: &Path,
    sandbox: Option<&BuildSandbox>,
) -> Result<Command, ConfDirError> {
    let inner = pinned_cargo(toolchain, conf_dir)?;
    let mut cmd = match sandbox {
        None => inner,
        Some(s) => sandboxed(&inner, s, conf_dir),
    };
    cmd.args(["build", "--workspace", "--release", "--locked", "--offline"]);
    if let Some(path) = manifest_path {
        cmd.arg(manifest_arg(path));
    }
    Ok(cmd)
}

/// `cargo vendor --versioned-dirs DIR`, outside the sandbox: copies every
/// dependency's source into `vendor_dir` and prints the source-replacement
/// configuration for the sandboxed, offline run. With `locked`, a lock file
/// that needs updating is an error (a build); without it, cargo writes the
/// lock file as a plain `cargo check` would (a check).
///
/// # Errors
///
/// As [`check_command`].
pub fn vendor_command(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf_dir: &Path,
    vendor_dir: &Path,
    locked: bool,
) -> Result<Command, ConfDirError> {
    let mut cmd = pinned_cargo(toolchain, conf_dir)?;
    cmd.arg("vendor");
    if locked {
        cmd.arg("--locked");
    }
    // --respect-source-config: vendor from the same sources a plain build of
    // this repository would use (mirrors, directory sources).
    cmd.args(["--versioned-dirs", "--respect-source-config"])
        .arg(vendor_dir);
    if let Some(path) = manifest_path {
        cmd.arg(manifest_arg(path));
    }
    Ok(cmd)
}

/// The `cargo metadata` invocation the dependency policy reads, under the
/// same environment as the check (so the repository's configuration cannot
/// run a program here either).
///
/// # Errors
///
/// As [`check_command`].
pub fn metadata_command(
    toolchain: &Toolchain,
    manifest_path: Option<&Path>,
    conf_dir: &Path,
) -> Result<Command, ConfDirError> {
    let mut cmd = pinned_cargo(toolchain, conf_dir)?;
    cmd.args(["metadata", "--format-version", "1"]);
    if let Some(path) = manifest_path {
        cmd.arg(manifest_arg(path));
    }
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// What the command does with one environment variable.
    #[derive(Debug, PartialEq)]
    enum EnvSetting<'a> {
        Inherited,
        Removed,
        Set(&'a OsStr),
    }

    fn env_of<'a>(cmd: &'a Command, key: &str) -> EnvSetting<'a> {
        match cmd.get_envs().find(|(k, _)| *k == OsStr::new(key)) {
            None => EnvSetting::Inherited,
            Some((_, None)) => EnvSetting::Removed,
            Some((_, Some(v))) => EnvSetting::Set(v),
        }
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            cargo: PathBuf::from("/tc/bin/cargo"),
            rustc: PathBuf::from("/tc/bin/rustc"),
            clippy_driver: PathBuf::from("/tc/bin/clippy-driver"),
        }
    }

    fn command(manifest: Option<&Path>) -> Command {
        check_command(&toolchain(), manifest, Path::new("/conf"), None).unwrap()
    }

    #[test]
    fn injects_profile_flags_as_encoded_rustflags() {
        let cmd = command(None);
        let EnvSetting::Set(flags) = env_of(&cmd, "CARGO_ENCODED_RUSTFLAGS") else {
            panic!("CARGO_ENCODED_RUSTFLAGS not set");
        };
        let flags: Vec<_> = flags.to_str().unwrap().split('\u{1f}').collect();
        assert_eq!(flags, profile_rustflags());
        for needle in [
            "unsafe_code",
            "unused_must_use",
            "clippy::disallowed_methods",
            "clippy::arithmetic_side_effects",
            "overflow-checks=on",
        ] {
            assert!(flags.contains(&needle), "{needle} missing from {flags:?}");
        }
        let forbids = flags.iter().filter(|f| **f == "-F").count();
        assert_eq!(
            forbids,
            profile::FORBIDDEN_RUSTC_LINTS.len() + profile::FORBIDDEN_CLIPPY_LINTS.len()
        );
    }

    #[test]
    fn overrides_wrappers_and_toolchain_and_removes_flag_variables() {
        let cmd = command(None);
        for name in EMPTIED_ENV {
            assert_eq!(
                env_of(&cmd, name),
                EnvSetting::Set(OsStr::new("")),
                "{name}"
            );
        }
        for name in REMOVED_ENV {
            assert_eq!(env_of(&cmd, name), EnvSetting::Removed, "{name}");
        }
        for (name, value) in [
            ("RUSTC", "/tc/bin/rustc"),
            ("RUSTC_WRAPPER", "/tc/bin/clippy-driver"),
            ("CLIPPY_CONF_DIR", "/conf"),
            ("RUSTC_BOOTSTRAP", "-1"),
        ] {
            assert_eq!(
                env_of(&cmd, name),
                EnvSetting::Set(OsStr::new(value)),
                "{name}"
            );
        }
    }

    #[test]
    fn pins_env_through_config_and_keeps_manifest_path_one_argument() {
        let cmd = command(Some(Path::new("-evil/Cargo.toml")));
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "--config",
                "env.CLIPPY_CONF_DIR.value='/conf'",
                "--config",
                "env.CLIPPY_CONF_DIR.force=true",
                "--config",
                "env.RUSTC_BOOTSTRAP.value='-1'",
                "--config",
                "env.RUSTC_BOOTSTRAP.force=true",
                "check",
                "--workspace",
                "--all-targets",
                "--manifest-path=-evil/Cargo.toml"
            ]
        );
    }

    #[test]
    fn conf_dir_that_breaks_toml_is_refused() {
        for bad in ["/a'b", "/a\nb"] {
            assert!(
                check_command(&toolchain(), None, Path::new(bad), None).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn toolchain_requires_cargo() {
        assert_eq!(
            Toolchain::from_env(None, Some("rustc".into())),
            Err(ToolchainError::CargoUnknown)
        );
    }

    #[test]
    fn missing_sibling_rustc_is_an_error() {
        let tc = Toolchain::from_env(Some("/nowhere/cargo".into()), None);
        assert!(matches!(tc, Err(ToolchainError::RustcNotBesideCargo(_))));
    }

    #[test]
    fn missing_clippy_driver_is_an_error() {
        let tc = Toolchain::from_env(Some("/nowhere/cargo".into()), Some("/x/rustc".into()));
        assert!(matches!(
            tc,
            Err(ToolchainError::ClippyDriverNotBesideCargo(_))
        ));
    }

    #[test]
    fn clippy_toml_parses_as_toml_shaped_lists() {
        // Every entry is one line of the form { path = "...", reason = "..." }.
        let entries = profile::CLIPPY_TOML
            .lines()
            .filter(|l| l.trim_start().starts_with("{ path"))
            .count();
        assert!(entries > 60, "{entries}");
    }
}
