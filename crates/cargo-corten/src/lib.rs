//! Library behind the `cargo corten` subcommand.
//!
//! `cargo corten check` runs `cargo check` with lint flags the checker
//! supplies itself, and overrides the ways the checked repository could
//! weaken them (`docs/spec.md` section 10, `AGENTS.md` rule 3). The crate
//! README lists what is neutralised today and what is not.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Flags every checked crate is compiled with, in the order rustc gets them.
///
/// Phase 1 of the roadmap adds the Clippy lint set; until then the profile is
/// the one rule measured in spec section 10.
pub const PROFILE_RUSTFLAGS: &[&str] = &["-F", "unsafe_code"];

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
];

/// Wrapper variables set to the empty string. An empty value overrides a
/// `[build] rustc-wrapper` (or `rustc-workspace-wrapper`) in any
/// `.cargo/config.toml` the checked repository or its ancestors carry; such a
/// wrapper could drop the injected flags (measured, see the README).
const EMPTIED_ENV: &[&str] = &["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"];

/// Where the checker finds the toolchain it drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    /// The `cargo` binary to run.
    pub cargo: PathBuf,
    /// The `rustc` binary cargo must use, overriding any `[build] rustc` in
    /// the checked repository's configuration.
    pub rustc: PathBuf,
}

/// Why the toolchain could not be located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolchainError {
    /// `CARGO` is unset, so this was not started as `cargo corten`.
    CargoUnknown,
    /// `RUSTC` is unset and no `rustc` sits beside the `cargo` binary.
    RustcNotBesideCargo(PathBuf),
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
        }
    }
}

impl std::error::Error for ToolchainError {}

impl Toolchain {
    /// Locates the toolchain from the operator's environment.
    ///
    /// `CARGO` (set by cargo when it runs a subcommand) names cargo. `RUSTC`
    /// names rustc when the operator set it; otherwise the `rustc` beside
    /// cargo is used. Nothing is read from the checked repository.
    ///
    /// # Errors
    ///
    /// Returns [`ToolchainError`] when cargo or rustc cannot be located.
    pub fn from_env(
        cargo: Option<OsString>,
        rustc: Option<OsString>,
    ) -> Result<Self, ToolchainError> {
        let cargo = PathBuf::from(cargo.ok_or(ToolchainError::CargoUnknown)?);
        let rustc = if let Some(rustc) = rustc {
            PathBuf::from(rustc)
        } else {
            let sibling = cargo.with_file_name(format!("rustc{}", std::env::consts::EXE_SUFFIX));
            if !sibling.is_file() {
                return Err(ToolchainError::RustcNotBesideCargo(sibling));
            }
            sibling
        };
        Ok(Self { cargo, rustc })
    }
}

/// The `cargo check` invocation that builds a crate under the Corten profile.
///
/// The command inherits stdio; the caller runs it and reads its status.
#[must_use]
pub fn check_command(toolchain: &Toolchain, manifest_path: Option<&Path>) -> Command {
    let mut cmd = Command::new(&toolchain.cargo);
    cmd.args(["check", "--workspace", "--all-targets"]);
    if let Some(path) = manifest_path {
        // One argument, so a path beginning with `-` cannot be read as a flag.
        let mut arg = OsString::from("--manifest-path=");
        arg.push(path);
        cmd.arg(arg);
    }
    for name in REMOVED_ENV {
        cmd.env_remove(name);
    }
    for name in EMPTIED_ENV {
        cmd.env(name, "");
    }
    cmd.env("RUSTC", &toolchain.rustc);
    // Highest-precedence flag source in cargo: it replaces RUSTFLAGS and every
    // `rustflags` key in configuration rather than adding to them.
    cmd.env(
        "CARGO_ENCODED_RUSTFLAGS",
        PROFILE_RUSTFLAGS.join(ENCODED_FLAG_SEPARATOR),
    );
    cmd
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
        }
    }

    #[test]
    fn injects_profile_flags_as_encoded_rustflags() {
        let cmd = check_command(&toolchain(), None);
        assert_eq!(
            env_of(&cmd, "CARGO_ENCODED_RUSTFLAGS"),
            EnvSetting::Set(OsStr::new("-F\u{1f}unsafe_code"))
        );
    }

    #[test]
    fn overrides_wrappers_and_rustc_and_removes_flag_variables() {
        let cmd = check_command(&toolchain(), None);
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
        assert_eq!(
            env_of(&cmd, "RUSTC"),
            EnvSetting::Set(OsStr::new("/tc/bin/rustc"))
        );
    }

    #[test]
    fn manifest_path_is_a_single_argument() {
        let cmd = check_command(&toolchain(), Some(Path::new("-evil/Cargo.toml")));
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "check",
                "--workspace",
                "--all-targets",
                "--manifest-path=-evil/Cargo.toml"
            ]
        );
    }

    #[test]
    fn toolchain_requires_cargo() {
        assert_eq!(
            Toolchain::from_env(None, Some("rustc".into())),
            Err(ToolchainError::CargoUnknown)
        );
    }

    #[test]
    fn operator_rustc_wins_over_sibling() {
        let tc = Toolchain::from_env(Some("/nowhere/cargo".into()), Some("/x/rustc".into()));
        assert_eq!(tc.map(|t| t.rustc), Ok(PathBuf::from("/x/rustc")));
    }

    #[test]
    fn missing_sibling_rustc_is_an_error() {
        let tc = Toolchain::from_env(Some("/nowhere/cargo".into()), None);
        assert!(matches!(tc, Err(ToolchainError::RustcNotBesideCargo(_))));
    }
}
