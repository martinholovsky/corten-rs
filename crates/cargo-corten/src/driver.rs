//! Which `corten-driver` the checker trusts, and how a prebuilt one loads.
//!
//! The driver is part of the trusted base: it runs Corten's own lints. By
//! default the checker accepts only a release binary whose SHA-256 is pinned
//! for the host target in `driver-pins.txt`, compiled into this checker. A
//! driver the operator built (`scripts/build-driver.sh`) is accepted only
//! through `--unpinned-driver PATH`, a command-line flag a checked repository
//! cannot set, with a warning on every run (owner decision 2026-11-22; design
//! principle 2: a weaker mode is explicit and logged).
//!
//! A release binary carries the build machine's library path, so the checker
//! starts it with the pinned nightly's `lib` directory as the loader path
//! (`LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH` on macOS). It finds that
//! directory by asking rustup, with automatic installation off: the checker
//! makes no network call, and a missing nightly is reported with the exact
//! command that installs it.

use std::fmt;

/// The pins, as compiled into this checker.
const PINS: &str = include_str!("../driver-pins.txt");

/// The lint driver's `rust-toolchain.toml`, which names its nightly.
const DRIVER_TOOLCHAIN_TOML: &str = include_str!("../../corten-lints/rust-toolchain.toml");

/// The rustup target triple this checker was built for, where a prebuilt
/// driver is published for it.
#[must_use]
pub fn host_target() -> Option<&'static str> {
    if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else {
        None
    }
}

/// The environment variable that names the loader's library path here.
#[must_use]
pub fn library_path_var() -> &'static str {
    if cfg!(target_os = "macos") {
        "DYLD_LIBRARY_PATH"
    } else {
        "LD_LIBRARY_PATH"
    }
}

/// The nightly the lint driver is built on (`channel` in
/// `crates/corten-lints/rust-toolchain.toml`).
#[must_use]
pub fn pinned_toolchain() -> Option<&'static str> {
    toolchain_channel(DRIVER_TOOLCHAIN_TOML)
}

fn toolchain_channel(toml: &str) -> Option<&str> {
    toml.lines().find_map(|line| {
        let value = line.trim().strip_prefix("channel")?.trim_start();
        let value = value.strip_prefix('=')?.trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        (!value.is_empty()).then_some(value)
    })
}

/// The command that installs the driver's nightly with what a prebuilt
/// driver needs at run time (no `rustc-dev`).
#[must_use]
pub fn install_command(toolchain: &str) -> String {
    format!("rustup toolchain install {toolchain} --profile minimal")
}

/// Why a driver binary is not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// No prebuilt driver is published for this platform.
    UnsupportedTarget,
    /// `driver-pins.txt` names no binary for the host target.
    NoPin {
        /// The host target.
        target: &'static str,
    },
    /// The binary's SHA-256 is not the pinned one.
    Mismatch {
        /// The host target.
        target: &'static str,
        /// The binary's digest.
        found: String,
    },
    /// A line of the pins file is malformed (a defect in this checker).
    BadPins(String),
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTarget => {
                write!(f, "no prebuilt corten-driver exists for this platform")
            }
            Self::NoPin { target } => write!(
                f,
                "this cargo-corten pins no corten-driver release for {target}"
            ),
            Self::Mismatch { target, found } => write!(
                f,
                "its SHA-256 {found} is not the corten-driver release this cargo-corten pins for {target}"
            ),
            Self::BadPins(line) => write!(f, "malformed line in driver-pins.txt: {line:?}"),
        }
    }
}

impl std::error::Error for PinError {}

/// Accepts `digest` (lowercase hex SHA-256 of the driver binary) only when it
/// is the pin for the host target.
///
/// # Errors
///
/// [`PinError`] when the platform has no prebuilt driver, no pin, or another
/// digest.
pub fn check_pinned(digest: &str) -> Result<(), PinError> {
    let target = host_target().ok_or(PinError::UnsupportedTarget)?;
    check_against(PINS, target, digest)
}

fn check_against(pins: &str, target: &'static str, digest: &str) -> Result<(), PinError> {
    let mut pinned = None;
    for line in pins.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(t), Some(d), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(PinError::BadPins(line.to_owned()));
        };
        if d.len() != 64
            || !d
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PinError::BadPins(line.to_owned()));
        }
        if t == target {
            pinned = Some(d);
        }
    }
    match pinned {
        None => Err(PinError::NoPin { target }),
        Some(d) if d == digest => Ok(()),
        Some(_) => Err(PinError::Mismatch {
            target,
            found: digest.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn only_the_pinned_digest_for_the_target_is_accepted() {
        let pins = format!("# comment\n\nx86_64-unknown-linux-gnu {A}\naarch64-apple-darwin {B}\n");
        assert_eq!(check_against(&pins, "x86_64-unknown-linux-gnu", A), Ok(()));
        assert_eq!(check_against(&pins, "aarch64-apple-darwin", B), Ok(()));
        // Another target's pin does not count.
        assert_eq!(
            check_against(&pins, "x86_64-unknown-linux-gnu", B),
            Err(PinError::Mismatch {
                target: "x86_64-unknown-linux-gnu",
                found: B.to_owned()
            })
        );
        assert_eq!(
            check_against(&pins, "x86_64-apple-darwin", A),
            Err(PinError::NoPin {
                target: "x86_64-apple-darwin"
            })
        );
    }

    #[test]
    fn malformed_pins_are_an_error_not_a_skip() {
        for bad in [
            format!("x86_64-unknown-linux-gnu {A} extra"),
            "x86_64-unknown-linux-gnu".to_owned(),
            format!("x86_64-unknown-linux-gnu {}", A.to_uppercase()),
            format!("x86_64-unknown-linux-gnu {}", "a".repeat(63)),
        ] {
            assert!(
                matches!(
                    check_against(&bad, "x86_64-unknown-linux-gnu", A),
                    Err(PinError::BadPins(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_shipped_pins_file_parses() {
        // Empty until the first driver release; whatever it holds must parse.
        match check_against(PINS, "x86_64-unknown-linux-gnu", A) {
            Ok(()) | Err(PinError::NoPin { .. } | PinError::Mismatch { .. }) => {}
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn the_driver_toolchain_is_read_from_its_toml() {
        let channel = pinned_toolchain().unwrap_or_default();
        assert!(channel.starts_with("nightly-"), "{channel:?}");
        assert_eq!(
            toolchain_channel("[toolchain]\nchannel = \"nightly-2026-10-26\"\n"),
            Some("nightly-2026-10-26")
        );
        assert_eq!(toolchain_channel("[toolchain]\nchannel = \"\"\n"), None);
        assert_eq!(toolchain_channel("[toolchain]\n"), None);
    }

    #[test]
    fn the_install_command_needs_no_rustc_dev() {
        assert_eq!(
            install_command("nightly-2026-10-26"),
            "rustup toolchain install nightly-2026-10-26 --profile minimal"
        );
    }
}
