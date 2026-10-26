//! End to end: `cargo corten check` on generated crates, including crates
//! whose cargo configuration tries to weaken the injected flags.
//!
//! Every rejection is paired with an acceptance of a benign crate, so false
//! rejections are measured beside detections (`AGENTS.md` rule 2). Every
//! hostile configuration is first shown to work against plain `cargo check`,
//! so a pass here cannot come from a bypass that never ran.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

/// Unsafe code with the in-source `forbid` deleted: the spec section 10 case.
const UNSAFE_NO_ATTRIBUTE: &str = "\
fn main() {
    let x = 1u8;
    let p = &raw const x;
    let _v = unsafe { *p };
}
";

/// Unsafe code that tries to allow itself.
const UNSAFE_WITH_ALLOW: &str = "#![allow(unsafe_code)]\n";

/// The matched benign program: same shape, no unsafe.
const SAFE: &str = "\
fn main() {
    let x = 1u8;
    let r = &x;
    let _v = *r;
}
";

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str, main_rs: &str) -> io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("corten-test-{}-{name}", process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        let fixture = Self { dir };
        fixture.write(
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )?;
        fixture.write("src/main.rs", main_rs)?;
        Ok(fixture)
    }

    fn write(&self, rel: &str, contents: &str) -> io::Result<()> {
        let path = self.dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)
    }

    /// File a hostile tool creates when cargo runs it.
    fn marker(&self) -> PathBuf {
        self.dir.join("hostile-tool-ran")
    }

    fn manifest(&self) -> PathBuf {
        self.dir.join("Cargo.toml")
    }

    fn target(&self) -> PathBuf {
        self.dir.join("target")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.dir) {
            eprintln!("could not remove {}: {e}", self.dir.display());
        }
    }
}

struct Outcome {
    code: Option<i32>,
    stderr: String,
}

fn outcome(cmd: &mut Command) -> io::Result<Outcome> {
    let out = cmd.output()?;
    Ok(Outcome {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// `cargo corten check` on the fixture, with extra environment.
fn corten(fx: &Fixture, env: &[(&str, &str)]) -> io::Result<Outcome> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cargo-corten"));
    cmd.args(["corten", "check", "--manifest-path"])
        .arg(fx.manifest())
        .env("CARGO", env!("CARGO"))
        .env_remove("RUSTC")
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target())
        .envs(env.iter().copied());
    outcome(&mut cmd)
}

/// Plain `cargo check` with the profile flags injected the same way, but no
/// neutralisation: the control that proves a hostile configuration is live.
fn plain_cargo_with_profile_flags(fx: &Fixture) -> io::Result<Outcome> {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["check", "--manifest-path"])
        .arg(fx.manifest())
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target())
        .env("CARGO_ENCODED_RUSTFLAGS", "-F\u{1f}unsafe_code");
    outcome(&mut cmd)
}

#[test]
fn rejects_unsafe_after_the_in_source_forbid_is_deleted() {
    let fx = Fixture::new("no-attr", UNSAFE_NO_ATTRIBUTE).unwrap();
    // Control: without the checker this builds (spec section 10, row 2).
    let mut plain = Command::new(env!("CARGO"));
    plain
        .args(["check", "--manifest-path"])
        .arg(fx.manifest())
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target());
    assert_eq!(outcome(&mut plain).unwrap().code, Some(0));

    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr.contains("usage of an `unsafe` block"),
        "{}",
        out.stderr
    );
}

#[test]
fn rejects_unsafe_that_allows_itself() {
    let src = format!("{UNSAFE_WITH_ALLOW}{UNSAFE_NO_ATTRIBUTE}");
    let fx = Fixture::new("allow", &src).unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("E0453"), "{}", out.stderr);
}

#[test]
fn accepts_the_matched_safe_program() {
    let fx = Fixture::new("safe", SAFE).unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.stderr);
}

#[test]
fn operator_rustflags_cannot_lower_the_profile() {
    let fx = Fixture::new("operator-rustflags", UNSAFE_NO_ATTRIBUTE).unwrap();
    let out = corten(&fx, &[("RUSTFLAGS", "-A unsafe_code")]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
}

#[test]
fn config_rustflags_cannot_lower_the_profile() {
    // The cfg proves the configuration is read: without it, `compile_error!`.
    let config = "[build]\nrustflags = [\"-A\", \"unsafe_code\", \"--cfg\", \"config_read\", \"--check-cfg\", \"cfg(config_read)\"]\n";
    let probe = "#[cfg(not(config_read))]\ncompile_error!(\"config not read\");\n";
    let bad = Fixture::new(
        "config-rustflags-bad",
        &format!("{probe}{UNSAFE_NO_ATTRIBUTE}"),
    )
    .unwrap();
    bad.write(".cargo/config.toml", config).unwrap();

    let mut plain = Command::new(env!("CARGO"));
    plain
        .arg("check")
        .current_dir(&bad.dir)
        .env("CARGO_TARGET_DIR", bad.target());
    let control = outcome(&mut plain).unwrap();
    assert_eq!(
        control.code,
        Some(0),
        "control: config not read\n{}",
        control.stderr
    );

    let out = corten(&bad, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr.contains("usage of an `unsafe` block"),
        "{}",
        out.stderr
    );

    let good = Fixture::new("config-rustflags-good", SAFE).unwrap();
    good.write(".cargo/config.toml", config).unwrap();
    assert_eq!(corten(&good, &[]).unwrap().code, Some(0));
}

#[test]
fn usage_errors_exit_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-corten"))
        .args(["corten", "build"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[cfg(unix)]
mod hostile_tools {
    //! A repository's `.cargo/config.toml` can name a program cargo runs in
    //! place of, or around, rustc. These stand-ins drop the profile flags.

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// POSIX shell that records it ran, drops `-F unsafe_code`, then runs
    /// `exec_prefix` followed by the remaining arguments.
    fn flag_stripper(fx: &Fixture, exec_prefix: &str) -> io::Result<PathBuf> {
        let path = fx.dir.join("strip-flags.sh");
        let script = format!(
            "#!/bin/sh\n: > '{marker}'\nfor a do\n  shift\n  case \"$a\" in -F|-Funsafe_code|unsafe_code) continue;; esac\n  set -- \"$@\" \"$a\"\ndone\nexec {exec_prefix} \"$@\"\n",
            marker = fx.marker().display(),
        );
        fs::write(&path, script)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(path)
    }

    /// Runs the control, then the checker on the unsafe program and on the
    /// matched safe one, under the configuration `config_for(script)`.
    fn assert_neutralised(
        name: &str,
        exec_prefix: &str,
        config_for: fn(&Path) -> String,
    ) -> io::Result<()> {
        let bad = Fixture::new(&format!("{name}-bad"), UNSAFE_NO_ATTRIBUTE)?;
        let script = flag_stripper(&bad, exec_prefix)?;
        bad.write(".cargo/config.toml", &config_for(&script))?;

        let control = plain_cargo_with_profile_flags(&bad)?;
        assert_eq!(
            control.code,
            Some(0),
            "control: the hostile tool should bypass plain cargo\n{}",
            control.stderr
        );
        assert!(bad.marker().exists(), "control: the hostile tool never ran");
        fs::remove_file(bad.marker())?;
        fs::remove_dir_all(bad.target())?;

        let out = corten(&bad, &[])?;
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(
            !bad.marker().exists(),
            "the hostile tool ran under the checker"
        );

        let good = Fixture::new(&format!("{name}-good"), SAFE)?;
        let script = flag_stripper(&good, exec_prefix)?;
        good.write(".cargo/config.toml", &config_for(&script))?;
        let out = corten(&good, &[])?;
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert!(
            !good.marker().exists(),
            "the hostile tool ran under the checker"
        );
        Ok(())
    }

    fn real_rustc() -> PathBuf {
        Path::new(env!("CARGO")).with_file_name("rustc")
    }

    fn quoted(path: &Path) -> String {
        format!("{:?}", path.display().to_string())
    }

    #[test]
    fn config_rustc_wrapper_is_not_run() {
        // A wrapper gets the real rustc as its first argument.
        assert_neutralised("wrapper", "", |s| {
            format!("[build]\nrustc-wrapper = {}\n", quoted(s))
        })
        .unwrap();
    }

    #[test]
    fn config_rustc_workspace_wrapper_is_not_run() {
        assert_neutralised("workspace-wrapper", "", |s| {
            format!("[build]\nrustc-workspace-wrapper = {}\n", quoted(s))
        })
        .unwrap();
    }

    #[test]
    fn config_rustc_replacement_is_not_run() {
        // A replacement rustc is not handed the real one, so the stand-in
        // execs it by path.
        let rustc = format!("'{}'", real_rustc().display());
        assert_neutralised("rustc-replacement", &rustc, |s| {
            format!("[build]\nrustc = {}\n", quoted(s))
        })
        .unwrap();
    }
}
