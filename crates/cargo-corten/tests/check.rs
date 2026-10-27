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

    /// File a hostile tool creates when cargo runs it. It lives in the target
    /// directory, the one place the sandboxed check can write, so a tool that
    /// runs inside the sandbox is still seen.
    fn marker(&self) -> PathBuf {
        self.target().join("hostile-tool-ran")
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
    // Fixtures are judged on errors; CI's CARGO_BUILD_WARNINGS=deny would turn
    // a fixture's own warnings into failures that say nothing about the rule.
    let out = cmd.env_remove("CARGO_BUILD_WARNINGS").output()?;
    Ok(Outcome {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// The `corten-driver` the checker under test uses: `CORTEN_DRIVER`, or the
/// one `scripts/build-driver.sh` builds. The checker requires it.
fn driver() -> String {
    if let Some(path) = std::env::var_os("CORTEN_DRIVER") {
        return path.to_string_lossy().into_owned();
    }
    let built =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../corten-lints/target/debug/corten-driver");
    assert!(
        built.is_file(),
        "corten-driver is not built: run scripts/build-driver.sh, or set CORTEN_DRIVER"
    );
    built.to_string_lossy().into_owned()
}

/// `cargo corten check` on the fixture, with extra environment (which may
/// replace `CORTEN_DRIVER`).
fn corten(fx: &Fixture, env: &[(&str, &str)]) -> io::Result<Outcome> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cargo-corten"));
    cmd.args(["corten", "check", "--manifest-path"])
        .arg(fx.manifest())
        .env("CARGO", env!("CARGO"))
        .env_remove("RUSTC")
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target())
        .env("CORTEN_DRIVER", driver())
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

/// Reads a file through ambient `std::fs`: the disallowed-methods ban.
const AMBIENT_FS: &str = "\
fn main() {
    let _text = std::fs::read_to_string(\"input\");
}
";

#[test]
fn ban_list_resolves_and_safe_program_is_clean() {
    let fx = Fixture::new("ban-list-resolves", SAFE).unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    // Clippy warns about a ban-list path it cannot resolve, and such an entry
    // bans nothing.
    assert!(
        !out.stderr.contains("does not refer to a reachable"),
        "{}",
        out.stderr
    );
    // Off Linux the checker itself warns that there is no sandbox; any other
    // warning comes from the build.
    let build_output: Vec<&str> = out
        .stderr
        .lines()
        .filter(|l| !l.starts_with("warning: no sandbox on this platform"))
        .collect();
    assert!(
        !build_output.iter().any(|l| l.contains("warning")),
        "{}",
        out.stderr
    );
}

#[test]
fn ambient_filesystem_access_is_rejected() {
    let fx = Fixture::new("ambient-fs", AMBIENT_FS).unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr.contains("use of a disallowed method"),
        "{}",
        out.stderr
    );
}

#[test]
fn unchecked_arithmetic_is_rejected() {
    // A runtime operand: Clippy skips arithmetic it can evaluate as a
    // constant (recorded in docs/gates/phase-1.md).
    let src =
        "fn add(a: u8, b: u8) -> u8 {\n    a + b\n}\nfn main() {\n    let _c = add(1, 2);\n}\n";
    let fx = Fixture::new("arith", src).unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("arithmetic"), "{}", out.stderr);
}

#[test]
fn repository_clippy_toml_cannot_empty_the_ban_list() {
    let fx = Fixture::new("repo-clippy-toml", AMBIENT_FS).unwrap();
    fx.write("clippy.toml", "disallowed-methods = []\n")
        .unwrap();
    fx.write(".clippy.toml", "disallowed-methods = []\n")
        .unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr.contains("use of a disallowed method"),
        "{}",
        out.stderr
    );
}

#[test]
fn forced_env_clippy_conf_dir_cannot_replace_the_ban_list() {
    let fx = Fixture::new("env-clippy-conf", AMBIENT_FS).unwrap();
    fx.write("evil/clippy.toml", "disallowed-methods = []\n")
        .unwrap();
    let config = format!(
        "[env]\nCLIPPY_CONF_DIR = {{ value = {:?}, force = true }}\n",
        fx.dir.join("evil").display().to_string()
    );
    fx.write(".cargo/config.toml", &config).unwrap();
    // Control: with the checker's flags and conf dir but without --config
    // pinning, the forced [env] entry wins and the ban list is empty.
    let conf = fx.dir.join("checker-conf");
    fs::create_dir_all(&conf).unwrap();
    fs::write(
        conf.join("clippy.toml"),
        "disallowed-methods = [{ path = \"std::fs::read_to_string\", reason = \"x\" }]\n",
    )
    .unwrap();
    let driver = Path::new(env!("CARGO")).with_file_name("clippy-driver");
    let mut plain = Command::new(env!("CARGO"));
    plain
        .arg("check")
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target())
        .env("RUSTC_WORKSPACE_WRAPPER", driver)
        .env("CLIPPY_CONF_DIR", &conf)
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            "-F\u{1f}clippy::disallowed_methods",
        );
    let control = outcome(&mut plain).unwrap();
    assert_eq!(
        control.code,
        Some(0),
        "control: [env] not effective\n{}",
        control.stderr
    );

    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr.contains("use of a disallowed method"),
        "{}",
        out.stderr
    );
}

#[test]
fn forced_env_rustc_bootstrap_cannot_unlock_nightly_features() {
    let src = "#![feature(rustc_attrs)]\nfn main() {}\n";
    let fx = Fixture::new("env-bootstrap", src).unwrap();
    fx.write(
        ".cargo/config.toml",
        "[env]\nRUSTC_BOOTSTRAP = { value = \"1\", force = true }\n",
    )
    .unwrap();
    // Control: plain cargo builds the nightly-only crate on stable.
    let mut plain = Command::new(env!("CARGO"));
    plain
        .arg("check")
        .current_dir(&fx.dir)
        .env_remove("RUSTC_BOOTSTRAP")
        .env("CARGO_TARGET_DIR", fx.target());
    let control = outcome(&mut plain).unwrap();
    assert_eq!(
        control.code,
        Some(0),
        "control: [env] not effective\n{}",
        control.stderr
    );

    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("E0554"), "{}", out.stderr);
}

#[test]
fn local_path_dependency_outside_the_workspace_is_linted() {
    // The workspace is app/; helper/ sits beside it, so cargo does not make
    // it a member (a path dependency under the workspace root would be one).
    let fx = Fixture::new("path-dep", "").unwrap();
    fx.write(
        "app/Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nhelper = { path = \"../helper\" }\n",
    )
    .unwrap();
    fx.write(
        "app/src/main.rs",
        "fn main() {\n    println!(\"{}\", helper::narrow(300));\n}\n",
    )
    .unwrap();
    fx.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fx.write(
        "helper/src/lib.rs",
        "pub fn narrow(v: u32) -> u8 {\n    v as u8\n}\n",
    )
    .unwrap();
    let app = fx.dir.join("app");
    let mut plain = Command::new(env!("CARGO"));
    plain
        .arg("check")
        .current_dir(&app)
        .env("CARGO_TARGET_DIR", fx.target());
    let control = outcome(&mut plain).unwrap();
    assert_eq!(control.code, Some(0), "control\n{}", control.stderr);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cargo-corten"));
    cmd.args(["corten", "check"])
        .current_dir(&app)
        .env("CARGO", env!("CARGO"))
        .env_remove("RUSTC")
        .env("CARGO_TARGET_DIR", fx.target());
    let out = outcome(&mut cmd).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("as-conversions"), "{}", out.stderr);
}

/// A non-local dependency, as cargo sees a registry crate: a directory
/// source replaces crates-io with `vendor/`.
fn vendor_crate(fx: &Fixture, name: &str, cargo_extra: &str, lib_rs: &str) -> io::Result<()> {
    fx.write(
        &format!("vendor/{name}/Cargo.toml"),
        &format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{cargo_extra}"
        ),
    )?;
    fx.write(&format!("vendor/{name}/src/lib.rs"), lib_rs)?;
    fx.write(
        &format!("vendor/{name}/.cargo-checksum.json"),
        "{\"files\":{},\"package\":null}",
    )?;
    let config = format!(
        "[source.crates-io]\nreplace-with = \"vendored\"\n[source.vendored]\ndirectory = {:?}\n",
        fx.dir.join("vendor").display().to_string()
    );
    fx.write(".cargo/config.toml", &config)
}

fn with_dependency(fx: &Fixture, name: &str) -> io::Result<()> {
    fx.write(
        "Cargo.toml",
        &format!("[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\n{name} = \"0.1.0\"\n"),
    )
}

/// Phase 1 found this bypass: a macro exported by a non-local dependency
/// expands to `unsafe` in the checked crate, and rustc does not report
/// `unsafe_code` inside external macro expansions. The layer 3 dependency
/// policy now refuses such a dependency unless the operator allows it.
#[test]
fn dependency_exporting_an_unsafe_macro_is_refused() {
    let main = "fn main() {\n    let p: *const u32 = std::ptr::null();\n    let v = evil_macro::read_raw!(p);\n    println!(\"{v}\");\n}\n";
    let fx = Fixture::new("dep-macro", main).unwrap();
    with_dependency(&fx, "evil-macro").unwrap();
    vendor_crate(
        &fx,
        "evil-macro",
        "",
        "#[macro_export]\nmacro_rules! read_raw {\n    ($p:expr) => { unsafe { *$p } };\n}\n",
    )
    .unwrap();
    // Control: plain cargo builds it.
    let mut plain = Command::new(env!("CARGO"));
    plain
        .arg("check")
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target());
    assert_eq!(outcome(&mut plain).unwrap().code, Some(0));

    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("dependency policy"), "{}", out.stderr);
    assert!(
        out.stderr.contains(
            "evil-macro@0.1.0: local code uses exported macros that expand to unsafe: read_raw"
        ),
        "{}",
        out.stderr
    );

    // Allowed by the operator, the dependency passes layer 3, and Clippy's
    // pass does not see the expansion (rustc drops `unsafe_code` in external
    // macros). Corten's own lint does: the second pass refuses it.
    let allowed = corten(&fx, &[("CORTEN_ALLOW_DEPS", "evil-macro")]).unwrap();
    assert_eq!(allowed.code, Some(1), "{}", allowed.stderr);
    assert!(
        allowed
            .stderr
            .contains("`unsafe` block expanded from macro `evil_macro::read_raw`"),
        "{}",
        allowed.stderr
    );
}

/// The driver is required (owner decision 10): without it the check refuses
/// to report a pass.
#[test]
fn missing_driver_is_an_error() {
    let fx = Fixture::new("no-driver", SAFE).unwrap();
    let out = corten(&fx, &[("CORTEN_DRIVER", "/nonexistent/corten-driver")]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr.contains("corten-driver is not installed"),
        "{}",
        out.stderr
    );
    // Control: the same program passes with the driver.
    assert_eq!(corten(&fx, &[]).unwrap().code, Some(0));
}

#[test]
fn procedural_macro_dependency_is_refused() {
    let fx = Fixture::new("dep-proc-macro", "derive_it::nothing!();\nfn main() {}\n").unwrap();
    with_dependency(&fx, "derive-it").unwrap();
    vendor_crate(
        &fx,
        "derive-it",
        "\n[lib]\nproc-macro = true\n",
        "extern crate proc_macro;\n#[proc_macro]\npub fn nothing(_i: proc_macro::TokenStream) -> proc_macro::TokenStream {\n    proc_macro::TokenStream::new()\n}\n",
    ).unwrap();
    // Control: plain cargo builds it.
    let mut plain = Command::new(env!("CARGO"));
    plain
        .arg("check")
        .current_dir(&fx.dir)
        .env("CARGO_TARGET_DIR", fx.target());
    assert_eq!(outcome(&mut plain).unwrap().code, Some(0));

    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(
        out.stderr
            .contains("derive-it@0.1.0: procedural macro used by local code (nothing)"),
        "{}",
        out.stderr
    );

    // The same dependency, unused by local code, is accepted: the policy
    // judges what the crate can reach and uses.
    fx.write("src/main.rs", "fn main() {}\n").unwrap();
    let unused = corten(&fx, &[]).unwrap();
    assert_eq!(unused.code, Some(0), "{}", unused.stderr);
}

#[test]
fn dependency_with_only_safe_macros_is_accepted() {
    let fx = Fixture::new(
        "dep-safe",
        "fn main() {\n    println!(\"{}\", tidy::double!(2u32));\n}\n",
    )
    .unwrap();
    with_dependency(&fx, "tidy").unwrap();
    vendor_crate(
        &fx,
        "tidy",
        "",
        "#[macro_export]\nmacro_rules! double {\n    ($v:expr) => { $v.saturating_mul(2) };\n}\n/// Mentions unsafe { only } in a comment and a \"string with unsafe\".\npub fn note() -> &'static str { \"unsafe\" }\n",
    ).unwrap();
    let out = corten(&fx, &[]).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.stderr);
}

/// On Linux the check runs inside `corten-sandbox`: a dependency's build
/// script cannot write outside the target directory. The control shows plain
/// `cargo check` lets it.
#[cfg(target_os = "linux")]
#[test]
fn check_confines_dependency_build_scripts() {
    let fx = Fixture::new("check-sandbox", "fn main() {}\n").unwrap();
    let victim = std::env::temp_dir().join(format!("corten-victim-{}", process::id()));
    let _ignored = fs::remove_file(&victim);
    with_dependency(&fx, "hostile").unwrap();
    vendor_crate(
        &fx,
        "hostile",
        "build = \"build.rs\"\n",
        "pub fn noop() {}\n",
    )
    .unwrap();
    fx.write(
        "vendor/hostile/build.rs",
        &format!(
            "fn main() {{ std::fs::write({:?}, \"x\").expect(\"build script write\"); }}\n",
            victim.display().to_string()
        ),
    )
    .unwrap();

    let plain = plain_cargo_with_profile_flags(&fx).unwrap();
    assert_eq!(plain.code, Some(0), "control: {}", plain.stderr);
    assert!(victim.exists(), "control: the build script did not write");
    fs::remove_file(&victim).unwrap();
    fs::remove_dir_all(fx.target()).unwrap();

    let out = corten(&fx, &[]).unwrap();
    assert_ne!(out.code, Some(0), "{}", out.stderr);
    assert!(out.stderr.contains("build script write"), "{}", out.stderr);
    assert!(
        !victim.exists(),
        "the build script wrote outside the target"
    );
}

#[test]
fn usage_errors_exit_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-corten"))
        .args(["corten", "install"])
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
            "#!/bin/sh\nmkdir -p '{target}'\n: > '{marker}'\nfor a do\n  shift\n  case \"$a\" in -F|-Funsafe_code|unsafe_code) continue;; esac\n  set -- \"$@\" \"$a\"\ndone\nexec {exec_prefix} \"$@\"\n",
            target = fx.target().display(),
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
