//! UI tests: each fixture in `tests/ui` names its lint, the messages it must
//! produce and how many; the driver compiles it with that lint forbidden.

use std::path::{Path, PathBuf};
use std::process::Command;

fn driver() -> Command {
    Command::new(env!("CARGO_BIN_EXE_corten-driver"))
}

fn out_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("corten-lints-ui-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Compiles `file` as a binary with `lint` forbidden; returns the exit code
/// and stderr.
fn check(file: &Path, lint: &str, externs: &[(&str, &Path)], dir: &Path) -> (i32, String) {
    let mut cmd = driver();
    cmd.args([
        "--edition",
        "2024",
        "--crate-type",
        "bin",
        "--emit=metadata",
        "-F",
        lint,
    ])
    .arg("-o")
    .arg(dir.join("out.rmeta"))
    .arg("-L")
    .arg(dir);
    for (name, path) in externs {
        cmd.arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let out = cmd.arg(file).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn header(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix(&format!("//@ {key}: ")))
        .map(str::to_owned)
        .collect()
}

#[test]
fn fixtures() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ui");
    let mut ran = 0;
    for entry in std::fs::read_dir(&ui).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let lint = header(&text, "lint").pop().expect("//@ lint:");
        let count: usize = header(&text, "count")
            .pop()
            .expect("//@ count:")
            .parse()
            .unwrap();
        let dir = out_dir(path.file_stem().unwrap().to_str().unwrap());
        let (code, stderr) = check(&path, &lint, &[], &dir);
        let errors = stderr
            .lines()
            .filter(|l| l.starts_with("error: ") && !l.starts_with("error: aborting"))
            .count();
        assert_eq!(
            errors,
            count,
            "{}: expected {count} errors\n{stderr}",
            path.display()
        );
        assert_eq!(
            code == 0,
            count == 0,
            "{}: exit {code}\n{stderr}",
            path.display()
        );
        for want in header(&text, "expect") {
            assert!(
                stderr.contains(&want),
                "{}: missing `{want}`\n{stderr}",
                path.display()
            );
        }
        ran += 1;
    }
    assert!(ran >= 6, "only {ran} fixtures ran");
}

/// Builds `tests/deps/{name}.rs` as an rlib with the driver; returns its path.
fn dep(name: &str, dir: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/deps/{name}.rs"));
    let rlib = dir.join(format!("lib{name}.rlib"));
    let out = driver()
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "rlib",
            "--crate-name",
            name,
        ])
        .arg("-o")
        .arg(&rlib)
        .arg(src)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    rlib
}

/// The Phase 1 bypass: `-F unsafe_code` does not see `unsafe` that a
/// dependency's macro expands into the crate (the control); the Corten lint
/// does.
#[test]
fn unsafe_from_a_dependency_macro() {
    let dir = out_dir("sneaky");
    let rlib = dep("sneaky", &dir);
    let main = dir.join("main.rs");
    std::fs::write(
        &main,
        "fn main() {\n    let x = 7u32;\n    println!(\"{}\", sneaky::sneak!(x));\n}\n",
    )
    .unwrap();

    let (code, stderr) = check(&main, "unsafe_code", &[("sneaky", &rlib)], &dir);
    assert_eq!(
        code, 0,
        "control: rustc's unsafe_code should miss it\n{stderr}"
    );

    let (code, stderr) = check(
        &main,
        "corten_unsafe_from_macro",
        &[("sneaky", &rlib)],
        &dir,
    );
    assert_ne!(code, 0, "{stderr}");
    assert!(
        stderr.contains("`unsafe` block expanded from macro `sneaky::sneak`"),
        "{stderr}"
    );
}

/// The Phase 2 gap: `from_template` called directly is refused; through the
/// crate's own macro it is not.
#[test]
fn direct_template_call() {
    let dir = out_dir("template");
    let rlib = dep("corten_std", &dir);
    let ext = [("corten_std", rlib.as_path())];

    let via_macro = dir.join("via_macro.rs");
    std::fs::write(
        &via_macro,
        "fn main() {\n    println!(\"{}\", corten_std::html!(\"<b>x</b>\").0);\n}\n",
    )
    .unwrap();
    let (code, stderr) = check(&via_macro, "corten_direct_template", &ext, &dir);
    assert_eq!(code, 0, "{stderr}");

    let direct = dir.join("direct.rs");
    std::fs::write(&direct, "fn main() {\n    println!(\"{}\", corten_std::html::Html::from_template(\"<a href=\\\"{}\\\">\").0);\n}\n").unwrap();
    let (code, stderr) = check(&direct, "corten_direct_template", &ext, &dir);
    assert_ne!(code, 0, "{stderr}");
    assert!(stderr.contains("called directly"), "{stderr}");
}

/// CWE-798 aid: a `Secret` from a literal or constant is refused; one from a
/// runtime value, including a value a loader computes from a literal name,
/// is not (the control).
#[test]
fn secret_from_a_literal() {
    let dir = out_dir("secret");
    let rlib = dep("corten_std", &dir);
    let ext = [("corten_std", rlib.as_path())];
    let bad = dir.join("bad.rs");
    std::fs::write(
        &bad,
        "use corten_std::secret::Secret;\nconst KEY: &str = \"k\";\nfn main() {\n    let _a = Secret::from_string(\"hunter2\".to_owned());\n    let _b = Secret::from_string(String::from(\"hunter2\"));\n    let _c = Secret::new(b\"key\".to_vec());\n    let _d = Secret::new(vec![1, 2, 3]);\n    let _e = Secret::from_string(KEY.to_string());\n}\n",
    )
    .unwrap();
    let (code, stderr) = check(&bad, "corten_secret_literal", &ext, &dir);
    assert_ne!(code, 0, "{stderr}");
    let n = stderr.matches("hard-coded credential").count();
    assert_eq!(n, 5, "{stderr}");

    let good = dir.join("good.rs");
    std::fs::write(
        &good,
        "use corten_std::secret::Secret;\nfn load(name: &str) -> String {\n    name.chars().rev().collect()\n}\nfn main() {\n    let input: String = std::iter::repeat('x').take(3).collect();\n    let _a = Secret::from_string(input);\n    let _b = Secret::from_string(load(\"API_KEY\"));\n}\n",
    )
    .unwrap();
    let (code, stderr) = check(&good, "corten_secret_literal", &ext, &dir);
    assert_eq!(code, 0, "{stderr}");
}
