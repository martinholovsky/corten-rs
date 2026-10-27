//! Phase 4 rejection tests: each `tests/phase4/*.rs` is checked as its own
//! crate depending on `corten-std`, with plain `cargo check`, which is what
//! the checker's first pass runs. A bad fixture must fail with its
//! `//@ expect:` text (so a failure for another reason does not count); a
//! `//@ good` fixture must pass.

use std::path::Path;
use std::process::Command;

#[test]
fn phase4_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = root.join("tests/phase4");
    let work = std::env::temp_dir().join(format!("corten-std-phase4-{}", std::process::id()));
    let target = work.join("target");
    let mut ran = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&fixtures)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let krate = work.join(&name);
        std::fs::create_dir_all(krate.join("src")).unwrap();
        std::fs::write(krate.join("src/main.rs"), &text).unwrap();
        std::fs::write(
            krate.join("Cargo.toml"),
            format!(
                "[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\ncorten-std = {{ path = {:?} }}\n",
                name.replace('_', "-"),
                root.display().to_string()
            ),
        )
        .unwrap();
        let out = Command::new(env!("CARGO"))
            .args(["check", "--quiet", "--offline", "--manifest-path"])
            .arg(krate.join("Cargo.toml"))
            .env("CARGO_TARGET_DIR", &target)
            .env_remove("CARGO_BUILD_WARNINGS")
            .env_remove("RUSTFLAGS")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        if text.lines().any(|l| l == "//@ good") {
            assert!(out.status.success(), "{name} should build:\n{stderr}");
        } else {
            assert!(!out.status.success(), "{name} should not build");
            for want in text.lines().filter_map(|l| l.strip_prefix("//@ expect: ")) {
                assert!(stderr.contains(want), "{name}: missing `{want}`:\n{stderr}");
            }
        }
        ran += 1;
    }
    let _cleanup = std::fs::remove_dir_all(&work);
    assert!(ran >= 14, "only {ran} fixtures ran");
}
