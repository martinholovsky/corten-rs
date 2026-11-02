//! The prelude's surface toward its dependencies (spec section 8, question
//! 20). Layer 3 does not walk `corten-std`'s own dependencies when it looks
//! for macros program code can reach (`src/deps.rs`, `reachable`). That is
//! sound only while `corten-std`:
//!
//! 1. re-exports no third-party dependency (`pub use dep`, `pub extern crate
//!    dep`), so program code cannot reach one through the prelude; and
//! 2. invokes no third-party macro: no `dep::name!`, no `#[dep::attr]`, no
//!    derive outside the standard set, and no bare `name!` that is neither a
//!    standard macro nor one of `corten-std`'s own `macro_rules!`. rustc does
//!    not report `unsafe` produced by an external macro (docs/gates/phase-1.md),
//!    so this keeps the prelude's own profile honest.
//!
//! The rules are checked on known-bad snippets first, so a scanner that
//! matched nothing would fail here rather than pass.

#![expect(
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    reason = "a test-only scanner over the repository's own ASCII source; a panic fails the test"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const STD_DERIVES: &[&str] = &[
    "Debug",
    "Clone",
    "Copy",
    "PartialEq",
    "Eq",
    "Hash",
    "Default",
    "PartialOrd",
    "Ord",
];

const STD_MACROS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "cfg",
    "column",
    "compile_error",
    "concat",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "env",
    "eprint",
    "eprintln",
    "file",
    "format",
    "format_args",
    "include",
    "include_bytes",
    "include_str",
    "line",
    "macro_rules",
    "matches",
    "module_path",
    "option_env",
    "panic",
    "print",
    "println",
    "stringify",
    "thread_local",
    "todo",
    "unimplemented",
    "unreachable",
    "vec",
    "write",
    "writeln",
];

/// Third-party dependency names of a `Cargo.toml` (normal and target
/// dependencies, not dev-dependencies), with `-` written as `_`.
fn dependencies(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_deps = line == "[dependencies]"
                || (line.starts_with("[target.") && line.ends_with(".dependencies]"));
            continue;
        }
        if in_deps
            && let Some((name, _)) = line.split_once(" = ")
            && !name.starts_with('#')
        {
            out.insert(name.trim().replace('-', "_"));
        }
    }
    out
}

/// Identifiers made of `[A-Za-z0-9_]` that end right before `at` in `text`.
fn ident_before(text: &str, at: usize) -> &str {
    let head = &text[..at];
    let start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |i| i + 1);
    &head[start..]
}

/// Every violation of rules 1 and 2 in `source`, given the prelude's own
/// macro names and its dependencies.
fn violations(source: &str, own_macros: &BTreeSet<String>, deps: &BTreeSet<String>) -> Vec<String> {
    let mut found = Vec::new();
    for dep in deps {
        for prefix in ["pub use ", "pub extern crate ", "pub use ::"] {
            let needle = format!("{prefix}{dep}");
            if source.match_indices(&needle).any(|(i, _)| {
                source[i + needle.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            }) {
                found.push(format!("re-exports {dep}"));
            }
        }
        if source.contains(&format!("#[{dep}::")) {
            found.push(format!("uses an attribute from {dep}"));
        }
    }
    for (i, _) in source.match_indices('!') {
        let next = source[i + 1..].chars().next();
        if !matches!(next, Some('(' | '[' | '{')) {
            continue;
        }
        let name = ident_before(source, i);
        if name.is_empty() {
            continue;
        }
        let before = &source[..i - name.len()];
        let path = if before.ends_with("::") {
            ident_before(before, before.len() - 2)
        } else {
            ""
        };
        let ok = match path {
            "" => STD_MACROS.contains(&name) || own_macros.contains(name),
            "std" | "core" | "alloc" => true,
            "crate" | "corten_std" | "self" | "super" => own_macros.contains(name),
            other => !deps.contains(other) && own_macros.contains(name),
        };
        if !ok {
            found.push(format!(
                "invokes {path}{}{name}!",
                if path.is_empty() { "" } else { "::" }
            ));
        }
    }
    for (i, _) in source.match_indices("#[derive(") {
        let rest = &source[i + "#[derive(".len()..];
        let Some(end) = rest.find(")]") else { continue };
        for derive in rest[..end].split(',') {
            let derive = derive.trim();
            if !derive.is_empty() && !STD_DERIVES.contains(&derive) {
                found.push(format!("derives {derive}"));
            }
        }
    }
    found
}

/// Names of every `macro_rules!` in `source`.
fn own_macros(source: &str) -> BTreeSet<String> {
    source
        .match_indices("macro_rules!")
        .filter_map(|(i, m)| {
            let rest = source[i + m.len()..].trim_start();
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
            Some(rest[..end].to_owned())
        })
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn the_rules_catch_each_known_bad() {
    let deps: BTreeSet<String> = ["tokio".to_owned(), "rustls".to_owned()].into();
    let own: BTreeSet<String> = ["sql".to_owned()].into();
    for (bad, why) in [
        ("pub use tokio;", "re-exports tokio"),
        ("pub use tokio::runtime;", "re-exports tokio"),
        ("pub extern crate rustls;", "re-exports rustls"),
        (
            "#[tokio::main]\nfn main() {}",
            "uses an attribute from tokio",
        ),
        ("fn f() { tokio::select!{} }", "invokes tokio::select!"),
        ("fn f() { join!(a) }", "invokes join!"),
        ("#[derive(Debug, Zeroize)]\nstruct S;", "derives Zeroize"),
    ] {
        let v = violations(bad, &own, &deps);
        assert!(v.iter().any(|x| x == why), "{bad:?}: {v:?}");
    }
    for good in [
        "use tokio::runtime::Builder;",
        "fn f() { vec![1]; format!(\"x\"); crate::sql!(\"q\"); corten_std::sql!(\"q\"); }",
        "#[derive(Debug, Clone, PartialEq)]\nstruct S;",
        "fn f(a: bool) -> bool { a != !a }",
        "#[test]\nfn main() {}",
        "pub use tokio_like_name_of_mine::x;",
    ] {
        assert_eq!(
            violations(good, &own, &deps),
            Vec::<String>::new(),
            "{good:?}"
        );
    }
}

#[test]
fn the_prelude_reexports_no_dependency_and_invokes_no_dependency_macro() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../corten-std");
    let deps = dependencies(&fs::read_to_string(root.join("Cargo.toml")).unwrap());
    assert!(
        deps.contains("rustls") && deps.contains("hickory_resolver"),
        "dependency list: {deps:?}"
    );
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files).unwrap();
    assert!(files.len() >= 20, "read only {} files", files.len());
    let sources: Vec<(PathBuf, String)> = files
        .into_iter()
        .map(|f| {
            let s = fs::read_to_string(&f).unwrap();
            (f, s)
        })
        .collect();
    let own: BTreeSet<String> = sources.iter().flat_map(|(_, s)| own_macros(s)).collect();
    assert!(
        own.contains("sql") && own.contains("log_record"),
        "own macros: {own:?}"
    );
    let mut all = Vec::new();
    for (file, source) in &sources {
        for v in violations(source, &own, &deps) {
            all.push(format!("{}: {v}", file.display()));
        }
    }
    assert_eq!(all, Vec::<String>::new(), "read {} files", sources.len());
}
