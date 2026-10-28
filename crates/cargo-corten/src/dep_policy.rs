//! The operator's dependency policy (layer 3; `docs/gates/phase-5.md`).
//!
//! Dependencies are refused unless the operator admits them. The policy is
//! an operator file (`--dep-policy` or `CORTEN_DEP_POLICY`), never read from
//! the checked repository:
//!
//! ```text
//! corten-dep-policy 1
//! # comments and blank lines are ignored
//! allow serde               admit a crate, any version
//! allow my-db@2.1.0         admit one version
//! ban my_db::query raw SQL string      refuse a raw entry point in local code
//! ban-type my_db::RawClient raw client refuse a type in local code
//! ```
//!
//! Admission does not exempt a crate from the other layer 3 checks. Each
//! `ban` joins the checker's `disallowed-methods` and each `ban-type` its
//! `disallowed-types`, which the profile forbids, so the operator closes the
//! raw entry points of the crates it admits. Parsing is strict: an unknown
//! directive, a malformed name or path, or a reason with characters that
//! could escape the generated configuration is an error, not a skipped line.

use std::collections::BTreeSet;
use std::fmt;

/// The header the file must start with.
pub const HEADER: &str = "corten-dep-policy 1";

/// Largest policy file read, in bytes.
pub const MAX_LEN: usize = 1024 * 1024;

/// Longest `ban` reason.
const MAX_REASON: usize = 200;

/// A parsed policy.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DepPolicy {
    /// Admitted crates: `NAME` or `NAME@VERSION`.
    pub allow: BTreeSet<String>,
    /// Banned functions and methods, with the reason.
    pub ban_methods: Vec<(String, String)>,
    /// Banned types, with the reason.
    pub ban_types: Vec<(String, String)>,
}

/// Why a policy was refused, with its 1-based line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    /// The line, or 0 for the whole file.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "dependency policy: {}", self.reason)
        } else {
            write!(f, "dependency policy line {}: {}", self.line, self.reason)
        }
    }
}

impl std::error::Error for PolicyError {}

/// A crate name as cargo accepts it: ASCII letters, digits, `-`, `_`.
fn crate_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A version: ASCII letters, digits, `.`, `-`, `+`.
fn version_ok(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// A Rust path of at least two identifier segments, `a::b`.
fn path_ok(path: &str) -> bool {
    let segments: Vec<&str> = path.split("::").collect();
    segments.len() >= 2
        && path.len() <= 256
        && segments.iter().all(|s| {
            let mut bytes = s.bytes();
            bytes
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

/// A reason: printable ASCII without `"` or `\`, so it cannot leave its
/// TOML string.
fn reason_ok(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAX_REASON
        && reason
            .bytes()
            .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

/// Parses a policy file.
///
/// # Errors
///
/// [`PolicyError`] for a missing header, an unknown directive, or a
/// malformed name, version, path or reason.
pub fn parse(text: &str) -> Result<DepPolicy, PolicyError> {
    let err = |line: usize, reason: String| PolicyError { line, reason };
    if text.len() > MAX_LEN {
        return Err(err(0, format!("larger than {MAX_LEN} bytes")));
    }
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i.saturating_add(1), l));
    match lines.next() {
        Some((_, first)) if first.trim_end() == HEADER => {}
        _ => return Err(err(1, format!("the first line must be `{HEADER}`"))),
    }
    let mut policy = DepPolicy::default();
    for (n, raw) in lines {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (directive, rest) = line.split_once(' ').unwrap_or((line, ""));
        let rest = rest.trim();
        match directive {
            "allow" => {
                let (name, version) = rest.split_once('@').unwrap_or((rest, ""));
                if !crate_name_ok(name) || (rest.contains('@') && !version_ok(version)) {
                    return Err(err(
                        n,
                        format!("`allow` needs NAME or NAME@VERSION, got {rest:?}"),
                    ));
                }
                policy.allow.insert(rest.to_owned());
            }
            "ban" | "ban-type" => {
                let (path, reason) = rest.split_once(' ').unwrap_or((rest, ""));
                let reason = reason.trim();
                if !path_ok(path) {
                    return Err(err(
                        n,
                        format!("`{directive}` needs a path like crate::item, got {path:?}"),
                    ));
                }
                if !reason_ok(reason) {
                    return Err(err(
                        n,
                        format!(
                            "`{directive}` needs a reason of printable ASCII without quotes or backslashes, at most {MAX_REASON} bytes"
                        ),
                    ));
                }
                let entry = (path.to_owned(), reason.to_owned());
                if directive == "ban" {
                    policy.ban_methods.push(entry);
                } else {
                    policy.ban_types.push(entry);
                }
            }
            other => return Err(err(n, format!("unknown directive {other:?}"))),
        }
    }
    Ok(policy)
}

impl DepPolicy {
    /// Whether a package is admitted.
    #[must_use]
    pub fn admits(&self, name: &str, version: &str) -> bool {
        self.allow.contains(name) || self.allow.contains(&format!("{name}@{version}"))
    }

    /// `base` (the checker's `clippy.toml`) with this policy's bans added to
    /// `disallowed-methods` and `disallowed-types`.
    ///
    /// # Panics
    ///
    /// Never for the checker's own template, which has both tables; a
    /// template without them is a build-time bug caught by the tests.
    #[must_use]
    pub fn clippy_toml(&self, base: &str) -> String {
        let entries = |list: &[(String, String)]| -> String {
            let mut out = String::new();
            for (path, reason) in list {
                out.push_str("    { path = \"");
                out.push_str(path);
                out.push_str("\", reason = \"operator dependency policy: ");
                out.push_str(reason);
                out.push_str("\" },\n");
            }
            out
        };
        let mut out = base.to_owned();
        for (table, list) in [
            ("disallowed-methods = [\n", &self.ban_methods),
            ("disallowed-types = [\n", &self.ban_types),
        ] {
            if let Some(at) = out.find(table) {
                out.insert_str(at.saturating_add(table.len()), &entries(list));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_policy() {
        let p = parse(
            "corten-dep-policy 1\n# admitted\nallow serde\nallow my-db@2.1.0\n\nban my_db::query raw SQL string\nban-type my_db::RawClient raw client\n",
        )
        .unwrap();
        assert!(p.admits("serde", "1.0.0"));
        assert!(p.admits("my-db", "2.1.0"));
        assert!(!p.admits("my-db", "2.2.0"));
        assert!(!p.admits("other", "1.0.0"));
        assert_eq!(
            p.ban_methods,
            [("my_db::query".to_owned(), "raw SQL string".to_owned())]
        );
        assert_eq!(p.ban_types.len(), 1);
    }

    #[test]
    fn refuses_what_it_does_not_understand() {
        for bad in [
            "",
            "allow serde\n",
            "corten-dep-policy 2\n",
            "corten-dep-policy 1\npermit serde\n",
            "corten-dep-policy 1\nallow ser de\n",
            "corten-dep-policy 1\nallow serde@\n",
            "corten-dep-policy 1\nban query raw\n",
            "corten-dep-policy 1\nban my_db::query\n",
            "corten-dep-policy 1\nban my_db::query a \"quoted\" reason\n",
            "corten-dep-policy 1\nban my_db::query back\\slash\n",
            "corten-dep-policy 1\nban my_db::9query reason\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// The shipped example must parse; a broken example is worse than none.
    #[test]
    fn the_example_policy_parses() {
        let text = include_str!("../../../docs/dep-policy.example");
        let p = parse(text).unwrap();
        assert!(p.allow.is_empty(), "the example admits nothing by itself");
        assert!(p.ban_methods.len() >= 10, "{}", p.ban_methods.len());
    }

    #[test]
    fn bans_join_the_clippy_tables() {
        let p =
            parse("corten-dep-policy 1\nban my_db::query raw SQL\nban-type my_db::Raw raw type\n")
                .unwrap();
        let toml = p.clippy_toml(crate::profile::CLIPPY_TOML);
        let methods = toml.find("disallowed-methods = [\n").unwrap();
        let types = toml.find("disallowed-types = [\n").unwrap();
        let m = toml.find("my_db::query").unwrap();
        let t = toml.find("my_db::Raw\"").unwrap();
        assert!(methods < m && m < types && types < t, "{toml}");
        // The checker's own entries are kept.
        assert!(toml.contains("std::process::Command::new"));
    }
}
