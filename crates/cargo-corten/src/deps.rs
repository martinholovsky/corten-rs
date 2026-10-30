//! Layer 3: the dependency policy `cargo corten check` applies before it
//! builds (spec section 10; `docs/gates/phase-1.md` section 4).
//!
//! Registry and git dependencies are compiled with `--cap-lints allow`, so
//! the profile's lints never reach their code. Their macros reach the checked
//! crate anyway: a `macro_rules!` expansion lands in it, and rustc does not
//! report `unsafe_code` inside external macro expansions (measured); a
//! procedural macro can emit any code. The policy therefore looks at what
//! local code can reach and uses:
//!
//! - **Reachable** packages are the direct dependencies of local packages
//!   (workspace members and path dependencies), plus any package a reachable
//!   one re-exports (`pub use name` / `pub extern crate name`).
//! - A reachable package's **tainted** macros are its `#[macro_export]`
//!   `macro_rules!` whose body contains `unsafe`, or which invoke a tainted
//!   macro by name (`bitflags!` calls `__impl_bitflags!`).
//! - It is refused when local source mentions one of its tainted macros or,
//!   for a procedural-macro crate, one of its exported macro names. A mention
//!   is any identifier with that name: an invocation, a path, or a `use ... as`
//!   rename. Name collisions over-approximate toward refusal.
//! - Any package in the graph on [`BANNED`] is refused, as is any package the
//!   scan cannot read within its limits (fail closed).
//! - A reachable package the operator's dependency policy does not admit is
//!   refused (deny by default; [`crate::dep_policy`]). Admission does not
//!   skip the checks above. The prelude's own dependencies are exempt only
//!   when the local package is the checker's own `corten-std`, identified by
//!   its directory, never by its name: a repository can name a crate
//!   anything, and rustix's safe API would bypass every path claim.
//!
//! The operator accepts a package refused by one of the first three checks
//! by name (`--allow-dep` or `CORTEN_ALLOW_DEPS`); that does not admit it.
//! Nothing is read from the checked repository's configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::dep_policy::DepPolicy;
use crate::json::Json;

/// Crates refused by name, with the reason.
pub const BANNED: &[(&str, &str)] = &[
    ("fancy-regex", "backtracking regex engine (CWE-1333)"),
    ("pcre2", "backtracking regex engine (CWE-1333)"),
    ("pcre2-sys", "backtracking regex engine (CWE-1333)"),
    ("pcre", "backtracking regex engine (CWE-1333)"),
    ("onig", "backtracking regex engine (CWE-1333)"),
    ("onig_sys", "backtracking regex engine (CWE-1333)"),
    ("regress", "backtracking regex engine (CWE-1333)"),
    (
        "libxml",
        "XML parser with DTD and external entity processing (CWE-611, 776, 827)",
    ),
    (
        "libxml2-sys",
        "XML parser with DTD and external entity processing (CWE-611, 776, 827)",
    ),
];

/// Scan limits; a package beyond them is refused, not skipped.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest source file read.
    pub max_file_bytes: u64,
    /// Most source files read per package.
    pub max_files: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 4 * 1024 * 1024,
            max_files: 20_000,
        }
    }
}

/// One refused dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `name@version`.
    pub package: String,
    /// Why it was refused.
    pub reason: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.package, self.reason)
    }
}

/// `cargo metadata` output was not what the policy expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataError(pub &'static str);

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unexpected cargo metadata output: {}", self.0)
    }
}

impl std::error::Error for MetadataError {}

struct Package {
    id: String,
    name: String,
    version: String,
    local: bool,
    proc_macro: bool,
    root: PathBuf,
    /// Where this package's own targets live: a target's directory, or the
    /// file alone when it sits at the package root (`build.rs`). Nested
    /// packages and vendored copies under the root are not this package.
    sources: Vec<PathBuf>,
}

fn target_sources(pkg: &Json, root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for target in pkg.get("targets").and_then(Json::as_array).unwrap_or(&[]) {
        let Some(src) = target.get("src_path").and_then(Json::as_str) else {
            continue;
        };
        let src = Path::new(src);
        let dir = src.parent().unwrap_or(src);
        let entry = if dir == root {
            src.to_path_buf()
        } else {
            dir.to_path_buf()
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

fn packages(metadata: &Json) -> Result<Vec<Package>, MetadataError> {
    let list = metadata
        .get("packages")
        .and_then(Json::as_array)
        .ok_or(MetadataError("no packages array"))?;
    let mut out = Vec::with_capacity(list.len());
    for pkg in list {
        let text = |key: &'static str| pkg.get(key).and_then(Json::as_str);
        let manifest =
            text("manifest_path").ok_or(MetadataError("package without manifest_path"))?;
        let root = Path::new(manifest)
            .parent()
            .unwrap_or(Path::new(manifest))
            .to_path_buf();
        out.push(Package {
            id: text("id")
                .ok_or(MetadataError("package without id"))?
                .to_owned(),
            name: text("name")
                .ok_or(MetadataError("package without name"))?
                .to_owned(),
            version: text("version").unwrap_or("?").to_owned(),
            local: pkg.get("source").is_none_or(|s| *s == Json::Null),
            proc_macro: pkg
                .get("targets")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|t| t.get("kind").and_then(Json::as_array))
                .flatten()
                .any(|k| k.as_str() == Some("proc-macro")),
            sources: target_sources(pkg, &root),
            root,
        });
    }
    Ok(out)
}

/// `id -> [(dependency id, extern crate name)]` from the resolve graph.
fn resolve(metadata: &Json) -> Graph {
    let mut graph = BTreeMap::new();
    let nodes = metadata
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(Json::as_array)
        .unwrap_or(&[]);
    for node in nodes {
        let Some(id) = node.get("id").and_then(Json::as_str) else {
            continue;
        };
        let deps = node
            .get("deps")
            .and_then(Json::as_array)
            .unwrap_or(&[])
            .iter()
            .filter_map(|d| {
                Some((
                    d.get("pkg")?.as_str()?.to_owned(),
                    d.get("name")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        graph.insert(id.to_owned(), deps);
    }
    graph
}

/// What the policy needs from one package's sources.
#[derive(Debug, Default)]
struct Scan {
    /// Every identifier in the package's code (strings and comments removed).
    identifiers: BTreeSet<String>,
    /// Exported macros with `unsafe` in their body, closed over invocation.
    tainted: BTreeSet<String>,
    /// Names of procedural macros the package exports.
    proc_macros: BTreeSet<String>,
    /// Stripped source text, for the re-export search.
    text: String,
}

fn scan_package(roots: &[PathBuf], limits: Limits) -> Result<Scan, String> {
    let mut files = Vec::new();
    for root in roots {
        if root.is_file() {
            files.push(root.clone());
        } else {
            collect_rs(root, &mut files, limits)?;
        }
    }
    let mut scan = Scan::default();
    let mut macros = Vec::new();
    for file in files {
        let len = fs::metadata(&file)
            .map(|m| m.len())
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        if len > limits.max_file_bytes {
            return Err(format!("{} is larger than the scan limit", file.display()));
        }
        let text = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let stripped: String = strip(&text).into_iter().collect();
        scan.identifiers.extend(identifiers(&stripped));
        scan.proc_macros.extend(proc_macro_names(&stripped));
        macros.extend(exported_macros(&stripped));
        scan.text.push_str(&stripped);
        scan.text.push('\n');
    }
    scan.tainted = taint(&macros);
    Ok(scan)
}

type Graph = BTreeMap<String, Vec<(String, String)>>;

/// Reachable non-local packages, scanned: direct dependencies of local
/// packages, then whatever a reachable package re-exports, transitively.
fn reachable(
    pkgs: &[Package],
    graph: &Graph,
    by_id: &BTreeMap<&str, &Package>,
    limits: Limits,
) -> BTreeMap<String, Result<Scan, String>> {
    let mut queue: Vec<String> = pkgs
        .iter()
        .filter(|p| p.local)
        .flat_map(|p| graph.get(&p.id).into_iter().flatten())
        .map(|(dep, _)| dep.clone())
        .collect();
    let mut seen = BTreeSet::new();
    let mut scans = BTreeMap::new();
    while let Some(id) = queue.pop() {
        let Some(p) = by_id.get(id.as_str()) else {
            continue;
        };
        if p.local || !seen.insert(id.clone()) {
            continue;
        }
        // A dependency's whole directory: over-approximating its macros
        // only errs toward refusal.
        let scan = scan_package(std::slice::from_ref(&p.root), limits);
        if let Ok(found) = &scan {
            for (dep, extern_name) in graph.get(&id).into_iter().flatten() {
                if reexports(&found.text, extern_name) {
                    queue.push(dep.clone());
                }
            }
        }
        scans.insert(id, scan);
    }
    scans
}

/// Packages that local code other than the prelude can reach: direct
/// dependencies of local packages except the prelude, plus what a reachable
/// package re-exports. Uses the scans `reachable` already made.
fn admission_set(
    pkgs: &[Package],
    graph: &Graph,
    by_id: &BTreeMap<&str, &Package>,
    scans: &BTreeMap<String, Result<Scan, String>>,
    is_prelude: &dyn Fn(&Package) -> bool,
) -> BTreeSet<String> {
    let mut queue: Vec<String> = pkgs
        .iter()
        .filter(|p| p.local && !is_prelude(p))
        .flat_map(|p| graph.get(&p.id).into_iter().flatten())
        .map(|(dep, _)| dep.clone())
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(id) = queue.pop() {
        if by_id.get(id.as_str()).is_none_or(|p| p.local) || !seen.insert(id.clone()) {
            continue;
        }
        if let Some(Ok(found)) = scans.get(&id) {
            for (dep, extern_name) in graph.get(&id).into_iter().flatten() {
                if reexports(&found.text, extern_name) {
                    queue.push(dep.clone());
                }
            }
        }
    }
    seen
}

/// Applies the policy. See the module documentation.
///
/// # Errors
///
/// [`MetadataError`] if the metadata lacks the fields the policy reads.
pub fn audit(
    metadata: &Json,
    policy: &DepPolicy,
    prelude: Option<&Path>,
    allow: &BTreeSet<String>,
    limits: Limits,
) -> Result<Vec<Finding>, MetadataError> {
    let pkgs = packages(metadata)?;
    let graph = resolve(metadata);
    let by_id: BTreeMap<&str, &Package> = pkgs.iter().map(|p| (p.id.as_str(), p)).collect();
    let allowed = |p: &Package| {
        allow.contains(&p.name) || allow.contains(&format!("{}@{}", p.name, p.version))
    };
    let label = |p: &Package| format!("{}@{}", p.name, p.version);
    let mut findings = Vec::new();

    // Banned anywhere in the graph.
    for p in pkgs.iter().filter(|p| !p.local && !allowed(p)) {
        if let Some((_, why)) = BANNED.iter().find(|(banned, _)| *banned == p.name) {
            findings.push(Finding {
                package: label(p),
                reason: format!("banned: {why}"),
            });
        }
    }

    // Identifiers local code uses.
    let mut local_idents = BTreeSet::new();
    for p in pkgs.iter().filter(|p| p.local) {
        match scan_package(&p.sources, limits) {
            Ok(scan) => local_idents.extend(scan.identifiers),
            Err(why) => findings.push(Finding {
                package: label(p),
                reason: format!("local package cannot be scanned: {why}"),
            }),
        }
    }

    let scans = reachable(&pkgs, &graph, &by_id, limits);
    let prelude = prelude.and_then(|d| fs::canonicalize(d).ok());
    let is_prelude = |p: &Package| {
        p.local
            && prelude
                .as_ref()
                .is_some_and(|d| fs::canonicalize(&p.root).is_ok_and(|r| r == *d))
    };
    let must_admit = admission_set(&pkgs, &graph, &by_id, &scans, &is_prelude);

    for (id, scan) in &scans {
        let Some(p) = by_id.get(id.as_str()) else {
            continue;
        };
        if must_admit.contains(id) && !policy.admits(&p.name, &p.version) {
            findings.push(Finding {
                package: label(p),
                reason: "not on the operator's dependency allowlist (add `allow NAME` to the --dep-policy file after reviewing it)".to_owned(),
            });
        }
        if allowed(p) || BANNED.iter().any(|(b, _)| *b == p.name) {
            continue;
        }
        let scan = match scan {
            Ok(scan) => scan,
            Err(why) => {
                findings.push(Finding {
                    package: label(p),
                    reason: why.clone(),
                });
                continue;
            }
        };
        let used = |names: &BTreeSet<String>| -> Vec<String> {
            names
                .iter()
                .filter(|n| local_idents.contains(*n))
                .cloned()
                .collect()
        };
        if p.proc_macro {
            let hit = used(&scan.proc_macros);
            if !hit.is_empty() {
                findings.push(Finding {
                    package: label(p),
                    reason: format!(
                        "procedural macro used by local code ({}): its output cannot be checked before expansion",
                        hit.join(", ")
                    ),
                });
            }
            continue;
        }
        let hit = used(&scan.tainted);
        if !hit.is_empty() {
            findings.push(Finding {
                package: label(p),
                reason: format!(
                    "local code uses exported macros that expand to unsafe: {}",
                    hit.join(", ")
                ),
            });
        }
    }
    findings.sort_by(|a, b| a.package.cmp(&b.package));
    findings.dedup();
    Ok(findings)
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>, limits: Limits) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            // Code in these directories is never compiled into a dependent.
            if !matches!(
                name.to_str(),
                Some("target" | "tests" | "benches" | "examples" | ".git")
            ) {
                collect_rs(&path, out, limits)?;
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            if out.len() >= limits.max_files {
                return Err("too many source files to scan".to_owned());
            }
            out.push(path);
        }
    }
    Ok(())
}

/// Replaces comments, string literals and character literals with spaces,
/// keeping every other character (and every newline) in place.
#[expect(
    clippy::too_many_lines,
    reason = "one lexer loop; splitting it would scatter the cases of one state machine"
)]
fn strip(text: &str) -> Vec<char> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(c.len());
    let mut i = 0usize;
    let at = |k: usize| c.get(k).copied();
    let is_ident = |ch: Option<char>| ch.is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
    let blank = |out: &mut Vec<char>, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });
    while let Some(ch) = at(i) {
        let next = at(i.saturating_add(1));
        // Line comment.
        if ch == '/' && next == Some('/') {
            while let Some(x) = at(i) {
                if x == '\n' {
                    break;
                }
                blank(&mut out, x);
                i = i.saturating_add(1);
            }
            continue;
        }
        // Block comment, nested.
        if ch == '/' && next == Some('*') {
            let mut depth = 0usize;
            while let Some(x) = at(i) {
                let y = at(i.saturating_add(1));
                if x == '/' && y == Some('*') {
                    depth = depth.saturating_add(1);
                    blank(&mut out, x);
                    blank(&mut out, '*');
                    i = i.saturating_add(2);
                } else if x == '*' && y == Some('/') {
                    depth = depth.saturating_sub(1);
                    blank(&mut out, x);
                    blank(&mut out, '/');
                    i = i.saturating_add(2);
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, x);
                    i = i.saturating_add(1);
                }
            }
            continue;
        }
        // Raw string: r"..", r#".."#, br#".."#, cr"..".
        let raw_start = if ch == 'r' && !is_ident(i.checked_sub(1).and_then(at)) {
            Some(i)
        } else if matches!(ch, 'b' | 'c')
            && next == Some('r')
            && !is_ident(i.checked_sub(1).and_then(at))
        {
            Some(i.saturating_add(1))
        } else {
            None
        };
        if let Some(r) = raw_start {
            let mut k = r.saturating_add(1);
            let mut hashes = 0usize;
            while at(k) == Some('#') {
                hashes = hashes.saturating_add(1);
                k = k.saturating_add(1);
            }
            if at(k) == Some('"') {
                // Blank from i to the closing quote and hashes.
                let mut j = k.saturating_add(1);
                loop {
                    match at(j) {
                        None => break,
                        Some('"') => {
                            let closes = (1..=hashes).all(|h| at(j.saturating_add(h)) == Some('#'));
                            if closes {
                                j = j.saturating_add(hashes).saturating_add(1);
                                break;
                            }
                            j = j.saturating_add(1);
                        }
                        Some(_) => j = j.saturating_add(1),
                    }
                }
                while i < j {
                    blank(&mut out, at(i).unwrap_or(' '));
                    i = i.saturating_add(1);
                }
                continue;
            }
        }
        // Ordinary or byte/C string.
        if ch == '"' {
            blank(&mut out, ch);
            i = i.saturating_add(1);
            while let Some(x) = at(i) {
                blank(&mut out, x);
                i = i.saturating_add(1);
                if x == '\\' {
                    if let Some(y) = at(i) {
                        blank(&mut out, y);
                        i = i.saturating_add(1);
                    }
                } else if x == '"' {
                    break;
                }
            }
            continue;
        }
        // Character literal ('x', '\n', '\u{..}') versus lifetime ('a).
        if ch == '\'' {
            let is_char = next == Some('\\') || at(i.saturating_add(2)) == Some('\'');
            if is_char {
                blank(&mut out, ch);
                i = i.saturating_add(1);
                while let Some(x) = at(i) {
                    blank(&mut out, x);
                    i = i.saturating_add(1);
                    if x == '\\' {
                        if let Some(y) = at(i) {
                            blank(&mut out, y);
                            i = i.saturating_add(1);
                        }
                    } else if x == '\'' {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(ch);
        i = i.saturating_add(1);
    }
    out
}

fn closing(open: char) -> Option<char> {
    match open {
        '{' => Some('}'),
        '(' => Some(')'),
        '[' => Some(']'),
        _ => None,
    }
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// Every identifier in stripped source.
fn identifiers(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !is_ident_char(ch))
        .filter(|w| {
            w.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
        })
        .map(str::to_owned)
        .collect()
}

/// Whether stripped source re-exports the crate `name`
/// (`pub use name...` or `pub extern crate name`).
fn reexports(text: &str, name: &str) -> bool {
    let toks: Vec<&str> = text
        .split(|ch: char| !is_ident_char(ch))
        .filter(|w| !w.is_empty())
        .collect();
    toks.windows(3)
        .any(|w| matches!(w, ["pub", "use", n] if *n == name))
        || toks
            .windows(4)
            .any(|w| matches!(w, ["pub", "extern", "crate", n] if *n == name))
}

/// One `#[macro_export]` macro: its name, whether its body contains
/// `unsafe`, and the macro names its body invokes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportedMacro {
    name: String,
    has_unsafe: bool,
    invokes: BTreeSet<String>,
}

/// Exported macros whose body contains `unsafe` or invokes such a macro.
fn taint(macros: &[ExportedMacro]) -> BTreeSet<String> {
    let mut tainted: BTreeSet<String> = macros
        .iter()
        .filter(|m| m.has_unsafe)
        .map(|m| m.name.clone())
        .collect();
    loop {
        let before = tainted.len();
        for m in macros {
            if !tainted.contains(&m.name) && m.invokes.iter().any(|i| tainted.contains(i)) {
                tainted.insert(m.name.clone());
            }
        }
        if tainted.len() == before {
            return tainted;
        }
    }
}

/// Names of `#[macro_export]` `macro_rules!` macros whose body contains the
/// keyword `unsafe`, directly or by invoking another such macro in the same
/// source.
#[must_use]
pub fn scan_source(text: &str) -> Vec<String> {
    let stripped: String = strip(text).into_iter().collect();
    let macros = exported_macros(&stripped);
    let tainted = taint(&macros);
    macros
        .into_iter()
        .map(|m| m.name)
        .filter(|n| tainted.contains(n))
        .collect()
}

/// Procedural macros a crate exports: `#[proc_macro_derive(Name ...)]`, and
/// the function after `#[proc_macro]` or `#[proc_macro_attribute]`.
fn proc_macro_names(text: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (i, _) in text.match_indices("proc_macro_derive") {
        let rest = text
            .get(i.saturating_add("proc_macro_derive".len())..)
            .unwrap_or("");
        let rest = rest.trim_start().trim_start_matches('(').trim_start();
        let name: String = rest.chars().take_while(|c| is_ident_char(*c)).collect();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    for marker in ["#[proc_macro]", "#[proc_macro_attribute]"] {
        for (i, _) in text.match_indices(marker) {
            let rest = text.get(i.saturating_add(marker.len())..).unwrap_or("");
            if let Some(pos) = rest.find("fn ") {
                let name: String = rest
                    .get(pos.saturating_add(3)..)
                    .unwrap_or("")
                    .trim_start()
                    .chars()
                    .take_while(|c| is_ident_char(*c))
                    .collect();
                if !name.is_empty() {
                    names.insert(name);
                }
            }
        }
    }
    names
}

/// Every `#[macro_export]` `macro_rules!` in stripped source.
fn exported_macros(stripped: &str) -> Vec<ExportedMacro> {
    let src: Vec<char> = stripped.chars().collect();
    let at = |k: usize| src.get(k).copied();
    let is_ident = |ch: Option<char>| ch.is_some_and(is_ident_char);
    let word_at = |k: usize, w: &str| -> bool {
        let n = w.chars().count();
        w.chars()
            .enumerate()
            .all(|(o, wc)| at(k.saturating_add(o)) == Some(wc))
            && !is_ident(k.checked_sub(1).and_then(at))
            && !is_ident(at(k.saturating_add(n)))
    };
    let mut found = Vec::new();
    let mut i = 0usize;
    while i < src.len() {
        if !word_at(i, "macro_rules") {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        let mut k = i.saturating_add("macro_rules".len());
        while at(k).is_some_and(char::is_whitespace) {
            k = k.saturating_add(1);
        }
        if at(k) != Some('!') {
            i = k;
            continue;
        }
        k = k.saturating_add(1);
        while at(k).is_some_and(char::is_whitespace) {
            k = k.saturating_add(1);
        }
        let name_start = k;
        while is_ident(at(k)) {
            k = k.saturating_add(1);
        }
        let name: String = src.get(name_start..k).unwrap_or(&[]).iter().collect();
        while at(k).is_some_and(char::is_whitespace) {
            k = k.saturating_add(1);
        }
        let Some(close) = at(k).and_then(closing) else {
            i = k;
            continue;
        };
        let open = at(k).unwrap_or('{');
        let body_start = k;
        let mut depth = 0usize;
        let mut end = k;
        while let Some(x) = at(end) {
            if x == open {
                depth = depth.saturating_add(1);
            } else if x == close {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            end = end.saturating_add(1);
        }
        if exported(&src, start) {
            let body: String = src.get(body_start..end).unwrap_or(&[]).iter().collect();
            let has_unsafe = (body_start..end).any(|p| word_at(p, "unsafe"));
            // Macro invocations in the body: an identifier followed by `!`.
            let bytes: Vec<char> = body.chars().collect();
            let mut invokes = BTreeSet::new();
            for (bang, ch) in bytes.iter().enumerate() {
                if *ch != '!' {
                    continue;
                }
                let mut from = bang;
                while from > 0
                    && bytes
                        .get(from.saturating_sub(1))
                        .copied()
                        .is_some_and(is_ident_char)
                {
                    from = from.saturating_sub(1);
                }
                let ident: String = bytes.get(from..bang).unwrap_or(&[]).iter().collect();
                if !ident.is_empty() {
                    invokes.insert(ident);
                }
            }
            found.push(ExportedMacro {
                name,
                has_unsafe,
                invokes,
            });
        }
        i = end.saturating_add(1);
    }
    found
}

/// Whether the attributes directly before `pos` include `macro_export`.
fn exported(c: &[char], pos: usize) -> bool {
    let mut k = pos;
    loop {
        while k > 0
            && c.get(k.saturating_sub(1))
                .is_some_and(|ch| ch.is_whitespace())
        {
            k = k.saturating_sub(1);
        }
        if k == 0 || c.get(k.saturating_sub(1)) != Some(&']') {
            return false;
        }
        // Walk back to the matching '['.
        let end = k.saturating_sub(1);
        let mut depth = 0usize;
        let mut j = end;
        loop {
            match c.get(j) {
                Some(']') => depth = depth.saturating_add(1),
                Some('[') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                None => return false,
                _ => {}
            }
            if j == 0 {
                return false;
            }
            j = j.saturating_sub(1);
        }
        if j == 0 || c.get(j.saturating_sub(1)) != Some(&'#') {
            return false;
        }
        let attr: String = c.get(j..=end).unwrap_or(&[]).iter().collect();
        if attr.contains("macro_export") {
            return true;
        }
        k = j.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exported_unsafe_macros_only() {
        let src = r##"
            /// Reads a raw pointer.
            #[macro_export]
            #[doc(hidden)]
            macro_rules! read_raw { ($p:expr) => { unsafe { *$p } }; }

            macro_rules! internal { () => { unsafe { 0 } }; }

            #[macro_export]
            macro_rules! safe_one { () => { "unsafe in a string" }; }

            #[cfg_attr(feature = "x", macro_export)]
            macro_rules! cfg_exported ( () => ( unsafe { 1 } ) );

            #[macro_export]
            macro_rules! commented { () => { /* unsafe */ 1 // unsafe
            }; }

            #[macro_export]
            macro_rules! raw_string { () => { r#"unsafe"# }; }

            #[macro_export]
            macro_rules! lifetimes { ($x:lifetime) => { fn f<'a>(_: &'a u8) { let _c = '}'; unsafe {} } }; }
        "##;
        assert_eq!(scan_source(src), ["read_raw", "cfg_exported", "lifetimes"]);
    }

    #[test]
    fn unsafe_must_be_a_whole_word() {
        let src = "#[macro_export]\nmacro_rules! m { () => { not_unsafe_at_all() }; }";
        assert_eq!(scan_source(src), Vec::<String>::new());
    }

    #[test]
    fn taint_follows_invocations() {
        let src = "#[macro_export]\nmacro_rules! outer { () => { $crate::inner!() }; }\n#[macro_export]\nmacro_rules! inner { () => { unsafe { 0 } }; }\n#[macro_export]\nmacro_rules! clean { () => { 1 }; }";
        assert_eq!(scan_source(src), ["outer", "inner"]);
    }

    #[test]
    fn reexport_detection() {
        assert!(reexports(
            "pub use serde_derive :: { Serialize } ;",
            "serde_derive"
        ));
        assert!(reexports("pub extern crate evil ;", "evil"));
        assert!(!reexports("pub extern crate other ;", "evil"));
        assert!(!reexports("use evil :: x ;", "evil"));
    }

    /// A temporary package tree for the policy tests.
    struct Tree(PathBuf);
    impl Tree {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("corten-deps-{}-{name}", std::process::id()));
            let _ignored = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn package(&self, name: &str, lib: &str) -> String {
            let root = self.0.join(name);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), lib).unwrap();
            root.join("Cargo.toml").display().to_string()
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    fn pkg(id: &str, local: bool, proc_macro: bool, manifest: &str) -> String {
        let source = if local {
            "null".to_owned()
        } else {
            "\"registry+x\"".to_owned()
        };
        let kind = if proc_macro { "proc-macro" } else { "lib" };
        let src = Path::new(manifest)
            .with_file_name("src")
            .join("lib.rs")
            .display()
            .to_string();
        format!(
            r#"{{"id":"{id}","name":"{id}","version":"1.0.0","source":{source},"targets":[{{"kind":["{kind}"],"src_path":{src:?}}}],"manifest_path":{manifest:?}}}"#
        )
    }

    fn metadata(pkgs: &[String], edges: &[(&str, &str)]) -> Json {
        let ids: BTreeSet<&str> = edges.iter().flat_map(|(a, b)| [*a, *b]).collect();
        let nodes: Vec<String> = ids
            .iter()
            .map(|id| {
                let deps: Vec<String> = edges
                    .iter()
                    .filter(|(a, _)| a == id)
                    .map(|(_, b)| format!(r#"{{"pkg":"{b}","name":"{}"}}"#, b.replace('-', "_")))
                    .collect();
                format!(r#"{{"id":"{id}","deps":[{}]}}"#, deps.join(","))
            })
            .collect();
        Json::parse(&format!(
            r#"{{"packages":[{}],"resolve":{{"nodes":[{}]}}}}"#,
            pkgs.join(","),
            nodes.join(",")
        ))
        .unwrap()
    }

    /// A policy admitting every package name the tests use, so each test
    /// sees only the check it is about.
    fn admit_all() -> DepPolicy {
        crate::dep_policy::parse(
            "corten-dep-policy 1\nallow evil\nallow mid\nallow derive\nallow fancy-regex\nallow ghost\n",
        )
        .unwrap()
    }

    #[test]
    fn unadmitted_dependencies_are_refused_and_admission_skips_no_check() {
        let t = Tree::new("admit");
        let app = pkg(
            "app",
            true,
            false,
            &t.package("app", "fn f(p: *const u8) -> u8 { evil::read_raw!(p) }"),
        );
        let evil = pkg("evil", false, false, &t.package("evil", UNSAFE_MACRO));
        let tidy = pkg("tidy", false, false, &t.package("tidy", "pub fn x() {}"));
        let m = metadata(&[app, evil, tidy], &[("app", "evil"), ("app", "tidy")]);
        let none = DepPolicy::default();
        let f = audit(&m, &none, None, &BTreeSet::new(), Limits::default()).unwrap();
        let unadmitted = f.iter().filter(|x| x.reason.contains("allowlist")).count();
        assert_eq!(unadmitted, 2, "{f:?}");
        // Admitted, evil is still refused for its unsafe macro; tidy passes.
        let some =
            crate::dep_policy::parse("corten-dep-policy 1\nallow evil\nallow tidy\n").unwrap();
        let f = audit(&m, &some, None, &BTreeSet::new(), Limits::default()).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].reason.contains("read_raw"), "{f:?}");
        // --allow-dep overrides the macro finding but does not admit.
        let over: BTreeSet<String> = ["evil".to_owned(), "tidy".to_owned()].into();
        let f = audit(&m, &none, None, &over, Limits::default()).unwrap();
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.reason.contains("allowlist")), "{f:?}");
    }

    /// The prelude's dependencies need no admission, but only for the
    /// prelude at the checker's own path; a local crate that merely takes its
    /// name does not get the exemption.
    #[test]
    fn prelude_dependencies_are_exempt_only_at_the_prelude_path() {
        let t = Tree::new("prelude");
        let app = pkg("app", true, false, &t.package("app", "fn f() {}"));
        let prelude_manifest = t.package("corten-std", "pub fn p() {}");
        let prelude = pkg("corten-std", true, false, &prelude_manifest);
        let rustix = pkg(
            "rustix",
            false,
            false,
            &t.package("rustix", "pub fn raw() {}"),
        );
        let m = metadata(
            &[app, prelude, rustix],
            &[("app", "corten-std"), ("corten-std", "rustix")],
        );
        let none = DepPolicy::default();
        let dir = Path::new(&prelude_manifest).parent().unwrap();
        assert_eq!(
            audit(&m, &none, Some(dir), &BTreeSet::new(), Limits::default()).unwrap(),
            Vec::new()
        );
        // Elsewhere, the same name is just another local crate.
        let f = audit(
            &m,
            &none,
            Some(Path::new("/nonexistent/corten-std")),
            &BTreeSet::new(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].reason.contains("allowlist"), "{f:?}");
    }

    const UNSAFE_MACRO: &str =
        "#[macro_export]\nmacro_rules! read_raw { ($p:expr) => { unsafe { *$p } }; }\n";

    #[test]
    fn refused_only_when_local_code_uses_the_macro() {
        let t = Tree::new("uses");
        let app_uses = pkg(
            "app",
            true,
            false,
            &t.package("app", "fn f(p: *const u8) -> u8 { evil::read_raw!(p) }"),
        );
        let evil = pkg("evil", false, false, &t.package("evil", UNSAFE_MACRO));
        let m = metadata(&[app_uses, evil.clone()], &[("app", "evil")]);
        let f = audit(&m, &admit_all(), None, &BTreeSet::new(), Limits::default()).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].reason.contains("read_raw"));

        let t2 = Tree::new("unused");
        let app_clean = pkg("app", true, false, &t2.package("app", "fn f() -> u8 { 1 }"));
        let evil2 = pkg("evil", false, false, &t2.package("evil", UNSAFE_MACRO));
        let m2 = metadata(&[app_clean, evil2], &[("app", "evil")]);
        assert_eq!(
            audit(&m2, &admit_all(), None, &BTreeSet::new(), Limits::default()).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn rename_counts_as_use_and_transitive_needs_a_reexport() {
        let t = Tree::new("rename");
        let app = pkg(
            "app",
            true,
            false,
            &t.package(
                "app",
                "use evil::read_raw as r;\nfn f(p: *const u8) -> u8 { r!(p) }",
            ),
        );
        let mid = pkg("mid", false, false, &t.package("mid", "pub fn x() {}"));
        let evil = pkg("evil", false, false, &t.package("evil", UNSAFE_MACRO));
        // evil reached only through mid, which does not re-export it.
        let m = metadata(
            &[app.clone(), mid, evil.clone()],
            &[("app", "mid"), ("mid", "evil")],
        );
        assert_eq!(
            audit(&m, &admit_all(), None, &BTreeSet::new(), Limits::default()).unwrap(),
            Vec::new()
        );
        // Now mid re-exports it.
        let mid2 = pkg(
            "mid",
            false,
            false,
            &t.package("mid", "pub use evil::read_raw;"),
        );
        let m2 = metadata(&[app, mid2, evil], &[("app", "mid"), ("mid", "evil")]);
        let f = audit(&m2, &admit_all(), None, &BTreeSet::new(), Limits::default()).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
    }

    #[test]
    fn proc_macros_bans_and_allow() {
        let t = Tree::new("pm");
        let app = pkg(
            "app",
            true,
            false,
            &t.package("app", "#[derive(Serialize)] struct S;"),
        );
        let derive = pkg(
            "derive",
            false,
            true,
            &t.package("derive", "#[proc_macro_derive(Serialize, attributes(serde))]\npub fn s(i: TokenStream) -> TokenStream { i }"),
        );
        let banned = pkg(
            "fancy-regex",
            false,
            false,
            &t.package("fancy-regex", "pub fn x() {}"),
        );
        let m = metadata(
            &[app, derive, banned],
            &[("app", "derive"), ("app", "fancy-regex")],
        );
        let f = audit(&m, &admit_all(), None, &BTreeSet::new(), Limits::default()).unwrap();
        assert_eq!(f.len(), 2, "{f:?}");
        let allow: BTreeSet<String> = ["derive".to_owned(), "fancy-regex@1.0.0".to_owned()].into();
        assert_eq!(
            audit(&m, &admit_all(), None, &allow, Limits::default()).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn unreadable_reachable_package_fails_closed() {
        let t = Tree::new("ghost");
        let app = pkg("app", true, false, &t.package("app", "fn f() {}"));
        let ghost = pkg(
            "ghost",
            false,
            false,
            "/nonexistent/corten/ghost/Cargo.toml",
        );
        let m = metadata(&[app, ghost], &[("app", "ghost")]);
        let f = audit(&m, &admit_all(), None, &BTreeSet::new(), Limits::default()).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].reason.contains("cannot list"));
    }
}
