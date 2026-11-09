//! Errors that teach: for every lint the profile forbids, the weakness it
//! guards against and the fix. After a refused check the checker prints the
//! entry for each lint whose `-F` note appeared in the compiler's output.
//!
//! The CWE ids come from the ledger (`ledger/cwe-ledger.csv`) and the
//! comments in [`crate::profile`]; a lint with no ledger row says so.

use std::collections::BTreeSet;

/// What one forbidden lint guards against, and how to satisfy it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Explanation {
    /// The lint as the profile names it (`clippy::as_conversions`).
    pub lint: &'static str,
    /// The weakness, with its CWE ids.
    pub why: &'static str,
    /// The fix.
    pub fix: &'static str,
}

const fn e(lint: &'static str, why: &'static str, fix: &'static str) -> Explanation {
    Explanation { lint, why, fix }
}

const BANNED: &str = "the reason printed with each call names the weakness and the fix";

/// One entry per forbidden lint; a test keeps it complete.
pub const EXPLANATIONS: &[Explanation] = &[
    e(
        "unsafe_code",
        "memory corruption (CWE-787, CWE-416, CWE-125): no `unsafe` in application crates (spec section 8, question 9)",
        "use a safe API from std, corten-std, or a crate the dependency policy admits",
    ),
    e(
        "unused_must_use",
        "an ignored result or status (CWE-252)",
        "handle it: `?`, `match`, or `if let Err(e) = ...`",
    ),
    e(
        "dead_code",
        "dead code (CWE-561)",
        "remove the unused item, or use it",
    ),
    e(
        "deprecated",
        "use of an obsolete function (CWE-477)",
        "use the replacement the deprecation note names",
    ),
    e(
        "clippy::disallowed_methods",
        "ambient authority or an unsafe default (spec 4.3)",
        BANNED,
    ),
    e(
        "clippy::disallowed_types",
        "ambient authority or an unsafe default (spec 4.3)",
        BANNED,
    ),
    e(
        "clippy::arithmetic_side_effects",
        "integer overflow or wraparound (CWE-190, CWE-191)",
        "`checked_add` and the other `checked_*` methods with `?`; `saturating_*` or `wrapping_*` where that is the intent",
    ),
    e(
        "clippy::as_conversions",
        "an incorrect type conversion (CWE-704)",
        "`From` or `TryFrom`: `u64::from(x)`, `u8::try_from(x)?`",
    ),
    e(
        "clippy::let_underscore_must_use",
        "an ignored result or status (CWE-252)",
        "bind the value and handle it",
    ),
    e(
        "clippy::mem_forget",
        "a skipped destructor (CWE-1091)",
        "let the value drop at the end of its owner",
    ),
    e(
        "clippy::precedence",
        "an operator precedence error (CWE-783)",
        "add parentheses",
    ),
    e(
        "clippy::float_cmp",
        "exact floating-point comparison (CWE-1077)",
        "compare within a tolerance",
    ),
    e(
        "clippy::float_cmp_const",
        "exact floating-point comparison (CWE-1077)",
        "compare within a tolerance",
    ),
    e(
        "clippy::dbg_macro",
        "active debug code (CWE-489)",
        "remove the `dbg!`",
    ),
    e(
        "clippy::todo",
        "placeholder code (CWE-489)",
        "implement it, or return an error",
    ),
    e(
        "clippy::unimplemented",
        "placeholder code (CWE-489)",
        "implement it, or return an error",
    ),
    e(
        "clippy::eq_op",
        "a condition that is always true or false (CWE-570, CWE-571)",
        "fix the condition",
    ),
    e(
        "clippy::absurd_extreme_comparisons",
        "a condition that is always true or false (CWE-570, CWE-571)",
        "fix the condition",
    ),
    e(
        "clippy::impossible_comparisons",
        "a condition that is always true or false (CWE-570, CWE-571)",
        "fix the condition",
    ),
    e(
        "clippy::redundant_comparisons",
        "a condition that is always true or false (CWE-570, CWE-571)",
        "fix the condition",
    ),
    e(
        "clippy::overly_complex_bool_expr",
        "a condition that is always true or false (CWE-570, CWE-571)",
        "simplify the condition",
    ),
    e(
        "clippy::nonminimal_bool",
        "a condition that is always true or false (CWE-570, CWE-571)",
        "simplify the condition",
    ),
    e(
        "clippy::short_circuit_statement",
        "a short-circuit operator used as control flow (CWE-768)",
        "use `if`",
    ),
    e(
        "corten_must_use_return",
        "an ignored return value (CWE-252)",
        "use or handle the value the function returns",
    ),
    e(
        "corten_labelled_params",
        "arguments passed in the wrong order (CWE-683)",
        "give the same-typed parameters distinct newtypes, or take a struct",
    ),
    e(
        "corten_pub_interior_mut_static",
        "a public mutable static (CWE-493, CWE-500, CWE-607)",
        "make the static non-public, or immutable",
    ),
    e(
        "corten_unsafe_from_macro",
        "`unsafe` reaching the crate through a dependency's macro (the no-`unsafe` rule; no ledger row of its own)",
        "use the crate's safe API, or a macro that expands to no `unsafe`",
    ),
    e(
        "corten_direct_template",
        "an unchecked template for an injection sink (CWE-79, CWE-89)",
        "use the sink's macro (`html!`, `sql!`, ...), which checks the template",
    ),
    e(
        "corten_blocking_in_async",
        "blocking code in an async body (CWE-1322)",
        "use the async API, or move the call to a blocking thread",
    ),
    e(
        "corten_rc_cycle",
        "a reference cycle that skips a destructor (CWE-1091)",
        "hold back references as `Weak`",
    ),
    e(
        "corten_secret_literal",
        "a hard-coded credential (CWE-798)",
        "load the secret at run time, from a file the manifest grants",
    ),
];

/// The entry for a lint as rustc prints it in a `-F` note, with dashes
/// (`clippy::as-conversions`).
#[must_use]
pub fn lookup(printed: &str) -> Option<&'static Explanation> {
    let lint = printed.replace('-', "_");
    EXPLANATIONS.iter().find(|x| x.lint == lint)
}

/// Removes ANSI escape sequences (`ESC [ ... letter`), so a coloured note
/// matches too.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The forbidden lint a compiler output line names in its note
/// "requested on the command line with `-F <lint>`", if any.
#[must_use]
pub fn forbidden_lint_in(line: &str) -> Option<&'static Explanation> {
    const NOTE: &str = "requested on the command line with `-F ";
    let line = strip_ansi(line);
    let (_, rest) = line.split_once(NOTE)?;
    let (printed, _) = rest.split_once('`')?;
    lookup(printed)
}

/// The text printed after a refused check, one block per lint seen.
#[must_use]
pub fn render(seen: &BTreeSet<&'static Explanation>) -> String {
    let mut out = String::from("\nWhy the profile refused this, and how to fix it:\n");
    for x in seen {
        for part in [
            "  ",
            &x.lint.replace('_', "-"),
            ": ",
            x.why,
            ".\n    fix: ",
            x.fix,
            "\n",
        ] {
            out.push_str(part);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;

    #[test]
    fn every_forbidden_lint_has_an_explanation() {
        for lint in profile::FORBIDDEN_RUSTC_LINTS
            .iter()
            .chain(profile::FORBIDDEN_CLIPPY_LINTS)
            .chain(profile::FORBIDDEN_CORTEN_LINTS)
        {
            assert!(
                EXPLANATIONS.iter().any(|x| x.lint == *lint),
                "{lint} has no explanation"
            );
        }
    }

    #[test]
    fn every_explanation_names_a_forbidden_lint() {
        for x in EXPLANATIONS {
            assert!(
                profile::FORBIDDEN_RUSTC_LINTS
                    .iter()
                    .chain(profile::FORBIDDEN_CLIPPY_LINTS)
                    .chain(profile::FORBIDDEN_CORTEN_LINTS)
                    .any(|l| *l == x.lint),
                "{} is not forbidden",
                x.lint
            );
        }
    }

    #[test]
    fn notes_name_their_lint_plain_and_coloured() {
        // Lines as rustc 1.99.1, Clippy and corten-driver print them.
        for (line, lint) in [
            (
                "  = note: requested on the command line with `-F unsafe-code`",
                "unsafe_code",
            ),
            (
                "  = note: requested on the command line with `-F clippy::arithmetic-side-effects`",
                "clippy::arithmetic_side_effects",
            ),
            (
                "  = note: requested on the command line with `-F corten-must-use-return`",
                "corten_must_use_return",
            ),
            (
                "  \u{1b}[1m\u{1b}[94m= \u{1b}[0m\u{1b}[1mnote\u{1b}[0m: requested on the command line with `-F clippy::as-conversions`",
                "clippy::as_conversions",
            ),
        ] {
            assert_eq!(
                forbidden_lint_in(line).map(|x| x.lint),
                Some(lint),
                "{line}"
            );
        }
    }

    #[test]
    fn other_lines_name_no_lint() {
        for line in [
            "error: usage of an `unsafe` block",
            "  = note: `-F unsafe-code` implied by something else",
            "  = note: requested on the command line with `-F not-a-corten-lint`",
            "  = note: requested on the command line with `-F unsafe-code",
        ] {
            assert_eq!(forbidden_lint_in(line), None, "{line}");
        }
    }
}
