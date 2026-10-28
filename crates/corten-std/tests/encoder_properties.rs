//! Property tests for the typed sinks' encoders (evidence for the
//! independent review in docs/gates/phase-2.md section 5; not a substitute).
//!
//! Each property says one thing an attacker-controlled value must never do
//! to the output: change its structure. Values come from a fixed-seed
//! generator weighted towards the characters each grammar treats as special,
//! so a failure reproduces exactly. No dependency: the generator is below.

#![allow(
    clippy::unwrap_used,
    reason = "the test allowances cover #[test] bodies, not the setup helpers; a failed setup aborts the test either way"
)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::panic,
    reason = "test-only generator and checkers, whose panics are the failures: indices come from `find`/`match_indices` on ASCII delimiters and the generator's range, and a panic fails the test, which is the outcome wanted"
)]

use corten_std::csv::CsvCell;
use corten_std::http::HeaderValue;
use corten_std::ldap::{escape_dn_value, escape_filter_value};
use corten_std::sql::{Placeholder, SqlValue};
use corten_std::xpath::{xpath_literal, xquery_literal};

/// Cases per property.
const CASES: usize = 20_000;

/// Characters that are special in at least one grammar, plus ordinary and
/// non-ASCII text.
const ALPHABET: &[char] = &[
    '<', '>', '&', '"', '\'', '`', '=', '/', ';', ':', '(', ')', '*', '\\', '\0', ',', '+', '#',
    ' ', '\t', '\r', '\n', '-', '@', '$', '{', '}', '[', ']', '|', '!', '?', '%', 'a', 'Z', '0',
    '9', 'é', '＝', '\u{2028}', '\u{202E}', '\u{7f}', '\u{85}', '😀',
];

/// xorshift64*: deterministic and dependency-free.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn value(&mut self) -> String {
        let len = self.below(24);
        (0..len)
            .map(|_| ALPHABET[self.below(ALPHABET.len())])
            .collect()
    }
}

fn values(seed: u64) -> impl Iterator<Item = String> {
    let mut g = Gen(seed);
    (0..CASES).map(move |_| g.value())
}

/// Every `&` starts a character reference `&name;` or `&#...;`.
fn ampersands_are_references(s: &str) -> bool {
    s.match_indices('&').all(|(i, _)| {
        let rest = &s[i + 1..];
        let end = rest.find(';');
        end.is_some_and(|e| {
            let name = &rest[..e];
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '#')
        })
    })
}

fn check_html_element_text_never_carries_markup(v: &str) {
    let out = corten_std::html!("<p>{}</p>", v);
    let inner = out
        .as_str()
        .strip_prefix("<p>")
        .and_then(|s| s.strip_suffix("</p>"))
        .unwrap_or_else(|| panic!("structure changed for {v:?}: {}", out.as_str()));
    assert!(
        !inner.contains(['<', '>', '"', '\'']) && ampersands_are_references(inner),
        "{v:?} -> {inner:?}"
    );
}

#[test]
fn html_element_text_never_carries_markup() {
    for v in values(1) {
        check_html_element_text_never_carries_markup(&v);
    }
}

fn check_html_attribute_value_never_closes_its_quotes(v: &str) {
    let out = corten_std::html!("<abbr title=\"{}\">x</abbr>", v);
    let inner = out
        .as_str()
        .strip_prefix("<abbr title=\"")
        .and_then(|s| s.strip_suffix("\">x</abbr>"))
        .unwrap_or_else(|| panic!("structure changed for {v:?}: {}", out.as_str()));
    assert!(
        !inner.contains(['"', '\'', '<', '>']) && ampersands_are_references(inner),
        "{v:?} -> {inner:?}"
    );
}

#[test]
fn html_attribute_value_never_closes_its_quotes() {
    for v in values(2) {
        check_html_attribute_value_never_closes_its_quotes(&v);
    }
}

fn check_sql_values_never_enter_the_text(v: &str) {
    let expected = "SELECT id FROM users WHERE name = $1";
    let q = corten_std::sql!("SELECT id FROM users WHERE name = {}", v);
    assert_eq!(q.text(Placeholder::Dollar), expected, "{v:?}");
    assert_eq!(q.params(), [SqlValue::Text(v.to_owned())].as_slice());
}

#[test]
fn sql_values_never_enter_the_text() {
    for v in values(3) {
        check_sql_values_never_enter_the_text(&v);
    }
}

/// The value with each escape removed: `\xx` (two hex digits) and, for each
/// character in `specials`, `\` followed by it. RFC 4514 section 2.4 allows
/// both in a DN; RFC 4515 filters allow only the hex form. `None` when a
/// backslash starts anything else.
fn without_escapes(s: &str, specials: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let a = chars.next()?;
            if specials.contains(a) {
                continue;
            }
            let b = chars.next()?;
            if !(a.is_ascii_hexdigit() && b.is_ascii_hexdigit()) {
                return None;
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn check_ldap_filter_values_carry_no_filter_syntax(v: &str) {
    let e = escape_filter_value(v);
    let bare = without_escapes(&e, "").unwrap_or_else(|| panic!("bad escape {v:?} -> {e:?}"));
    assert!(
        !bare.contains(['*', '(', ')', '\\', '\0']),
        "{v:?} -> {e:?}"
    );
    let f = corten_std::ldap_filter!("(&(uid={})(objectClass=person))", v);
    let opens = f.as_str().matches('(').count();
    assert_eq!(opens, 3, "{v:?} -> {}", f.as_str());
}

#[test]
fn ldap_filter_values_carry_no_filter_syntax() {
    for v in values(4) {
        check_ldap_filter_values_carry_no_filter_syntax(&v);
    }
}

fn check_ldap_dn_values_carry_no_dn_syntax(v: &str) {
    let e = escape_dn_value(v);
    let bare =
        without_escapes(&e, "\"+,;<>\\= #").unwrap_or_else(|| panic!("bad escape {v:?} -> {e:?}"));
    assert!(
        !bare.contains([',', '+', '"', '\\', '<', '>', ';', '=', '\0']),
        "{v:?} -> {e:?}"
    );
    // Leading `#` or space and a trailing space must be escaped in the
    // output itself (checked there: stripping an escaped leading space
    // would expose a `#` that is not leading in the value).
    assert!(
        !e.starts_with(['#', ' ']) && (!e.ends_with(' ') || e.ends_with("\\ ")),
        "{v:?} -> {e:?}"
    );
}

#[test]
fn ldap_dn_values_carry_no_dn_syntax() {
    for v in values(5) {
        check_ldap_dn_values_carry_no_dn_syntax(&v);
    }
}

/// An XPath 1.0 string expression yielding exactly `v`: one quoted literal
/// without its own quote, or `concat(...)` of such literals.
fn xpath_string_value(expr: &str) -> Option<String> {
    let literal = |s: &str| -> Option<String> {
        let q = s.chars().next()?;
        if q != '\'' && q != '"' {
            return None;
        }
        let body = s.strip_prefix(q)?.strip_suffix(q)?;
        (!body.contains(q)).then(|| body.to_owned())
    };
    if let Some(args) = expr
        .strip_prefix("concat(")
        .and_then(|s| s.strip_suffix(')'))
    {
        // Split on commas outside quotes.
        let (mut parts, mut cur, mut quote) = (Vec::new(), String::new(), None);
        for c in args.chars() {
            match (quote, c) {
                (None, '\'' | '"') => {
                    quote = Some(c);
                    cur.push(c);
                }
                (Some(q), c) if c == q => {
                    quote = None;
                    cur.push(c);
                }
                (None, ',') => parts.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        parts.push(cur);
        parts.iter().map(|p| literal(p.trim())).collect()
    } else {
        literal(expr)
    }
}

fn check_xpath_literals_round_trip(v: &str) {
    let e = xpath_literal(v);
    assert_eq!(xpath_string_value(&e).as_deref(), Some(v), "{v:?} -> {e:?}");
}

#[test]
fn xpath_literals_round_trip() {
    for v in values(6) {
        check_xpath_literals_round_trip(&v);
    }
}

fn check_xquery_literals_stay_one_string(v: &str) {
    let e = xquery_literal(v);
    // XQuery 3.1: StringLiteral ::= '"' (PredefinedEntityRef | CharRef |
    // EscapeQuot | [^"&])* '"'. A lone `"` would end it and a bare `&`
    // would start a reference; braces are ordinary characters here.
    let body = e
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{v:?} -> {e:?}"));
    assert!(!body.replace("\"\"", "").contains('"'), "{v:?} -> {e:?}");
    assert!(ampersands_are_references(body), "{v:?} -> {e:?}");
}

#[test]
fn xquery_literals_stay_one_string() {
    for v in values(7) {
        check_xquery_literals_stay_one_string(&v);
    }
}

fn check_log_records_stay_on_one_line_and_in_their_field(v: &str) {
    let r = corten_std::log_record!("login.failed", user = v);
    let line = r.render();
    assert!(
        !line.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
            && !line.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')),
        "{v:?} -> {line:?}"
    );
    let field = line
        .strip_prefix("login.failed user=\"")
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{v:?} -> {line:?}"));
    // Inside the field, every quote is escaped.
    let unescaped = field.replace("\\\\", "").replace("\\\"", "");
    assert!(!unescaped.contains('"'), "{v:?} -> {line:?}");
}

#[test]
fn log_records_stay_on_one_line_and_in_their_field() {
    for v in values(8) {
        check_log_records_stay_on_one_line_and_in_their_field(&v);
    }
}

fn check_header_values_refuse_line_breaks(v: &str) {
    if HeaderValue::parse(v).is_ok() {
        assert!(!v.contains(['\r', '\n', '\0']), "{v:?} accepted");
    }
}

#[test]
fn header_values_refuse_line_breaks() {
    for v in values(9) {
        check_header_values_refuse_line_breaks(&v);
    }
}

fn check_csv_cells_never_start_a_formula(v: &str) {
    let c = CsvCell::new(v);
    assert!(
        !c.as_str().starts_with([
            '=', '+', '-', '@', '\t', '\r', '\n', '\0', '＝', '＋', '－', '＠'
        ]),
        "{v:?} -> {:?}",
        c.as_str()
    );
}

#[test]
fn csv_cells_never_start_a_formula() {
    for v in values(10) {
        check_csv_cells_never_start_a_formula(&v);
    }
}

/// Every input of the exhaustive tests: the empty string, every Unicode
/// scalar value alone (1,112,064), and every pair of ASCII characters
/// (16,384). The encoders map characters independently, apart from position
/// (a DN's first and last character, a CSV cell's first), so this covers
/// each character class completely, which is what a bounded proof of length
/// 1 would show (docs/gates/phase-5.md, part 4).
fn every_short_input() -> impl Iterator<Item = String> {
    let singles = (0..=0x10_FFFF_u32)
        .filter_map(char::from_u32)
        .map(String::from);
    let pairs = (0..128_u8).flat_map(|a| {
        (0..128_u8).map(move |b| [char::from(a), char::from(b)].iter().collect::<String>())
    });
    std::iter::once(String::new()).chain(singles).chain(pairs)
}

fn exhaustively(check: fn(&str)) {
    let mut n = 0usize;
    for v in every_short_input() {
        check(&v);
        n += 1;
    }
    assert_eq!(n, 1 + 1_112_064 + 16_384, "denominator");
}

#[test]
fn html_element_text_never_carries_markup_exhaustively() {
    exhaustively(check_html_element_text_never_carries_markup);
}

#[test]
fn html_attribute_value_never_closes_its_quotes_exhaustively() {
    exhaustively(check_html_attribute_value_never_closes_its_quotes);
}

#[test]
fn sql_values_never_enter_the_text_exhaustively() {
    exhaustively(check_sql_values_never_enter_the_text);
}

#[test]
fn ldap_filter_values_carry_no_filter_syntax_exhaustively() {
    exhaustively(check_ldap_filter_values_carry_no_filter_syntax);
}

#[test]
fn ldap_dn_values_carry_no_dn_syntax_exhaustively() {
    exhaustively(check_ldap_dn_values_carry_no_dn_syntax);
}

#[test]
fn xpath_literals_round_trip_exhaustively() {
    exhaustively(check_xpath_literals_round_trip);
}

#[test]
fn xquery_literals_stay_one_string_exhaustively() {
    exhaustively(check_xquery_literals_stay_one_string);
}

#[test]
fn log_records_stay_on_one_line_and_in_their_field_exhaustively() {
    exhaustively(check_log_records_stay_on_one_line_and_in_their_field);
}

#[test]
fn header_values_refuse_line_breaks_exhaustively() {
    exhaustively(check_header_values_refuse_line_breaks);
}

#[test]
fn csv_cells_never_start_a_formula_exhaustively() {
    exhaustively(check_csv_cells_never_start_a_formula);
}
