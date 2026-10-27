//! A CycloneDX SBOM and an in-toto provenance statement for a
//! `cargo corten build` (spec 4.15; Phase 3). The statement is unsigned:
//! signing is layer 4's job (a CI attestation, spec section 10).

use crate::json::Json;

/// A file the build produced, with its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Path relative to the target directory.
    pub name: String,
    /// SHA-256, hex.
    pub sha256: String,
}

/// What the provenance statement records about the build.
#[derive(Debug, Clone)]
pub struct BuildFacts<'a> {
    /// `cargo-corten` version.
    pub checker: &'a str,
    /// `rustc -vV` output.
    pub rustc: &'a str,
    /// The profile's flags, in order.
    pub profile_flags: &'a [&'a str],
    /// SHA-256 of `Cargo.lock`.
    pub lock_sha256: &'a str,
    /// Whether the build ran inside `corten-sandbox`.
    pub sandboxed: bool,
}

/// JSON string literal for `text`.
#[must_use]
pub fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                // \u00XX: control characters are below 0x20, so two hex digits.
                let v = u32::from(c);
                out.push_str("\\u00");
                out.push(char::from_digit(v / 16, 16).unwrap_or('0'));
                out.push(char::from_digit(v % 16, 16).unwrap_or('0'));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn field<'a>(pkg: &'a Json, key: &str) -> &'a str {
    pkg.get(key).and_then(Json::as_str).unwrap_or("")
}

/// A CycloneDX 1.5 SBOM of every package in `metadata`.
#[must_use]
pub fn sbom(metadata: &Json) -> String {
    let packages = metadata
        .get("packages")
        .and_then(Json::as_array)
        .unwrap_or(&[]);
    let components: Vec<String> = packages
        .iter()
        .map(|p| {
            let (name, version) = (field(p, "name"), field(p, "version"));
            let licence = field(p, "license");
            let licences = if licence.is_empty() {
                String::new()
            } else {
                format!(r#","licenses":[{{"expression":{}}}]"#, json_string(licence))
            };
            format!(
                r#"{{"type":"library","name":{},"version":{},"purl":{}{licences}}}"#,
                json_string(name),
                json_string(version),
                json_string(&format!("pkg:cargo/{name}@{version}")),
            )
        })
        .collect();
    format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{}]}}"#,
        components.join(",")
    )
}

/// An in-toto v1 statement with a SLSA v1 provenance predicate.
#[must_use]
pub fn statement(artifacts: &[Artifact], facts: &BuildFacts<'_>) -> String {
    let subjects: Vec<String> = artifacts
        .iter()
        .map(|a| {
            format!(
                r#"{{"name":{},"digest":{{"sha256":{}}}}}"#,
                json_string(&a.name),
                json_string(&a.sha256)
            )
        })
        .collect();
    let flags: Vec<String> = facts.profile_flags.iter().map(|f| json_string(f)).collect();
    format!(
        concat!(
            r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{subjects}],"#,
            r#""predicateType":"https://slsa.dev/provenance/v1","predicate":{{"#,
            r#""buildDefinition":{{"buildType":"https://github.com/martinholovsky/corten-rs/build/v1","#,
            r#""externalParameters":{{"profileFlags":[{flags}],"sandboxed":{sandboxed}}},"#,
            r#""resolvedDependencies":[{{"name":"Cargo.lock","digest":{{"sha256":{lock}}}}}],"#,
            r#""internalParameters":{{"rustc":{rustc}}}}},"#,
            r#""runDetails":{{"builder":{{"id":{builder}}}}}}}}}"#
        ),
        subjects = subjects.join(","),
        flags = flags.join(","),
        sandboxed = facts.sandboxed,
        lock = json_string(facts.lock_sha256),
        rustc = json_string(facts.rustc),
        builder = json_string(&format!("cargo-corten@{}", facts.checker)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings_escape() {
        assert_eq!(json_string("a\"b\\c\n\u{1}"), r#""a\"b\\c\n\u0001""#);
    }

    #[test]
    fn sbom_and_statement_are_valid_json() {
        let meta = Json::parse(
            r#"{"packages":[{"name":"app","version":"0.1.0","license":"MIT OR Apache-2.0"},{"name":"x\"y","version":"1.0.0"}]}"#,
        )
        .unwrap();
        let bom = Json::parse(&sbom(&meta)).unwrap();
        let comps = bom.get("components").and_then(Json::as_array).unwrap();
        assert_eq!(comps.len(), 2);
        assert_eq!(
            comps[0].get("purl").and_then(Json::as_str),
            Some("pkg:cargo/app@0.1.0")
        );
        let facts = BuildFacts {
            checker: "0.0.0",
            rustc: "rustc 1.99.1\nhost: x",
            profile_flags: &["-F", "unsafe_code"],
            lock_sha256: "ab",
            sandboxed: true,
        };
        let st = Json::parse(&statement(
            &[Artifact {
                name: "release/app".to_owned(),
                sha256: "cd".to_owned(),
            }],
            &facts,
        ))
        .unwrap();
        assert_eq!(
            st.get("predicateType").and_then(Json::as_str),
            Some("https://slsa.dev/provenance/v1")
        );
        let subj = st.get("subject").and_then(Json::as_array).unwrap();
        assert_eq!(
            subj[0].get("name").and_then(Json::as_str),
            Some("release/app")
        );
    }
}
