//! The `corten-gateway` binary, run as an operator runs it.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions; a failed setup panics and fails the test"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_corten-gateway"))
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("corten-gw-cli-{tag}-{}", std::process::id()));
    let _gone = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn help_goes_to_stdout_and_usage_errors_exit_2() {
    // Under a broken parser these would run; keep any key out of the tree.
    let d = scratch("usage");
    let k = d.join("k");
    let k = k.to_str().unwrap();
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("Exit codes: 0 success, 1 failure, 2 usage error.")
    );
    for args in [
        &[][..],
        &["frobnicate"],
        &["serve"],
        &["check", "--config"],
        &["check", "--config", "a", "--config", "b"],
        &["keygen-client", "--out", k, "--bogus", "x"],
        &["keygen-client", "--out", k, "--kid", "a.b"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            out.stdout.is_empty(),
            "usage errors print nothing on stdout"
        );
        assert!(String::from_utf8(out.stderr).unwrap().contains("Usage:"));
    }
    let v = run(&["--version"]);
    assert_eq!(v.status.code(), Some(0));
    assert!(
        String::from_utf8(v.stdout)
            .unwrap()
            .starts_with("corten-gateway ")
    );
}

#[test]
fn keygen_client_writes_a_private_key_once_and_prints_its_jwk() {
    let d = scratch("keygen");
    let key = d.join("client.key");
    let out = run(&[
        "keygen-client",
        "--out",
        key.to_str().unwrap(),
        "--kid",
        "gw-1",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let jwk: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (
            jwk["kty"].as_str(),
            jwk["crv"].as_str(),
            jwk["kid"].as_str()
        ),
        (Some("EC"), Some("P-256"), Some("gw-1"))
    );
    assert!(jwk.get("d").is_none(), "the private part is never printed");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = std::fs::read(&key).unwrap();
    let again = run(&["keygen-client", "--out", key.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        String::from_utf8(again.stderr)
            .unwrap()
            .contains("never overwritten")
    );
    assert_eq!(
        std::fs::read(&key).unwrap(),
        before,
        "an existing key is never overwritten"
    );
}

fn setup(tag: &str) -> PathBuf {
    let d = scratch(tag);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["gw.example".to_owned()])
        .unwrap()
        .self_signed(&ca_key)
        .unwrap();
    std::fs::write(d.join("gw.crt"), cert.pem()).unwrap();
    std::fs::write(d.join("gw.key"), ca_key.serialize_pem()).unwrap();
    std::fs::write(d.join("mint.key"), "corten-signing-key 1\nid gw-mint\nseed 0707070707070707070707070707070707070707070707070707070707070707\n").unwrap();
    std::fs::set_permissions(d.join("mint.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let k = run(&[
        "keygen-client",
        "--out",
        d.join("client.key").to_str().unwrap(),
    ]);
    assert_eq!(k.status.code(), Some(0));
    let p = |f: &str| d.join(f).display().to_string();
    std::fs::write(d.join("gateway.conf"), format!(
        "origin https://gw.example\nlisten 127.0.0.1:0\ntls-cert {}\ntls-key {}\nissuer https://idp.example\nclient-id gw\nclient-key {}\nmint-key {}\nauthn-name api\nupstream {}\n",
        p("gw.crt"), p("gw.key"), p("client.key"), p("mint.key"), p("app.sock"))).unwrap();
    d
}

#[test]
fn check_loads_every_file_and_prints_the_program_manifest_line() {
    let d = setup("check");
    let out = run(&[
        "check",
        "--config",
        d.join("gateway.conf").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("configuration valid\n"), "{text}");
    assert!(
        text.contains("client-key-id corten-gateway-1\n")
            && text.contains("program manifest line: authn api token gw-mint:"),
        "{text}"
    );
}

#[test]
fn check_fails_with_exit_1_on_an_exposed_key_or_a_bad_setting() {
    let d = setup("refuse");
    let conf = d.join("gateway.conf");
    std::fs::set_permissions(d.join("client.key"), std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = run(&["check", "--config", conf.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("accessible to group or others")
    );
    std::fs::set_permissions(d.join("client.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut text = std::fs::read_to_string(&conf).unwrap();
    text.push_str("acr pwd\n");
    std::fs::write(&conf, text).unwrap();
    let out = run(&["check", "--config", conf.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr).unwrap().contains("acr"));
}
