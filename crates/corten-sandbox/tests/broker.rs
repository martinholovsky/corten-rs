//! Phase 3 gate tests: a brokered program cannot exceed its declared
//! capabilities. Linux only; each confinement test first shows the same
//! action succeeds without the sandbox (the control).

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    reason = "the test allowances cover #[test] bodies, not the setup helpers; a failed setup aborts the test either way"
)]

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use corten_broker::process::{BrokerError, ProcessPolicy, run};
use corten_std::manifest::{Capabilities, KeyId, MinSerial, PublicKey, Signature, TrustedKeys};
use corten_std::process::{ExecCap, Operands, Options, OptionsTemplate, ProcessInvocation};
use ed25519_compact::{KeyPair, Seed};

fn exec_cap(program: &str) -> ExecCap {
    let kp = KeyPair::from_seed(Seed::new([9u8; 32]));
    // Capabilities::load does not check the program line; the launcher does.
    let manifest = format!(
        "corten-manifest 3\nkey k\nserial 1\nnot-after 4102444800\nprogram sha256 {}\nexec prog {program}\n",
        "0".repeat(64)
    );
    let sig = kp.sk.sign(manifest.as_bytes(), None);
    let mut keys = TrustedKeys::new();
    keys.add(KeyId("k"), PublicKey(kp.pk.as_ref())).unwrap();
    let mut caps = Capabilities::load(
        manifest.as_bytes(),
        Signature(sig.as_ref()),
        &keys,
        MinSerial(0),
    )
    .unwrap();
    caps.take_exec("prog").unwrap()
}

fn invocation(program: &str, operands: &[&str]) -> ProcessInvocation {
    // No options: the operands follow `--`, which these utilities accept.
    ProcessInvocation::new(&exec_cap(program), Options::none(), Operands(operands)).unwrap()
}

/// `-c`, the shell's literal option.
struct ShellC;
impl OptionsTemplate for ShellC {
    const OPTIONS: &'static [&'static str] = &["-c"];
}

fn shell(script: &str) -> ProcessInvocation {
    // `sh -c -- SCRIPT`: `-c` is the literal option and the script the
    // runtime operand after `--`, which POSIX shells accept.
    ProcessInvocation::new(
        &exec_cap("/bin/sh"),
        Options::from_template::<ShellC>(),
        Operands(&[script]),
    )
    .unwrap()
}

fn policy() -> ProcessPolicy {
    ProcessPolicy {
        sandbox: PathBuf::from(env!("CARGO_BIN_EXE_corten-sandbox")),
        read_only: Vec::new(),
        read_write: Vec::new(),
        system: true,
        deadline: Duration::from_secs(10),
        max_input: 1024,
        max_output: 64 * 1024,
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("corten-broker-{}-{name}", std::process::id()));
        let _ignored = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn reading_outside_the_grant_is_denied() {
    let s = Scratch::new("read");
    let secret = s.0.join("secret.txt");
    fs::write(&secret, "top secret").unwrap();
    // Control: unconfined, cat reads it.
    let plain = Command::new("/bin/cat").arg(&secret).output().unwrap();
    assert_eq!(text(&plain.stdout), "top secret");

    let out = run(
        &invocation("/bin/cat", &[secret.to_str().unwrap()]),
        &policy(),
        b"",
    )
    .unwrap();
    assert_ne!(out.code, Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("Permission denied"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout), "");

    // Granted read-only, it works.
    let mut granted = policy();
    granted.read_only.push(s.0.clone());
    let ok = run(
        &invocation("/bin/cat", &[secret.to_str().unwrap()]),
        &granted,
        b"",
    )
    .unwrap();
    assert_eq!(text(&ok.stdout), "top secret");
}

#[test]
fn writing_outside_the_grant_is_denied() {
    let s = Scratch::new("write");
    let target = s.0.join("out.txt");
    let script = format!("echo hi > {}", target.display());
    // Control.
    let plain = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .status()
        .unwrap();
    assert!(plain.success());
    fs::remove_file(&target).unwrap();

    let mut ro = policy();
    ro.read_only.push(s.0.clone());
    let out = run(&shell(&script), &ro, b"").unwrap();
    assert_ne!(out.code, Some(0));
    assert!(!target.exists());

    let mut rw = policy();
    rw.read_write.push(s.0.clone());
    let ok = run(&shell(&script), &rw, b"").unwrap();
    assert_eq!(ok.code, Some(0), "{}", text(&ok.stderr));
    assert_eq!(fs::read_to_string(&target).unwrap(), "hi\n");
}

#[test]
fn tcp_connect_is_denied() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port} && echo connected");
    // Control: bash connects unconfined.
    let plain = Command::new("/bin/bash")
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap();
    assert_eq!(
        text(&plain.stdout),
        "connected\n",
        "{}",
        text(&plain.stderr)
    );

    let inv = ProcessInvocation::new(
        &exec_cap("/bin/bash"),
        Options::from_template::<ShellC>(),
        Operands(&[&script]),
    )
    .unwrap();
    let out = run(&inv, &policy(), b"").unwrap();
    assert_ne!(out.code, Some(0));
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    // Landlock refuses the connect before the network stack is reached,
    // also inside the empty network namespace a program without a grant
    // runs in (F2; measured: "connect: Permission denied").
    assert!(
        text(&out.stderr).contains("Permission denied"),
        "{}",
        text(&out.stderr)
    );
}

/// F2: Landlock ABI v4 does not filter UDP; a program without a network
/// grant runs in an empty network namespace, so it cannot send any.
#[test]
fn udp_is_refused_without_a_network_grant() {
    let script = "echo x > /dev/udp/127.0.0.1/9 && echo sent";
    // Control: bash sends a datagram unconfined.
    let plain = Command::new("/bin/bash")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert_eq!(text(&plain.stdout), "sent\n", "{}", text(&plain.stderr));
    let inv = ProcessInvocation::new(
        &exec_cap("/bin/bash"),
        Options::from_template::<ShellC>(),
        Operands(&[script]),
    )
    .unwrap();
    let out = run(&inv, &policy(), b"").unwrap();
    assert_ne!(out.code, Some(0));
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("Network is unreachable"),
        "{}",
        text(&out.stderr)
    );
}

/// With a `net` grant the program keeps the host's network, and Landlock
/// allows TCP connects to the granted port only.
#[test]
fn landlock_denies_a_tcp_port_the_net_grant_does_not_name() {
    let s = Scratch::new("netgrant");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let granted = other.local_addr().unwrap().port();
    let kp = KeyPair::from_seed(Seed::new([13u8; 32]));
    let bash = corten_sha256::hex_digest(&fs::read("/bin/bash").unwrap());
    let manifest = format!(
        "corten-manifest 3\nkey deploy\nserial 1\nnot-after 4102444800\nprogram sha256 {bash}\nnet db 127.0.0.1:{granted} private\n"
    );
    let (m, g, state) = (s.0.join("m"), s.0.join("m.sig"), s.0.join("serial"));
    fs::write(&m, &manifest).unwrap();
    fs::write(&g, kp.sk.sign(manifest.as_bytes(), None).as_ref()).unwrap();
    let connect = |to: u16| {
        Command::new(env!("CARGO_BIN_EXE_corten-sandbox"))
            .arg("--manifest")
            .arg(&m)
            .arg("--signature")
            .arg(&g)
            .arg("--trusted-key")
            .arg(format!("deploy={}", hex(kp.pk.as_ref())))
            .arg("--serial-state")
            .arg(&state)
            .arg("--system")
            .arg("--")
            .arg("/bin/bash")
            .arg("-c")
            .arg(format!("exec 3<>/dev/tcp/127.0.0.1/{to} && echo connected"))
            .output()
            .unwrap()
    };
    let ok = connect(granted);
    assert_eq!(text(&ok.stdout), "connected\n", "{}", text(&ok.stderr));
    let denied = connect(port);
    assert_ne!(denied.status.code(), Some(0));
    assert!(
        text(&denied.stderr).contains("Permission denied"),
        "{}",
        text(&denied.stderr)
    );
}

/// Whether the running kernel has Landlock ABI v6 (Linux 6.12), the first
/// with signal and abstract UNIX socket scoping. Read from the release string:
/// a test cannot ask Landlock directly without `unsafe`.
fn kernel_has_scopes() -> bool {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut parts = release
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .map(|n| n.parse::<u32>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    (major, minor) >= (6, 12)
}

#[test]
fn signalling_a_process_outside_the_sandbox() {
    // The target is this test process, which is outside the sandbox.
    let script = format!("kill -0 {} && echo signalled", std::process::id());
    // Control: the shell can signal it unconfined.
    let plain = Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .output()
        .unwrap();
    assert_eq!(
        text(&plain.stdout),
        "signalled\n",
        "{}",
        text(&plain.stderr)
    );

    let out = run(&shell(&script), &policy(), b"").unwrap();
    if kernel_has_scopes() {
        assert_ne!(out.code, Some(0));
        assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
        assert!(
            text(&out.stderr).contains("Operation not permitted"),
            "{}",
            text(&out.stderr)
        );
    } else {
        // Below ABI v6 the sandbox still runs, without the scope (docs/tcb.md).
        assert_eq!(text(&out.stdout), "signalled\n", "{}", text(&out.stderr));
    }
}

#[test]
fn deadline_kills_the_program() {
    let mut p = policy();
    p.deadline = Duration::from_millis(300);
    let started = Instant::now();
    let r = run(&invocation("/bin/sleep", &["5"]), &p, b"");
    assert!(matches!(r, Err(BrokerError::Deadline)), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn output_quota_stops_the_program() {
    let mut p = policy();
    p.max_output = 1000;
    p.deadline = Duration::from_secs(5);
    let r = run(&invocation("/usr/bin/yes", &[]), &p, b"");
    assert!(matches!(r, Err(BrokerError::OutputQuota)), "{r:?}");
}

#[test]
fn input_reaches_stdin_and_quota_applies() {
    let out = run(&invocation("/bin/cat", &[]), &policy(), b"hello").unwrap();
    assert_eq!(text(&out.stdout), "hello");
    let big = vec![b'a'; 2048];
    assert!(matches!(
        run(&invocation("/bin/cat", &[]), &policy(), &big),
        Err(BrokerError::InputQuota)
    ));
}

/// CWE-403: descriptors this process holds are not inherited.
#[test]
fn open_descriptors_are_not_inherited() {
    let s = Scratch::new("fds");
    let mut held = Vec::new();
    for i in 0..5 {
        let p: &Path = &s.0.join(format!("f{i}"));
        fs::write(p, "x").unwrap();
        held.push(fs::File::open(p).unwrap());
    }
    let mut p = policy();
    p.read_only.push(PathBuf::from("/proc"));
    let out = run(&invocation("/bin/ls", &["/proc/self/fd"]), &p, b"").unwrap();
    assert_eq!(out.code, Some(0), "{}", text(&out.stderr));
    let fds: Vec<i32> = text(&out.stdout)
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .filter(|n| *n > 2)
        .collect();
    // At most the descriptor ls opened to list the directory; the five held
    // files would add five.
    assert!(fds.len() <= 1, "inherited descriptors: {fds:?}");
    let mut buf = String::new();
    held[0].read_to_string(&mut buf).unwrap();
    assert_eq!(buf, "x");
}

#[test]
fn sandbox_refuses_a_missing_path() {
    let mut p = policy();
    p.read_only.push(PathBuf::from("/nonexistent/corten"));
    let out = run(&invocation("/bin/true", &[]), &p, b"").unwrap();
    assert_eq!(out.code, Some(3), "{}", text(&out.stderr));
}

/// A descriptor the sandbox's parent left open without close-on-exec would
/// reach the program, past Landlock; the sandbox refuses to run (exit 3).
#[test]
fn a_descriptor_without_cloexec_is_refused() {
    let sandbox = env!("CARGO_BIN_EXE_corten-sandbox");
    let under_sh = |prelude: &str| {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{prelude} exec \"$0\" --system -- /bin/true"))
            .arg(sandbox)
            .output()
            .unwrap()
    };
    // Control: with no extra descriptor the program runs.
    let clean = under_sh("");
    assert_eq!(clean.status.code(), Some(0), "{}", text(&clean.stderr));
    // `exec 7<` opens descriptor 7 without close-on-exec.
    let leaky = under_sh("exec 7</dev/null;");
    assert_eq!(leaky.status.code(), Some(3), "{}", text(&leaky.stderr));
    assert!(
        text(&leaky.stderr).contains("descriptors [7]"),
        "{}",
        text(&leaky.stderr)
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _infallible = write!(out, "{b:02x}");
        out
    })
}

/// Layer 5: the signed manifest decides what the program may touch, and an
/// older, expired or untrusted manifest is refused before anything runs.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one launcher scenario: each refusal is checked against the same state file, in order"
)]
fn manifest_mode_grants_exactly_the_manifest() {
    let s = Scratch::new("manifest");
    let data = s.0.join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("in.txt"), "granted").unwrap();
    let outside = s.0.join("outside.txt");
    fs::write(&outside, "not granted").unwrap();
    let kp = KeyPair::from_seed(Seed::new([11u8; 32]));
    let state = s.0.join("serial");
    let sandbox = env!("CARGO_BIN_EXE_corten-sandbox");
    // The digest of the program the manifest is for (finding F4).
    let cat = corten_sha256::hex_digest(&fs::read("/bin/cat").unwrap());
    // Writes a manifest for `program` (a hex digest) and its signature;
    // returns their paths.
    let write_for = |tag: &str,
                     key: &str,
                     serial: u64,
                     not_after: u64,
                     signer: &KeyPair,
                     program: &str| {
        let manifest = format!(
            "corten-manifest 3\nkey {key}\nserial {serial}\nnot-after {not_after}\nprogram sha256 {program}\ndir data {}\nexec cat /bin/cat\n",
            data.display()
        );
        let m = s.0.join(format!("{tag}.manifest"));
        let g = s.0.join(format!("{tag}.sig"));
        fs::write(&m, &manifest).unwrap();
        fs::write(&g, signer.sk.sign(manifest.as_bytes(), None).as_ref()).unwrap();
        (m, g)
    };
    let write = |tag: &str, key: &str, serial: u64, not_after: u64, signer: &KeyPair| {
        write_for(tag, key, serial, not_after, signer, &cat)
    };
    let run_cat = |(m, g): &(PathBuf, PathBuf), file: &Path| {
        Command::new(sandbox)
            .arg("--manifest")
            .arg(m)
            .arg("--signature")
            .arg(g)
            .arg("--trusted-key")
            .arg(format!("deploy={}", hex(kp.pk.as_ref())))
            .arg("--serial-state")
            .arg(&state)
            .arg("--system")
            .arg("--")
            .arg("/bin/cat")
            .arg(file)
            .output()
            .unwrap()
    };
    let refused = |out: &std::process::Output, why: &str| {
        assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains(why), "{}", text(&out.stderr));
    };
    let later = 4_102_444_800;
    let current = write("current", "deploy", 5, later, &kp);
    let inside = run_cat(&current, &data.join("in.txt"));
    assert_eq!(text(&inside.stdout), "granted", "{}", text(&inside.stderr));
    assert_eq!(
        fs::read_to_string(&state).unwrap(),
        "5\n",
        "the serial was recorded"
    );
    let denied = run_cat(&current, &outside);
    assert_ne!(denied.status.code(), Some(0));
    assert!(
        text(&denied.stderr).contains("Permission denied"),
        "{}",
        text(&denied.stderr)
    );
    // A signature over different bytes: refused before anything runs.
    let (m, _) = &current;
    let bad_sig = s.0.join("bad.sig");
    fs::write(&bad_sig, kp.sk.sign(b"corten-manifest 3\n", None).as_ref()).unwrap();
    refused(
        &run_cat(&(m.clone(), bad_sig), &data.join("in.txt")),
        "manifest refused",
    );
    // A valid, newer manifest for another binary: refused before anything
    // runs, and the serial is not advanced (finding F4).
    let not_cat = "0".repeat(64);
    refused(
        &run_cat(
            &write_for("other-program", "deploy", 9, later, &kp, &not_cat),
            &data.join("in.txt"),
        ),
        "refusing to grant it the manifest's capabilities",
    );
    assert_eq!(
        fs::read_to_string(&state).unwrap(),
        "5\n",
        "a refused binary advanced the serial"
    );
    // An older manifest, validly signed: refused as a replay.
    refused(
        &run_cat(
            &write("older", "deploy", 4, later, &kp),
            &data.join("in.txt"),
        ),
        "replayed",
    );
    // An expired manifest.
    refused(
        &run_cat(&write("expired", "deploy", 6, 1, &kp), &data.join("in.txt")),
        "expired",
    );
    // A manifest naming a key the launcher does not trust.
    let other = KeyPair::from_seed(Seed::new([12u8; 32]));
    refused(
        &run_cat(
            &write("untrusted", "other", 6, later, &other),
            &data.join("in.txt"),
        ),
        "untrusted key",
    );
    // None of the refused manifests moved the high-water mark.
    assert_eq!(fs::read_to_string(&state).unwrap(), "5\n");
}
