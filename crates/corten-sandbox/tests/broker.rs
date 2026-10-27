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
use corten_std::manifest::Capabilities;
use corten_std::process::{ExecCap, ProcessInvocation};
use ed25519_compact::{KeyPair, Seed};

fn exec_cap(program: &str) -> ExecCap {
    let kp = KeyPair::from_seed(Seed::new([9u8; 32]));
    let manifest = format!("corten-manifest 1\nexec prog {program}\n");
    let sig = kp.sk.sign(manifest.as_bytes(), None);
    let mut caps = Capabilities::load(manifest.as_bytes(), sig.as_ref(), kp.pk.as_ref()).unwrap();
    caps.take_exec("prog").unwrap()
}

fn invocation(program: &str, operands: &[&str]) -> ProcessInvocation {
    // No options: the operands follow `--`, which these utilities accept.
    ProcessInvocation::new(&exec_cap(program), &[], operands).unwrap()
}

fn shell(script: &str) -> ProcessInvocation {
    // `sh -c -- SCRIPT`: `-c` is the literal option and the script the
    // runtime operand after `--`, which POSIX shells accept.
    ProcessInvocation::new(&exec_cap("/bin/sh"), &["-c"], &[script]).unwrap()
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

    let inv = ProcessInvocation::new(&exec_cap("/bin/bash"), &["-c"], &[&script]).unwrap();
    let out = run(&inv, &policy(), b"").unwrap();
    assert_ne!(out.code, Some(0));
    assert!(text(&out.stdout).is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("Permission denied"),
        "{}",
        text(&out.stderr)
    );
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
    // Descriptors this process inherited from its own parent without
    // close-on-exec (a CI runner leaks some) pass through the broker: closing
    // a descriptor the process does not own needs `unsafe` (docs/gates/phase-3.md).
    // The claim tested here is about descriptors the process opened itself.
    let leaked = descriptors_without_cloexec();
    let mut p = policy();
    p.read_only.push(PathBuf::from("/proc"));
    let out = run(&invocation("/bin/ls", &["/proc/self/fd"]), &p, b"").unwrap();
    assert_eq!(out.code, Some(0), "{}", text(&out.stderr));
    let fds: Vec<i32> = text(&out.stdout)
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .filter(|n| *n > 2 && !leaked.contains(n))
        .collect();
    // At most the descriptor ls opened to list the directory; the five held
    // files would add five.
    assert!(
        fds.len() <= 1,
        "inherited descriptors: {fds:?}, leaked by the parent: {leaked:?}"
    );
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

/// This process's descriptors without `O_CLOEXEC`, from /proc/self/fdinfo.
fn descriptors_without_cloexec() -> Vec<i32> {
    const O_CLOEXEC: u32 = 0o2_000_000;
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc/self/fdinfo").unwrap() {
        let name = entry.unwrap().file_name();
        let Ok(fd) = name.to_string_lossy().parse::<i32>() else {
            continue;
        };
        // The descriptor read_dir holds may be gone by now.
        let Ok(info) = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else {
            continue;
        };
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
            .unwrap();
        if flags & O_CLOEXEC == 0 {
            out.push(fd);
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _infallible = write!(out, "{b:02x}");
        out
    })
}

/// Layer 5: the signed manifest decides what the program may touch.
#[test]
fn manifest_mode_grants_exactly_the_manifest() {
    let s = Scratch::new("manifest");
    let data = s.0.join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("in.txt"), "granted").unwrap();
    let outside = s.0.join("outside.txt");
    fs::write(&outside, "not granted").unwrap();
    let kp = KeyPair::from_seed(Seed::new([11u8; 32]));
    let manifest = format!(
        "corten-manifest 1\ndir data {}\nexec cat /bin/cat\n",
        data.display()
    );
    let m_path = s.0.join("manifest");
    let s_path = s.0.join("manifest.sig");
    fs::write(&m_path, &manifest).unwrap();
    fs::write(&s_path, kp.sk.sign(manifest.as_bytes(), None).as_ref()).unwrap();
    let sandbox = env!("CARGO_BIN_EXE_corten-sandbox");
    let run_cat = |file: &Path, sig: &Path| {
        Command::new(sandbox)
            .arg("--manifest")
            .arg(&m_path)
            .arg("--signature")
            .arg(sig)
            .arg("--public-key")
            .arg(hex(kp.pk.as_ref()))
            .arg("--system")
            .arg("--")
            .arg("/bin/cat")
            .arg(file)
            .output()
            .unwrap()
    };
    let inside = run_cat(&data.join("in.txt"), &s_path);
    assert_eq!(text(&inside.stdout), "granted", "{}", text(&inside.stderr));
    let denied = run_cat(&outside, &s_path);
    assert_ne!(denied.status.code(), Some(0));
    assert!(
        text(&denied.stderr).contains("Permission denied"),
        "{}",
        text(&denied.stderr)
    );
    // A signature over different bytes: refused before anything runs.
    let bad_sig = s.0.join("bad.sig");
    fs::write(&bad_sig, kp.sk.sign(b"corten-manifest 1\n", None).as_ref()).unwrap();
    let refused = run_cat(&data.join("in.txt"), &bad_sig);
    assert_eq!(refused.status.code(), Some(3), "{}", text(&refused.stderr));
    assert!(text(&refused.stderr).contains("manifest refused"));
}
