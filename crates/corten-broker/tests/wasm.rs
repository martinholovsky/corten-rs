//! Wasm broker tests with hand-encoded modules (no `wat` dependency).
//!
//! Each module is run twice where the platform allows: by the runner binary
//! directly (every platform; the interpreter's behaviour), and on Linux
//! through `wasm::run`, which starts the runner under `corten-sandbox`. The
//! two must agree.

#![allow(
    clippy::unwrap_used,
    reason = "the test allowances cover #[test] bodies, not the setup helpers; a failed setup aborts the test either way"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use corten_broker::ipc::{read_message, write_message};
use corten_broker::wasm::{Request, Response, WasmError, WasmPolicy};

fn section(id: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(leb(body.len()));
    out.extend_from_slice(body);
    out
}

fn leb(mut v: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = u8::try_from(v & 0x7f).unwrap_or(0);
        v = v.checked_shr(7).unwrap_or(0);
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn with_len(bytes: &[u8]) -> Vec<u8> {
    let mut out = leb(bytes.len());
    out.extend_from_slice(bytes);
    out
}

/// A module exporting memory (1 page), `alloc` returning 1024, and `run`
/// with the given body; optionally importing `env.host`.
fn module(run_body: &[u8], import: bool) -> Vec<u8> {
    let mut m = b"\0asm\x01\0\0\0".to_vec();
    // Types: 0 = (i32) -> i32, 1 = (i32, i32) -> i64.
    m.extend(section(
        1,
        &[2, 0x60, 1, 0x7f, 1, 0x7f, 0x60, 2, 0x7f, 0x7f, 1, 0x7e],
    ));
    if import {
        let mut imp = vec![1];
        imp.extend(with_len(b"env"));
        imp.extend(with_len(b"host"));
        imp.extend([0x00, 0]);
        m.extend(section(2, &imp));
    }
    m.extend(section(3, &[2, 0, 1]));
    m.extend(section(5, &[1, 0x00, 1]));
    let base = u8::from(import);
    let mut exp = vec![3];
    exp.extend(with_len(b"memory"));
    exp.extend([0x02, 0]);
    exp.extend(with_len(b"alloc"));
    exp.extend([0x00, base]);
    exp.extend(with_len(b"run"));
    exp.extend([0x00, base.saturating_add(1)]);
    m.extend(section(7, &exp));
    let alloc_body = [0x00, 0x41, 0x80, 0x08, 0x0b]; // no locals; i32.const 1024; end
    let mut run_fn = vec![0x00];
    run_fn.extend_from_slice(run_body);
    let mut code = vec![2];
    code.extend(with_len(&alloc_body));
    code.extend(with_len(&run_fn));
    m.extend(section(10, &code));
    m
}

/// run(ptr, len) = ptr << 32 | len: echoes the input.
const ECHO: &[u8] = &[
    0x20, 0x00, 0xad, 0x42, 0x20, 0x86, 0x20, 0x01, 0xad, 0x84, 0x0b,
];
/// run: loop forever.
const SPIN: &[u8] = &[0x03, 0x40, 0x0c, 0x00, 0x0b, 0x42, 0x00, 0x0b];
/// run: grow memory by 1000 pages; trap if that fails.
const GROW: &[u8] = &[
    0x41, 0xe8, 0x07, 0x40, 0x00, 0x41, 0x7f, 0x46, 0x04, 0x40, 0x00, 0x0b, 0x42, 0x00, 0x0b,
];

fn runner() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_corten-wasm-runner"))
}

/// `corten-sandbox`, built beside the runner by a workspace build
/// (`cargo test --workspace`, as CI runs it).
fn sandbox() -> PathBuf {
    let path = runner().with_file_name("corten-sandbox");
    assert!(
        path.is_file(),
        "{} is missing: build the workspace (cargo build --workspace)",
        path.display()
    );
    path
}

fn policy() -> WasmPolicy {
    WasmPolicy {
        sandbox: sandbox(),
        runner: runner(),
        deadline: Duration::from_secs(10),
        fuel: 1_000_000,
        max_memory: 4 * 65_536,
        max_output: 1024,
    }
}

/// Runs the runner binary without the sandbox, speaking the wire protocol.
fn direct(module: &[u8], input: &[u8], policy: &WasmPolicy) -> Result<Vec<u8>, WasmError> {
    let mut child = Command::new(runner())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let request = Request {
        fuel: policy.fuel,
        max_memory: u64::try_from(policy.max_memory).unwrap(),
        max_output: u64::try_from(policy.max_output).unwrap(),
        module: module.to_vec(),
        input: input.to_vec(),
    };
    let mut stdin = child.stdin.take().unwrap();
    write_message(&mut stdin, &request).unwrap();
    drop(stdin);
    let Response(result) = read_message::<Response>(&mut child.stdout.take().unwrap()).unwrap();
    assert!(child.wait().unwrap().success());
    result
}

/// The direct result; on Linux, also checks the sandboxed broker agrees.
fn run(module: &[u8], input: &[u8], policy: &WasmPolicy) -> Result<Vec<u8>, WasmError> {
    let here = direct(module, input, policy);
    if cfg!(target_os = "linux") {
        let brokered = corten_broker::wasm::run(module, input, policy);
        assert_eq!(format!("{here:?}"), format!("{brokered:?}"));
    }
    here
}

#[test]
fn echo_round_trips_input() {
    let out = run(&module(ECHO, false), b"hello broker", &policy()).unwrap();
    assert_eq!(out, b"hello broker");
}

#[test]
fn a_module_that_imports_anything_is_refused() {
    let r = run(&module(ECHO, true), b"x", &policy());
    assert!(matches!(r, Err(WasmError::Instantiate(_))), "{r:?}");
}

#[test]
fn fuel_bounds_cpu() {
    let r = run(&module(SPIN, false), b"x", &policy());
    let Err(WasmError::Trap(msg)) = &r else {
        panic!("expected a trap, got {r:?}");
    };
    assert!(msg.contains("fuel"), "{msg}");
}

#[test]
fn memory_limit_holds() {
    // Enough fuel for the growth, so only the memory limit can stop it.
    let mut tight = policy();
    tight.fuel = 1_000_000_000;
    let r = run(&module(GROW, false), b"x", &tight);
    // The refused memory.grow returns -1 and the module hits `unreachable`;
    // any other trap (fuel, for one) would not show the limit worked.
    let Err(WasmError::Trap(msg)) = &r else {
        panic!("expected a trap, got {r:?}");
    };
    assert!(msg.contains("unreachable"), "{msg}");
    // Control: with room for 1001 pages, the same module runs.
    let mut roomy = tight.clone();
    roomy.max_memory = 1001 * 65_536;
    let roomy_run = run(&module(GROW, false), b"x", &roomy);
    assert!(roomy_run.is_ok(), "{roomy_run:?}");
}

#[test]
fn output_limit_holds() {
    let mut small = policy();
    small.max_output = 4;
    let r = run(&module(ECHO, false), b"too long", &small);
    assert!(matches!(r, Err(WasmError::Output)), "{r:?}");
}

#[test]
fn garbage_is_invalid() {
    assert!(matches!(
        run(b"not wasm", b"", &policy()),
        Err(WasmError::Invalid(_))
    ));
}

#[test]
fn a_malformed_request_is_refused_by_the_runner() {
    let mut child = Command::new(runner())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Announces 3 bytes: too short for the 32-byte header.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[0, 0, 0, 3, 1, 2, 3])
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
}

/// Only a separate process can be stopped from outside: an in-process
/// interpreter thread cannot be killed. Fuel is effectively unlimited here,
/// so only the deadline ends the run.
#[cfg(target_os = "linux")]
#[test]
fn the_deadline_kills_the_runner() {
    let mut endless = policy();
    endless.fuel = u64::MAX;
    endless.deadline = Duration::from_millis(500);
    let started = std::time::Instant::now();
    let r = corten_broker::wasm::run(&module(SPIN, false), b"x", &endless);
    assert!(
        matches!(
            r,
            Err(WasmError::Broker(
                corten_broker::process::BrokerError::Deadline
            ))
        ),
        "{r:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// Off Linux there is no sandbox, and the broker refuses rather than
/// running the module unconfined.
#[cfg(not(target_os = "linux"))]
#[test]
fn the_broker_fails_closed_off_linux() {
    let r = corten_broker::wasm::run(&module(ECHO, false), b"x", &policy());
    assert!(matches!(r, Err(WasmError::Runner(_))), "{r:?}");
}

#[test]
fn the_runner_binary_is_beside_the_sandbox() {
    assert!(Path::new(&policy().runner).is_file());
}
