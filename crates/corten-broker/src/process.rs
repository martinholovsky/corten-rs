//! The process broker: runs a [`ProcessInvocation`] under `corten-sandbox`
//! with a deadline and input and output quotas.

use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use corten_std::process::ProcessInvocation;

/// What the broker grants a program.
#[derive(Debug, Clone)]
pub struct ProcessPolicy {
    /// The `corten-sandbox` binary.
    pub sandbox: PathBuf,
    /// Readable beneath these paths.
    pub read_only: Vec<PathBuf>,
    /// Writable beneath these paths.
    pub read_write: Vec<PathBuf>,
    /// Add the system directories a dynamically linked program needs.
    pub system: bool,
    /// Kill the program after this long.
    pub deadline: Duration,
    /// Largest stdin accepted.
    pub max_input: usize,
    /// Largest stdout, and separately stderr, accepted.
    pub max_output: usize,
}

/// A finished run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Exit code, if the program exited (not killed by a signal).
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

/// Why a run failed.
#[derive(Debug)]
pub enum BrokerError {
    /// Input larger than the policy allows.
    InputQuota,
    /// The program wrote more than the policy allows; it was killed.
    OutputQuota,
    /// The program ran past its deadline; it was killed.
    Deadline,
    /// The sandbox or program could not be started.
    Spawn(std::io::Error),
    /// Waiting for or reading from the program failed.
    Io(std::io::Error),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputQuota => f.write_str("input exceeds the policy's limit"),
            Self::OutputQuota => {
                f.write_str("output exceeded the policy's limit; the program was killed")
            }
            Self::Deadline => f.write_str("the program ran past its deadline and was killed"),
            Self::Spawn(e) => write!(f, "could not start the sandbox: {e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BrokerError {}

/// A captured stream and whether it went over its limit.
type Captured = std::io::Result<(Vec<u8>, bool)>;

/// Reads at most `limit` bytes, then reports whether more was available.
fn read_capped(mut from: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let cap = u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX);
    (&mut from).take(cap).read_to_end(&mut out)?;
    let over = out.len() > limit;
    out.truncate(limit);
    Ok((out, over))
}

fn kill(child: &mut Child) {
    // The child may have exited between the check and the kill; both
    // results are fine, and wait reaps it either way.
    let _killed = child.kill().is_ok();
    let _reaped = child.wait().is_ok();
}

/// Runs `invocation` under the policy, feeding it `input`.
///
/// The environment is cleared; the working directory is `/`. The program
/// sees only what the sandbox grants.
///
/// # Errors
///
/// [`BrokerError`]; the program is killed and reaped on every error path.
pub fn run(
    invocation: &ProcessInvocation,
    policy: &ProcessPolicy,
    input: &[u8],
) -> Result<Output, BrokerError> {
    if input.len() > policy.max_input {
        return Err(BrokerError::InputQuota);
    }
    let mut cmd = Command::new(&policy.sandbox);
    for p in &policy.read_only {
        cmd.arg("--ro").arg(p);
    }
    for p in &policy.read_write {
        cmd.arg("--rw").arg(p);
    }
    if policy.system {
        cmd.arg("--system");
    }
    cmd.arg("--exec")
        .arg(invocation.program())
        .arg("--")
        .arg(invocation.program())
        .args(invocation.argv());
    let (status, stdout, stderr) = supervise(cmd, input, policy.deadline, policy.max_output)?;
    Ok(Output {
        code: status.code(),
        stdout,
        stderr,
    })
}

/// Spawns `cmd` with a cleared environment, `/` as its working directory and
/// piped standard streams; feeds it `input`; kills it at `deadline` or when
/// stdout or stderr exceeds `max_output`. Shared by both brokers.
pub(crate) fn supervise(
    mut cmd: Command,
    input: &[u8],
    deadline: Duration,
    max_output: usize,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), BrokerError> {
    cmd.env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(BrokerError::Spawn)?;

    let stdin = child.stdin.take();
    let data = input.to_vec();
    let writer = thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            // A program that exits without reading closes the pipe: fine.
            let _written = stdin.write_all(&data).is_ok();
        }
    });
    let limit = max_output;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_reader = thread::spawn(move || stdout.map(|s| read_capped(s, limit)));
    let err_reader = thread::spawn(move || stderr.map(|s| read_capped(s, limit)));

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= deadline => {
                kill(&mut child);
                return Err(BrokerError::Deadline);
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                kill(&mut child);
                return Err(BrokerError::Io(e));
            }
        }
    };
    let _done = writer.join().is_ok();
    let collect = |r: thread::JoinHandle<Option<Captured>>| match r.join() {
        Ok(Some(Ok(pair))) => Ok(pair),
        Ok(Some(Err(e))) => Err(BrokerError::Io(e)),
        Ok(None) => Ok((Vec::new(), false)),
        Err(_) => Err(BrokerError::Io(std::io::Error::other(
            "reader thread failed",
        ))),
    };
    let (stdout, out_over) = collect(out_reader)?;
    let (stderr, err_over) = collect(err_reader)?;
    if out_over || err_over {
        return Err(BrokerError::OutputQuota);
    }
    Ok((status, stdout, stderr))
}
