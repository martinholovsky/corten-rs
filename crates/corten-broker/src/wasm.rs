//! The Wasm broker (spec 4.14; owner decision 12: `wasmi`).
//!
//! A module runs in a separate process: `corten-wasm-runner`, started under
//! `corten-sandbox` (Landlock) with no filesystem grant beyond the system
//! directories and the runner itself, no network, a cleared environment, a
//! deadline and an output quota. The module never shares an address space
//! with the caller, so its isolation from the caller's secrets does not rest
//! on `wasmi`'s bounds checks alone, which speculative execution can bypass
//! (CWE-1420; MITRE's mitigation is a separate process). As with the process
//! broker, this needs Linux; elsewhere the sandbox refuses to start and every
//! run fails.
//!
//! Inside the runner, the module gets **no imports**: no host function, so
//! no file, network, clock or randomness, and a module that asks for any
//! import fails to instantiate. CPU is bounded by fuel, memory by a store
//! limiter, and the output by a size limit.
//!
//! Module ABI: it exports `memory`, `alloc(len: i32) -> i32` returning a
//! buffer for the input, and `run(ptr: i32, len: i32) -> i64` returning the
//! output as `ptr << 32 | len`.
//!
//! Wire protocol (one [`Request`] frame on the runner's stdin, one
//! [`Response`] frame on its stdout) uses [`crate::ipc`].

use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::ipc::{self, IpcError, Message};
use crate::process::{BrokerError, supervise};

/// What the broker grants a module.
#[derive(Debug, Clone)]
pub struct WasmPolicy {
    /// The `corten-sandbox` binary.
    pub sandbox: PathBuf,
    /// The `corten-wasm-runner` binary.
    pub runner: PathBuf,
    /// Kill the runner after this long, whatever fuel is left.
    pub deadline: Duration,
    /// Fuel: roughly, instructions executed.
    pub fuel: u64,
    /// Largest linear memory, in bytes.
    pub max_memory: usize,
    /// Largest output, in bytes.
    pub max_output: usize,
}

/// Why a module run failed.
#[derive(Debug)]
pub enum WasmError {
    /// The module does not parse or validate.
    Invalid(String),
    /// The module asked for imports; the broker grants none.
    Instantiate(String),
    /// The module lacks the ABI exports.
    Abi(String),
    /// A trap: out of fuel, memory limit, unreachable, out of bounds.
    Trap(String),
    /// The output is larger than the policy allows, or out of bounds.
    Output,
    /// The runner could not be started, ran past its deadline, wrote too
    /// much, or the request exceeded [`MAX_REQUEST`].
    Broker(BrokerError),
    /// The runner ended without a well-formed result (for example, it
    /// crashed).
    Runner(String),
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid module: {e}"),
            Self::Instantiate(e) => write!(f, "module refused: {e}"),
            Self::Abi(what) => write!(f, "module does not follow the broker ABI: {what}"),
            Self::Trap(e) => write!(f, "module trapped: {e}"),
            Self::Output => f.write_str("module output exceeds the policy or its memory"),
            Self::Broker(e) => write!(f, "Wasm runner: {e}"),
            Self::Runner(e) => write!(f, "Wasm runner failed: {e}"),
        }
    }
}

impl std::error::Error for WasmError {}

/// Largest request frame (module plus input plus 32 bytes of header).
pub const MAX_REQUEST: u32 = 64 * 1024 * 1024;

/// Longest error message the runner sends; longer ones are cut.
pub const MAX_MESSAGE: usize = 1024;

/// Bytes a response may carry beyond the output: frame length, tag, and an
/// error message in place of the output.
const RESPONSE_OVERHEAD: usize = 4 + 1 + MAX_MESSAGE;

/// Runs `module` on `input` under `policy`, in `corten-wasm-runner` under
/// `corten-sandbox`.
///
/// # Errors
///
/// [`WasmError`] for an invalid module, any import, a missing export, a trap
/// (including running out of fuel or memory), oversized output, a runner
/// that cannot start or is killed (deadline, output quota), or a runner that
/// ends without a result.
pub fn run(module: &[u8], input: &[u8], policy: &WasmPolicy) -> Result<Vec<u8>, WasmError> {
    let request = Request {
        fuel: policy.fuel,
        max_memory: u64::try_from(policy.max_memory).unwrap_or(u64::MAX),
        max_output: u64::try_from(policy.max_output).unwrap_or(u64::MAX),
        module: module.to_vec(),
        input: input.to_vec(),
    };
    let mut frame = Vec::new();
    ipc::write_message(&mut frame, &request).map_err(|e| match e {
        IpcError::TooLarge(_) => WasmError::Broker(BrokerError::InputQuota),
        other => WasmError::Runner(other.to_string()),
    })?;
    let mut cmd = Command::new(&policy.sandbox);
    cmd.arg("--system")
        .arg("--exec")
        .arg(&policy.runner)
        .arg("--")
        .arg(&policy.runner);
    let cap = policy.max_output.saturating_add(RESPONSE_OVERHEAD);
    let (status, stdout, stderr) =
        supervise(cmd, &frame, policy.deadline, cap).map_err(WasmError::Broker)?;
    let mut rest = stdout.as_slice();
    match ipc::read_message::<Response>(&mut rest) {
        Ok(Response(result)) if rest.is_empty() => result,
        Ok(_) => Err(WasmError::Runner("bytes after the result".to_owned())),
        Err(e) => {
            let stderr = String::from_utf8_lossy(&stderr);
            Err(WasmError::Runner(format!(
                "{status}, no result ({e}): {}",
                stderr.trim()
            )))
        }
    }
}

/// The broker's request to the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Fuel for the run.
    pub fuel: u64,
    /// Largest linear memory, in bytes.
    pub max_memory: u64,
    /// Largest output, in bytes.
    pub max_output: u64,
    /// The module's bytes.
    pub module: Vec<u8>,
    /// The input handed to the module's `run`.
    pub input: Vec<u8>,
}

fn take_u64(bytes: &[u8]) -> Result<(u64, &[u8]), IpcError> {
    let (head, rest) = bytes
        .split_first_chunk::<8>()
        .ok_or(IpcError::Decode("truncated request header"))?;
    Ok((u64::from_be_bytes(*head), rest))
}

impl Message for Request {
    const MAX_LEN: u32 = MAX_REQUEST;

    fn encode(&self) -> Vec<u8> {
        let module_len = u64::try_from(self.module.len()).unwrap_or(u64::MAX);
        let mut out = Vec::with_capacity(
            32usize
                .saturating_add(self.module.len())
                .saturating_add(self.input.len()),
        );
        out.extend_from_slice(&self.fuel.to_be_bytes());
        out.extend_from_slice(&self.max_memory.to_be_bytes());
        out.extend_from_slice(&self.max_output.to_be_bytes());
        out.extend_from_slice(&module_len.to_be_bytes());
        out.extend_from_slice(&self.module);
        out.extend_from_slice(&self.input);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, IpcError> {
        let (fuel, rest) = take_u64(bytes)?;
        let (max_memory, rest) = take_u64(rest)?;
        let (max_output, rest) = take_u64(rest)?;
        let (module_len, rest) = take_u64(rest)?;
        let module_len =
            usize::try_from(module_len).map_err(|_| IpcError::Decode("module length"))?;
        let (module, input) = rest
            .split_at_checked(module_len)
            .ok_or(IpcError::Decode("module length beyond the frame"))?;
        Ok(Self {
            fuel,
            max_memory,
            max_output,
            module: module.to_vec(),
            input: input.to_vec(),
        })
    }
}

/// The runner's answer: the module's output, or why there is none.
#[derive(Debug)]
pub struct Response(pub Result<Vec<u8>, WasmError>);

const TAG_OK: u8 = 0;
const TAG_INVALID: u8 = 1;
const TAG_INSTANTIATE: u8 = 2;
const TAG_ABI: u8 = 3;
const TAG_TRAP: u8 = 4;
const TAG_OUTPUT: u8 = 5;

/// `text`, cut to at most [`MAX_MESSAGE`] bytes on a character boundary.
fn cut(text: &str) -> &[u8] {
    let mut end = text.len().min(MAX_MESSAGE);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.as_bytes().get(..end).unwrap_or_default()
}

impl Message for Response {
    const MAX_LEN: u32 = MAX_REQUEST;

    fn encode(&self) -> Vec<u8> {
        let (tag, body): (u8, &[u8]) = match &self.0 {
            Ok(out) => (TAG_OK, out),
            Err(WasmError::Invalid(m)) => (TAG_INVALID, cut(m)),
            Err(WasmError::Instantiate(m)) => (TAG_INSTANTIATE, cut(m)),
            Err(WasmError::Abi(m)) => (TAG_ABI, cut(m)),
            Err(WasmError::Trap(m)) => (TAG_TRAP, cut(m)),
            // The runner produces only the variants above; the broker's own
            // errors never cross the wire, so they encode as an output error.
            Err(WasmError::Output | WasmError::Broker(_) | WasmError::Runner(_)) => {
                (TAG_OUTPUT, &[])
            }
        };
        let mut out = Vec::with_capacity(body.len().saturating_add(1));
        out.push(tag);
        out.extend_from_slice(body);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, IpcError> {
        let (&tag, body) = bytes.split_first().ok_or(IpcError::Decode("empty"))?;
        let text = || {
            if body.len() > MAX_MESSAGE {
                return Err(IpcError::Decode("message too long"));
            }
            String::from_utf8(body.to_vec()).map_err(|_| IpcError::Decode("message not UTF-8"))
        };
        Ok(Self(match tag {
            TAG_OK => Ok(body.to_vec()),
            TAG_INVALID => Err(WasmError::Invalid(text()?)),
            TAG_INSTANTIATE => Err(WasmError::Instantiate(text()?)),
            TAG_ABI => Err(WasmError::Abi(text()?)),
            TAG_TRAP => Err(WasmError::Trap(text()?)),
            TAG_OUTPUT if body.is_empty() => Err(WasmError::Output),
            _ => return Err(IpcError::Decode("unknown result tag")),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = Request {
            fuel: 7,
            max_memory: 65_536,
            max_output: 9,
            module: b"\0asm".to_vec(),
            input: b"in".to_vec(),
        };
        assert_eq!(Request::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn a_module_length_past_the_frame_is_refused() {
        let mut bytes = Request {
            fuel: 1,
            max_memory: 1,
            max_output: 1,
            module: Vec::new(),
            input: Vec::new(),
        }
        .encode();
        bytes.truncate(24);
        bytes.extend_from_slice(&5u64.to_be_bytes());
        bytes.extend_from_slice(b"abc");
        assert!(matches!(Request::decode(&bytes), Err(IpcError::Decode(_))));
    }

    #[test]
    fn responses_round_trip_and_unknown_tags_are_refused() {
        let ok = Response(Ok(b"out".to_vec())).encode();
        assert!(matches!(Response::decode(&ok), Ok(Response(Ok(v))) if v == b"out"));
        let trap = Response(Err(WasmError::Trap("fuel".to_owned()))).encode();
        assert!(matches!(
            Response::decode(&trap),
            Ok(Response(Err(WasmError::Trap(m)))) if m == "fuel"
        ));
        assert!(matches!(
            Response::decode(&[9, 1]),
            Err(IpcError::Decode(_))
        ));
        assert!(matches!(Response::decode(&[]), Err(IpcError::Decode(_))));
    }

    #[test]
    fn long_messages_are_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_MESSAGE);
        let cut = cut(&long);
        assert!(cut.len() <= MAX_MESSAGE);
        assert!(std::str::from_utf8(cut).is_ok());
    }
}
