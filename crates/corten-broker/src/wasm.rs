//! The Wasm broker (spec 4.14; owner decision 12: `wasmi`).
//!
//! A module runs with **no imports**: it gets no host function, so no file,
//! network, clock or randomness, and a module that asks for any import fails
//! to instantiate. CPU is bounded by fuel, memory by a store limiter, and the
//! output by a size limit.
//!
//! Module ABI: it exports `memory`, `alloc(len: i32) -> i32` returning a
//! buffer for the input, and `run(ptr: i32, len: i32) -> i64` returning the
//! output as `ptr << 32 | len`.

use std::fmt;

use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// What the broker grants a module.
#[derive(Debug, Clone, Copy)]
pub struct WasmPolicy {
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
    Abi(&'static str),
    /// A trap: out of fuel, memory limit, unreachable, out of bounds.
    Trap(String),
    /// The output is larger than the policy allows, or out of bounds.
    Output,
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid module: {e}"),
            Self::Instantiate(e) => write!(f, "module refused: {e}"),
            Self::Abi(what) => write!(f, "module does not follow the broker ABI: {what}"),
            Self::Trap(e) => write!(f, "module trapped: {e}"),
            Self::Output => f.write_str("module output exceeds the policy or its memory"),
        }
    }
}

impl std::error::Error for WasmError {}

/// Native stack for the interpreter thread. An unoptimised build of the
/// interpreter overflowed a default 2 MiB test-thread stack on a tight loop
/// (measured); an overflow aborts the whole host process, which no
/// supervisor can contain.
pub const INTERPRETER_STACK: usize = 32 * 1024 * 1024;

/// Wasm call depth allowed before a trap.
pub const MAX_RECURSION: usize = 1024;

/// Runs `module` on `input` under `policy`, on a dedicated thread with
/// [`INTERPRETER_STACK`] bytes of native stack.
///
/// # Errors
///
/// [`WasmError`] for an invalid module, any import, a missing export, a trap
/// (including running out of fuel or memory), or oversized output.
pub fn run(module: &[u8], input: &[u8], policy: &WasmPolicy) -> Result<Vec<u8>, WasmError> {
    let (module, input, policy) = (module.to_vec(), input.to_vec(), *policy);
    std::thread::Builder::new()
        .name("corten-wasm".to_owned())
        .stack_size(INTERPRETER_STACK)
        .spawn(move || run_here(&module, &input, &policy))
        .map_err(|e| WasmError::Trap(format!("cannot start the interpreter thread: {e}")))?
        .join()
        .map_err(|_| WasmError::Trap("the interpreter thread panicked".to_owned()))?
}

fn run_here(module: &[u8], input: &[u8], policy: &WasmPolicy) -> Result<Vec<u8>, WasmError> {
    let mut config = Config::default();
    config.consume_fuel(true);
    config.set_max_recursion_depth(MAX_RECURSION);
    let engine = Engine::new(&config);
    let module = Module::new(&engine, module).map_err(|e| WasmError::Invalid(e.to_string()))?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(policy.max_memory)
        .instances(1)
        .memories(1)
        .tables(1)
        .build();
    let mut store: Store<StoreLimits> = Store::new(&engine, limits);
    store.limiter(|limits| limits);
    store
        .set_fuel(policy.fuel)
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    // An empty linker: no host function exists to import.
    let linker: Linker<StoreLimits> = Linker::new(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or(WasmError::Abi("no exported memory"))?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .map_err(|_| WasmError::Abi("no alloc(i32) -> i32"))?;
    let entry = instance
        .get_typed_func::<(i32, i32), i64>(&store, "run")
        .map_err(|_| WasmError::Abi("no run(i32, i32) -> i64"))?;
    let len = i32::try_from(input.len()).map_err(|_| WasmError::Output)?;
    let ptr = alloc
        .call(&mut store, len)
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    let at = usize::try_from(ptr).map_err(|_| WasmError::Abi("negative pointer"))?;
    memory
        .write(&mut store, at, input)
        .map_err(|_| WasmError::Abi("alloc returned an out-of-bounds buffer"))?;
    let packed = entry
        .call(&mut store, (ptr, len))
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    let packed = u64::from_ne_bytes(packed.to_ne_bytes());
    let out_ptr =
        usize::try_from(packed.checked_shr(32).unwrap_or(0)).map_err(|_| WasmError::Output)?;
    let out_len = usize::try_from(packed & 0xFFFF_FFFF).map_err(|_| WasmError::Output)?;
    if out_len > policy.max_output {
        return Err(WasmError::Output);
    }
    let mut out = vec![0u8; out_len];
    memory
        .read(&store, out_ptr, &mut out)
        .map_err(|_| WasmError::Output)?;
    Ok(out)
}
