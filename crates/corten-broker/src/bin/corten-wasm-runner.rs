//! `corten-wasm-runner`: runs one Wasm module for `corten_broker::wasm::run`.
//!
//! Reads one `corten_broker::wasm::Request` frame on stdin, runs the module
//! on `wasmi` with no imports, fuel and a memory limit, writes one
//! `Response` frame on stdout and exits. The broker starts it under
//! `corten-sandbox`; it is not meant to be run by hand. It is the only
//! place the interpreter runs, so the module never shares an address space
//! with the broker's caller.
//!
//! Exit status: 0 when a response was written (whatever it says), 2 when the
//! request could not be read, 1 when the response could not be written.

use std::io::Write;
use std::process::ExitCode;

use corten_broker::ipc::{read_message, write_message};
use corten_broker::wasm::{Request, Response, WasmError};
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Native stack for the interpreter thread. An unoptimised build of the
/// interpreter overflowed a default 2 MiB test-thread stack on a tight loop
/// (measured). An overflow aborts the runner, which the broker reports as
/// `WasmError::Runner`.
const INTERPRETER_STACK: usize = 32 * 1024 * 1024;

/// Wasm call depth allowed before a trap.
const MAX_RECURSION: usize = 1024;

fn main() -> ExitCode {
    let request = match read_message::<Request>(&mut std::io::stdin().lock()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("corten-wasm-runner: cannot read the request: {e}");
            return ExitCode::from(2);
        }
    };
    let result = std::thread::Builder::new()
        .name("corten-wasm".to_owned())
        .stack_size(INTERPRETER_STACK)
        .spawn(move || interpret(&request))
        .map_err(|e| WasmError::Trap(format!("cannot start the interpreter thread: {e}")))
        .and_then(|t| {
            t.join()
                .map_err(|_| WasmError::Trap("the interpreter thread panicked".to_owned()))?
        });
    let mut out = std::io::stdout().lock();
    match write_message(&mut out, &Response(result))
        .and_then(|()| out.flush().map_err(corten_broker::ipc::IpcError::Io))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("corten-wasm-runner: cannot write the response: {e}");
            ExitCode::FAILURE
        }
    }
}

fn interpret(request: &Request) -> Result<Vec<u8>, WasmError> {
    let max_memory = usize::try_from(request.max_memory).unwrap_or(usize::MAX);
    let max_output = usize::try_from(request.max_output).unwrap_or(usize::MAX);
    let mut config = Config::default();
    config.consume_fuel(true);
    config.set_max_recursion_depth(MAX_RECURSION);
    let engine = Engine::new(&config);
    let module =
        Module::new(&engine, &request.module).map_err(|e| WasmError::Invalid(e.to_string()))?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(max_memory)
        .instances(1)
        .memories(1)
        .tables(1)
        .build();
    let mut store: Store<StoreLimits> = Store::new(&engine, limits);
    store.limiter(|limits| limits);
    store
        .set_fuel(request.fuel)
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    // An empty linker: no host function exists to import.
    let linker: Linker<StoreLimits> = Linker::new(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;
    let abi = |what: &str| WasmError::Abi(what.to_owned());
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| abi("no exported memory"))?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .map_err(|_| abi("no alloc(i32) -> i32"))?;
    let entry = instance
        .get_typed_func::<(i32, i32), i64>(&store, "run")
        .map_err(|_| abi("no run(i32, i32) -> i64"))?;
    let len = i32::try_from(request.input.len()).map_err(|_| WasmError::Output)?;
    let ptr = alloc
        .call(&mut store, len)
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    let at = usize::try_from(ptr).map_err(|_| abi("negative pointer"))?;
    memory
        .write(&mut store, at, &request.input)
        .map_err(|_| abi("alloc returned an out-of-bounds buffer"))?;
    let packed = entry
        .call(&mut store, (ptr, len))
        .map_err(|e| WasmError::Trap(e.to_string()))?;
    let packed = u64::from_ne_bytes(packed.to_ne_bytes());
    let out_ptr =
        usize::try_from(packed.checked_shr(32).unwrap_or(0)).map_err(|_| WasmError::Output)?;
    let out_len = usize::try_from(packed & 0xFFFF_FFFF).map_err(|_| WasmError::Output)?;
    if out_len > max_output {
        return Err(WasmError::Output);
    }
    let mut out = vec![0u8; out_len];
    memory
        .read(&store, out_ptr, &mut out)
        .map_err(|_| WasmError::Output)?;
    Ok(out)
}
