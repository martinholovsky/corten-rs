//! Corten's brokers (spec 4.14; Phase 3): foreign or untrusted code runs
//! outside the application's address space, with declared capabilities,
//! quotas and deadlines.
//!
//! - [`process`]: a [`corten_std::process::ProcessInvocation`] run under
//!   `corten-sandbox` (Landlock), with a deadline and input and output
//!   quotas; the environment is cleared.
//! - [`wasm`]: a Wasm module run on `wasmi` with no imports, fuel and a
//!   memory limit.
//! - [`ipc`]: length-prefixed, size-checked, decoded frames.
//!
//! This crate is part of Corten's trusted base. Unlike `corten-std`, it
//! spawns processes with `std::process::Command`, which the profile bans in
//! application code, so it is not built under `cargo corten check`.

pub mod ipc;
pub mod process;
pub mod wasm;
