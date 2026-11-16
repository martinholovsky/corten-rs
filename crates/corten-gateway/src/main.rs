//! `corten-gateway`: see `corten_gateway::cli` and
//! `docs/gates/gateway-proposal.md`.

fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    corten_gateway::cli::run(&args)
}
