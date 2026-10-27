//! Records where the pinned nightly's `librustc_driver` lives, so the driver
//! starts without `LD_LIBRARY_PATH`. The binary is tied to that toolchain
//! installation; rebuild it after reinstalling the toolchain.

use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let out = match Command::new(&rustc).args(["--print", "sysroot"]).output() {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            println!(
                "cargo::error={rustc} --print sysroot failed: {}",
                out.status
            );
            return;
        }
        Err(e) => {
            println!("cargo::error=cannot run {rustc}: {e}");
            return;
        }
    };
    let sysroot = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    println!("cargo::rustc-link-arg-bins=-Wl,-rpath,{sysroot}/lib");
    println!("cargo::rerun-if-env-changed=RUSTC");
}
