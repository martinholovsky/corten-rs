//! The Corten profile as the checker applies it: compiler flags, forbidden
//! lints and the Clippy configuration. Nothing here is read from the checked
//! repository.
//!
//! The ambient-authority bans below are a denylist over `std`, so they can
//! miss an API. The closed prelude (`corten-std`) is the deny-by-default
//! answer; until application code is confined to it, the bypass hunt
//! (`docs/gates/phase-1.md`) records which `std` surfaces were checked.

/// rustc flags other than lint levels.
pub const CODEGEN_FLAGS: &[&str] = &[
    // Spec 4.2: integer arithmetic is checked in every build profile.
    "-C",
    "overflow-checks=on",
];

/// rustc lints set to `forbid`, so no in-source `allow` or `expect` can lower
/// them (an attempt is E0453).
pub const FORBIDDEN_RUSTC_LINTS: &[&str] = &[
    // Spec 4.14: no unsafe code or FFI in application crates.
    "unsafe_code",
    // Spec 4.7: discarding a must-use value is a compile error.
    "unused_must_use",
];

/// Clippy lints set to `forbid`. Plain rustc accepts and ignores `clippy::`
/// lint flags, so passing them to every crate does not break dependencies.
pub const FORBIDDEN_CLIPPY_LINTS: &[&str] = &[
    // Spec 4.3: no ambient authority; the lists are in CLIPPY_TOML.
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
    // Spec 4.2: checked arithmetic only, no implicit numeric casts.
    "clippy::arithmetic_side_effects",
    "clippy::as_conversions",
    // Spec 4.7: `let _ = must_use()` would bypass unused_must_use.
    "clippy::let_underscore_must_use",
    // Spec 4.1: no skipped destructors.
    "clippy::mem_forget",
];

/// The `clippy.toml` the checker writes and points `CLIPPY_CONF_DIR` at.
pub const CLIPPY_TOML: &str = r#"# Written by cargo corten check. The checked repository's clippy.toml is not read.

disallowed-methods = [
    # Filesystem: only through a DirCap (spec 4.4).
    { path = "std::fs::canonicalize", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::copy", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::create_dir", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::create_dir_all", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::exists", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::hard_link", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::metadata", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::read", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::read_dir", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::read_link", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::read_to_string", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::remove_dir", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::remove_dir_all", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::remove_file", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::rename", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::set_permissions", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::soft_link", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::symlink_metadata", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::write", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::File::open", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::File::create", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::File::create_new", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::OpenOptions::open", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::os::unix::fs::chown", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::os::unix::fs::chroot", reason = "ambient privilege operation" },
    { path = "std::os::unix::fs::lchown", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::os::unix::fs::symlink", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::canonicalize", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::exists", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::is_dir", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::is_file", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::is_symlink", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::metadata", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::read_dir", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::read_link", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::symlink_metadata", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::path::Path::try_exists", reason = "ambient filesystem access; use a DirCap" },
    # Environment and configuration (spec 4.3; amendment: no ambient configuration).
    { path = "std::env::args", reason = "ambient environment; take configuration from the manifest" },
    { path = "std::env::args_os", reason = "ambient environment; take configuration from the manifest" },
    { path = "std::env::current_dir", reason = "ambient environment" },
    { path = "std::env::current_exe", reason = "ambient environment" },
    { path = "std::env::home_dir", reason = "ambient environment" },
    { path = "std::env::remove_var", reason = "ambient environment" },
    { path = "std::env::set_current_dir", reason = "ambient environment" },
    { path = "std::env::set_var", reason = "ambient environment" },
    { path = "std::env::temp_dir", reason = "ambient environment; use DirCap::create_temp" },
    { path = "std::env::var", reason = "ambient environment; take configuration from the manifest" },
    { path = "std::env::var_os", reason = "ambient environment; take configuration from the manifest" },
    { path = "std::env::vars", reason = "ambient environment; take configuration from the manifest" },
    { path = "std::env::vars_os", reason = "ambient environment; take configuration from the manifest" },
    # Processes (spec 4.4, 4.5): no PATH search, no ambient spawn.
    { path = "std::process::Command::new", reason = "ambient process authority; use process! with an ExecCap" },
    # Network (spec 4.3).
    { path = "std::net::TcpListener::bind", reason = "ambient network authority" },
    { path = "std::net::TcpStream::connect", reason = "ambient network authority" },
    { path = "std::net::TcpStream::connect_timeout", reason = "ambient network authority" },
    { path = "std::net::UdpSocket::bind", reason = "ambient network authority" },
    { path = "std::net::ToSocketAddrs::to_socket_addrs", reason = "ambient DNS resolution" },
    # Clock (spec 4.3).
    { path = "std::time::SystemTime::now", reason = "ambient clock; use a clock capability" },
    { path = "std::time::Instant::now", reason = "ambient clock; use a clock capability" },
    # Errors (spec 4.7): no catch-all handler.
    { path = "std::panic::catch_unwind", reason = "catch-all handler; components are supervised instead" },
    # Destructors (spec 4.1): nothing skips one.
    { path = "std::boxed::Box::leak", reason = "skips the destructor" },
    { path = "std::vec::Vec::leak", reason = "skips the destructor" },
    { path = "std::string::String::leak", reason = "skips the destructor" },
    { path = "std::mem::ManuallyDrop::new", reason = "skips the destructor" },
]

disallowed-types = [
    { path = "std::fs::File", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::OpenOptions", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::fs::DirBuilder", reason = "ambient filesystem access; use a DirCap" },
    { path = "std::os::unix::net::UnixDatagram", reason = "ambient network authority" },
    { path = "std::os::unix::net::UnixListener", reason = "ambient network authority" },
    { path = "std::os::unix::net::UnixStream", reason = "ambient network authority" },
    { path = "std::process::Command", reason = "ambient process authority; use process!" },
    { path = "std::net::TcpListener", reason = "ambient network authority" },
    { path = "std::net::TcpStream", reason = "ambient network authority" },
    { path = "std::net::UdpSocket", reason = "ambient network authority" },
    { path = "std::mem::ManuallyDrop", reason = "skips the destructor" },
]
"#;
