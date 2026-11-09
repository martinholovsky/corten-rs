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
    // Phase 6, strategy 15 (aids, no bucket moves): dead code (CWE-561) and
    // a deprecated API (CWE-477). `unused_assignments` (CWE-563) was tried
    // and dropped: it rejected corpus/CWE-482/good.rs, a benign dead store.
    "dead_code",
    "deprecated",
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
    // Phase 6, strategy 15 (aids, no bucket moves): operator precedence
    // (CWE-783), exact float comparison (CWE-1077), debug and placeholder
    // code (CWE-489), expressions that are always true or false (CWE-570,
    // 571) and a short-circuit operator used as control flow (CWE-768).
    "clippy::precedence",
    "clippy::float_cmp",
    "clippy::float_cmp_const",
    "clippy::dbg_macro",
    "clippy::todo",
    "clippy::unimplemented",
    "clippy::eq_op",
    "clippy::absurd_extreme_comparisons",
    "clippy::impossible_comparisons",
    "clippy::redundant_comparisons",
    "clippy::overly_complex_bool_expr",
    "clippy::nonminimal_bool",
    "clippy::short_circuit_statement",
];

/// Corten's own lints, run by `corten-driver` in a second pass (Phase 3b
/// trial, spec section 8 question 10). Each backs a ledger row: must-use on
/// every return (CWE-252), labelled parameters (CWE-683), public interior-
/// mutable statics (CWE-493, 500, 607), `unsafe` from a dependency's macro
/// (the Phase 1 bypass), direct `from_template` calls (the Phase 2 gap),
/// blocking inside async (CWE-1322) and Rc/Arc cycles of types with a
/// destructor (CWE-1091).
pub const FORBIDDEN_CORTEN_LINTS: &[&str] = &[
    "corten_must_use_return",
    "corten_labelled_params",
    "corten_pub_interior_mut_static",
    "corten_unsafe_from_macro",
    "corten_direct_template",
    "corten_blocking_in_async",
    "corten_rc_cycle",
    "corten_secret_literal",
];

/// The `clippy.toml` the checker writes and points `CLIPPY_CONF_DIR` at.
pub const CLIPPY_TOML: &str = r#"# Written by cargo corten check. The checked repository's clippy.toml is not read.

disallowed-methods = [
    # Filesystem: only through a DirCap (spec 4.4).
    { path = "std::fs::canonicalize", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::copy", reason = "copies a file and its mode outside a DirCap (CWE-689); fix: read and write through a DirCap" },
    { path = "std::fs::create_dir", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::fs::create_dir_all", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::fs::exists", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::hard_link", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::metadata", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::read", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::read_dir", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::read_link", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::read_to_string", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::remove_dir", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::remove_dir_all", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::remove_file", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::rename", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::set_permissions", reason = "changes a file's mode (CWE-276); fix: create it with OpenMode::CreateExclusive(FileMode) through a DirCap" },
    { path = "std::fs::soft_link", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::symlink_metadata", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::write", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::fs::File::open", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::File::create", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::fs::File::create_new", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::fs::OpenOptions::open", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::os::unix::fs::chown", reason = "assigns an owner (CWE-708); the prelude has no ownership API: ownership is deployment configuration" },
    { path = "std::os::unix::fs::chroot", reason = "ambient privilege operation (CWE-243); fix: confine the program with corten-sandbox and a manifest" },
    { path = "std::os::unix::fs::fchown", reason = "assigns an owner (CWE-708); the prelude has no ownership API: ownership is deployment configuration" },
    { path = "std::os::unix::fs::lchown", reason = "assigns an owner (CWE-708); the prelude has no ownership API: ownership is deployment configuration" },
    { path = "std::os::unix::fs::symlink", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::canonicalize", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::exists", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::is_dir", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::is_file", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::is_symlink", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::metadata", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::read_dir", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::read_link", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::symlink_metadata", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::path::Path::try_exists", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    # Environment and configuration (spec 4.3; amendment: no ambient configuration).
    { path = "std::env::args", reason = "ambient configuration (CWE-15, CWE-73); fix: take configuration from the signed manifest, Capabilities::load" },
    { path = "std::env::args_os", reason = "ambient configuration (CWE-15, CWE-73); fix: take configuration from the signed manifest, Capabilities::load" },
    { path = "std::env::current_dir", reason = "ambient environment (spec 4.3; no ledger row); fix: name files through a DirCap, configuration through the manifest" },
    { path = "std::env::current_exe", reason = "ambient environment (spec 4.3; no ledger row); fix: name files through a DirCap, configuration through the manifest" },
    { path = "std::env::home_dir", reason = "ambient environment (spec 4.3; no ledger row); fix: name files through a DirCap, configuration through the manifest" },
    { path = "std::env::remove_var", reason = "ambient environment (spec 4.3; no ledger row); fix: name files through a DirCap, configuration through the manifest" },
    { path = "std::env::set_current_dir", reason = "ambient environment (spec 4.3; no ledger row); fix: name files through a DirCap, configuration through the manifest" },
    { path = "std::env::set_var", reason = "ambient environment (spec 4.3; no ledger row); fix: name files through a DirCap, configuration through the manifest" },
    { path = "std::env::temp_dir", reason = "a shared, predictable temporary directory (CWE-378); fix: DirCap::create_temp" },
    { path = "std::env::var", reason = "ambient configuration (CWE-15, CWE-73); fix: take configuration from the signed manifest, Capabilities::load" },
    { path = "std::env::var_os", reason = "ambient configuration (CWE-15, CWE-73); fix: take configuration from the signed manifest, Capabilities::load" },
    { path = "std::env::vars", reason = "ambient configuration (CWE-15, CWE-73); fix: take configuration from the signed manifest, Capabilities::load" },
    { path = "std::env::vars_os", reason = "ambient configuration (CWE-15, CWE-73); fix: take configuration from the signed manifest, Capabilities::load" },
    # Processes (spec 4.4, 4.5): no PATH search, no ambient spawn.
    { path = "std::process::Command::new", reason = "ambient process authority with a PATH search (CWE-78); fix: process! with an ExecCap from the manifest" },
    # Network (spec 4.3).
    { path = "std::net::TcpListener::bind", reason = "ambient network authority (CWE-918); corten-std has no listening capability yet" },
    { path = "std::net::TcpStream::connect", reason = "ambient network authority (CWE-918); fix: a NetCap granted in the manifest, NetCap::connect_tls" },
    { path = "std::net::TcpStream::connect_timeout", reason = "ambient network authority (CWE-918); fix: a NetCap granted in the manifest, NetCap::connect_tls" },
    { path = "std::net::UdpSocket::bind", reason = "unencrypted datagrams outside any grant (CWE-319); corten-std has no UDP capability" },
    { path = "std::net::ToSocketAddrs::to_socket_addrs", reason = "ambient DNS resolution (CWE-918); fix: NetCap resolves the names the manifest grants" },
    # Clock (spec 4.3).
    { path = "std::time::SystemTime::now", reason = "ambient clock (spec 4.3; no ledger row); corten-std has no clock capability yet" },
    { path = "std::time::Instant::now", reason = "ambient clock (spec 4.3; no ledger row); corten-std has no clock capability yet" },
    # Errors (spec 4.7): no catch-all handler.
    { path = "std::panic::catch_unwind", reason = "catch-all handler (CWE-396); fix: let corten-runtime's supervisor restart the component" },
    { path = "std::thread::JoinHandle::join", reason = "returns a panic as a value, a catch-all handler (CWE-396); fix: corten_std::thread::spawn" },
    { path = "std::thread::ScopedJoinHandle::join", reason = "returns a panic as a value, a catch-all handler (CWE-396); fix: corten_std::thread::spawn, or let the scope propagate the panic" },
    # Destructors (spec 4.1): nothing skips one.
    { path = "std::boxed::Box::leak", reason = "skips the destructor (CWE-1091); fix: let the value drop at the end of its owner" },
    { path = "std::vec::Vec::leak", reason = "skips the destructor (CWE-1091); fix: let the value drop at the end of its owner" },
    { path = "std::string::String::leak", reason = "skips the destructor (CWE-1091); fix: let the value drop at the end of its owner" },
    { path = "std::mem::ManuallyDrop::new", reason = "skips the destructor (CWE-1091); fix: let the value drop at the end of its owner" },
]

disallowed-types = [
    { path = "std::fs::File", reason = "ambient filesystem access (CWE-22, path traversal); fix: take a DirCap from the manifest and use DirCap::open_file or open_dir" },
    { path = "std::fs::OpenOptions", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::fs::DirBuilder", reason = "ambient file creation (CWE-22, path traversal; CWE-276, default permissions); fix: DirCap::open_file with OpenMode::CreateExclusive(FileMode)" },
    { path = "std::os::unix::net::UnixDatagram", reason = "ambient IPC (spec 4.3; no ledger row); corten-std has no Unix-socket capability yet" },
    { path = "std::os::unix::net::UnixListener", reason = "ambient IPC (spec 4.3; no ledger row); corten-std has no Unix-socket capability yet" },
    { path = "std::os::unix::net::UnixStream", reason = "ambient IPC (spec 4.3; no ledger row); corten-std has no Unix-socket capability yet" },
    { path = "std::process::Command", reason = "ambient process authority with a PATH search (CWE-78); fix: process! with an ExecCap from the manifest" },
    { path = "std::net::TcpListener", reason = "ambient network authority (CWE-918); corten-std has no listening capability yet" },
    { path = "std::net::TcpStream", reason = "ambient network authority (CWE-918); fix: a NetCap granted in the manifest, NetCap::connect_tls" },
    { path = "std::net::UdpSocket", reason = "unencrypted datagrams outside any grant (CWE-319); corten-std has no UDP capability" },
    { path = "std::mem::ManuallyDrop", reason = "skips the destructor (CWE-1091); fix: let the value drop at the end of its owner" },
]
"#;
