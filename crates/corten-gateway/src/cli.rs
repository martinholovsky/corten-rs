//! The `corten-gateway` command line. Exit codes: 0 success, 1 failure,
//! 2 usage error. Data (a public key, a summary) goes to standard output;
//! logs and errors go to standard error.
//!
//! Signals: the gateway keeps no state on disk that an interrupted run could
//! corrupt (sessions live in memory, key files are created with
//! `create_new`), so it relies on the default handling of SIGINT and SIGTERM
//! and exits at once (crash-only).

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use corten_std::log::{LogRecord, LogWriter};

use crate::client::Https;
use crate::config::{self, Config, DEFAULT_KID};
use crate::flow::ClientKey;
use crate::mint::Minter;
use crate::server::{self, Gateway, Settings};

/// The usage text, printed by `--help` and after a usage error.
pub const USAGE: &str = "\
corten-gateway: phishing-resistant sign-in in front of a Corten program

Usage:
  corten-gateway serve --config FILE
  corten-gateway check --config FILE
  corten-gateway keygen-client --out FILE [--kid ID]
  corten-gateway --help | --version

Commands:
  serve          Serve HTTPS: sign-in through the identity provider, sessions,
                 and every other request forwarded to the program's Unix socket
                 with a fresh Corten token.
  check          Read the configuration and every file it names (TLS, client
                 and minting keys) and print a summary; contacts no network.
  keygen-client  Create the P-256 key for private_key_jwt client
                 authentication (mode 0600, never overwriting a file) and print
                 its public JWK to register at the identity provider.

Options:
  --config FILE  The configuration file (docs/gates/gateway-proposal.md).
  --out FILE     Where keygen-client writes the key.
  --kid ID       The key identifier to register (default: corten-gateway-1);
                 a different one must also be set as client-key-id.

Exit codes: 0 success, 1 failure, 2 usage error.
";

const EXIT_FAILURE: u8 = 1;
const EXIT_USAGE: u8 = 2;
const MAX_KEY: u64 = 4096;

/// Writes log records to standard error, one per line.
struct Stderr;

impl LogWriter for Stderr {
    fn write(&mut self, record: &LogRecord) {
        let _ignored = writeln!(std::io::stderr(), "{}", record.render());
    }
}

enum Command {
    Help,
    Version,
    Serve(PathBuf),
    Check(PathBuf),
    Keygen { out: PathBuf, kid: String },
}

fn parse(args: &[OsString]) -> Result<Command, String> {
    let mut it = args
        .iter()
        .map(|a| a.to_str().ok_or("arguments must be UTF-8"));
    let first = it.next().transpose()?.ok_or("no command given")?;
    let mut flags: Vec<(&str, &str)> = Vec::new();
    match first {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" => return Ok(Command::Version),
        _ => {}
    }
    while let Some(flag) = it.next().transpose()? {
        let value = it
            .next()
            .transpose()?
            .ok_or(format!("{flag} needs a value"))?;
        if flags.iter().any(|(f, _)| *f == flag) {
            return Err(format!("{flag} given twice"));
        }
        flags.push((flag, value));
    }
    let take = |name: &str| flags.iter().find(|(f, _)| *f == name).map(|(_, v)| *v);
    let only = |allowed: &[&str]| -> Result<(), String> {
        match flags.iter().find(|(f, _)| !allowed.contains(f)) {
            Some((f, _)) => Err(format!("unknown option {f} for {first}")),
            None => Ok(()),
        }
    };
    match first {
        "serve" | "check" => {
            only(&["--config"])?;
            let path = PathBuf::from(take("--config").ok_or("--config is required")?);
            Ok(if first == "serve" {
                Command::Serve(path)
            } else {
                Command::Check(path)
            })
        }
        "keygen-client" => {
            only(&["--out", "--kid"])?;
            let kid = take("--kid").unwrap_or(DEFAULT_KID);
            if !corten_std::authz::token_field(kid) {
                return Err(format!(
                    "--kid {kid:?}: use [A-Za-z0-9_-], 1 to 64 characters"
                ));
            }
            Ok(Command::Keygen {
                out: PathBuf::from(take("--out").ok_or("--out is required")?),
                kid: kid.to_owned(),
            })
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

/// Runs the command line `args` (without the program name).
#[must_use]
pub fn run(args: &[OsString]) -> ExitCode {
    let command = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            let _ignored = write!(std::io::stderr(), "corten-gateway: {e}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let result = match command {
        Command::Help => {
            let _ignored = write!(std::io::stdout(), "{USAGE}");
            Ok(())
        }
        Command::Version => {
            let _ignored = writeln!(
                std::io::stdout(),
                "corten-gateway {}",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Command::Keygen { out, kid } => keygen(&out, &kid),
        Command::Check(path) => check(&path),
        Command::Serve(path) => serve(&path),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ignored = writeln!(std::io::stderr(), "corten-gateway: {e}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn keygen(out: &Path, kid: &str) -> Result<(), String> {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use std::os::unix::fs::OpenOptionsExt as _;
    let doc = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &aws_lc_rs::rand::SystemRandom::new(),
    )
    .map_err(|_| "could not generate a key".to_owned())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "{} already exists; a key is never overwritten (choose another --out, or remove the old key once the provider no longer accepts it)",
                out.display()
            ),
            _ => format!("{}: {e}", out.display()),
        })?;
    file.write_all(doc.as_ref())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{}: {e}", out.display()))?;
    let key = load_client_key(out, kid)?;
    let _ignored = writeln!(std::io::stdout(), "{}", key.public_jwk());
    Ok(())
}

fn load_client_key(path: &Path, kid: &str) -> Result<ClientKey, String> {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    let der = crate::keyfile::read_private(path, MAX_KEY)?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
        .map_err(|_| format!("{} is not a P-256 PKCS#8 key", path.display()))?;
    Ok(ClientKey {
        kid: kid.to_owned(),
        key,
    })
}

struct Loaded {
    config: Config,
    client_key: ClientKey,
    minter: Minter,
    tls: tokio_rustls::TlsAcceptor,
}

fn load(path: &Path) -> Result<Loaded, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config = config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let client_key = load_client_key(&config.client_key, &config.client_key_id)?;
    let minter =
        Minter::from_key_file(&config.mint_key, &config.authn_name, config.token_lifetime)?;
    let tls = server::tls_acceptor(&config.tls_cert, &config.tls_key)?;
    Ok(Loaded {
        config,
        client_key,
        minter,
        tls,
    })
}

fn check(path: &Path) -> Result<(), String> {
    let l = load(path)?;
    let c = &l.config;
    let _ignored = writeln!(
        std::io::stdout(),
        "configuration valid\norigin {}\nlisten {}\nissuer {}\nclient-id {}\nclient-key-id {}\nupstream {}\nprogram manifest line: authn {} token {}",
        c.public.origin,
        c.listen,
        c.issuer,
        c.client_id,
        l.client_key.kid,
        c.upstream.display(),
        c.authn_name,
        l.minter.manifest_entry()
    );
    Ok(())
}

fn serve(path: &Path) -> Result<(), String> {
    let l = load(path)?;
    let c = l.config;
    let settings = Settings {
        public: c.public,
        issuer: c.issuer,
        client_id: c.client_id,
        acr: c.acr,
        algorithms: c.algorithms,
        upstream: c.upstream,
        sessions: c.sessions,
        login_burst: c.login_burst,
        login_refill: c.login_refill,
        upstream_timeout: c.upstream_timeout,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let gateway = Arc::new(Gateway::new(
            settings,
            l.client_key,
            l.minter,
            Https::platform()?,
            Box::new(Stderr),
        ));
        let listener = tokio::net::TcpListener::bind(c.listen)
            .await
            .map_err(|e| format!("{}: {e}", c.listen))?;
        // Sign-in answers 503 until the provider is loaded; keep trying.
        let loader = Arc::clone(&gateway);
        let _loading = tokio::spawn(async move {
            while let Err(e) = loader.load_provider().await {
                let _ignored = writeln!(
                    std::io::stderr(),
                    "corten-gateway: provider not loaded: {e}; retrying in 30 s"
                );
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        gateway.serve(listener, l.tls).await;
        Ok(())
    })
}
