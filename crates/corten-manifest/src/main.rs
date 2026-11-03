//! `corten-manifest`: the deployer's side of the signed capability manifest
//! (`corten_std::manifest`, format 3), so the header is never written by
//! hand (design principle 10; owner decisions of 2026-11-02).
//!
//! - `keygen --id ID --out FILE` creates an Ed25519 key file (mode 0600,
//!   never overwriting) and prints `ID=HEX`, the `corten-sandbox
//!   --trusted-key` argument.
//! - `sign --key FILE --grants FILE (--provenance FILE [--subject NAME] |
//!   --program FILE) [--valid-for DAYS] [--previous MANIFEST] --out FILE
//!   --signature FILE` writes the header in front of the grant lines and
//!   signs the result:
//!   - `serial` is the current Unix time, so no counter has to be kept; with
//!     `--previous`, a serial not above that manifest's is refused;
//!   - `not-after` is now plus `--valid-for` days: 90 by default, at most
//!     366;
//!   - `program sha256` is the build's digest from its provenance (the
//!     `cargo corten build --provenance` statement), or the digest of the
//!     program file itself.
//!
//!   The signed manifest is verified with `corten_std::manifest::verify`
//!   before it is written, so a malformed grant fails here, not at launch.
//!
//! The key file is refused if it is a symlink, readable or writable by group
//! or others, or not owned by `$HOME`'s owner.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargo_corten::json::Json;

const USAGE: &str = "\
Usage: corten-manifest keygen --id ID --out KEYFILE
       corten-manifest sign --key KEYFILE --grants FILE
                            (--provenance FILE [--subject NAME] | --program FILE)
                            [--valid-for DAYS] [--previous MANIFEST]
                            --out MANIFEST --signature SIGFILE

keygen prints ID=HEX, the corten-sandbox --trusted-key argument.
sign writes a format 3 manifest: key, serial (Unix time), not-after (now plus
DAYS, default 90, at most 366), program sha256, then the grant lines.";

const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const DAY: u64 = 86_400;
const DEFAULT_DAYS: u64 = 90;
const MAX_DAYS: u64 = 366;
const KEY_HEADER: &str = "corten-signing-key 1";
/// Largest provenance statement or grants file read, in bytes.
const MAX_TEXT: u64 = 16 * 1024 * 1024;
/// Largest program hashed, in bytes (as `corten-sandbox`).
const MAX_PROGRAM: u64 = 1 << 30;
/// Lines the tool writes itself; a grants file may not contain them.
const RESERVED: &[&str] = &[
    "corten-manifest",
    "key ",
    "serial ",
    "not-after ",
    "program ",
];

#[derive(Debug, PartialEq, Eq)]
enum ProgramSource {
    File(PathBuf),
    Provenance {
        file: PathBuf,
        subject: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct SignArgs {
    key: PathBuf,
    grants: PathBuf,
    program: ProgramSource,
    days: u64,
    previous: Option<PathBuf>,
    out: PathBuf,
    signature: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Keygen { id: String, out: PathBuf },
    Sign(SignArgs),
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let sub = args.next().ok_or("missing command: keygen or sign")?;
    let mut flags: Vec<(String, OsString)> = Vec::new();
    while let Some(flag) = args.next() {
        let flag = flag
            .into_string()
            .map_err(|f| format!("unexpected argument {}", f.display()))?;
        if !flag.starts_with("--") {
            return Err(format!("unexpected argument {flag}"));
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if flags.iter().any(|(f, _)| *f == flag) {
            return Err(format!("{flag} given twice"));
        }
        flags.push((flag, value));
    }
    let mut take = |name: &str| {
        flags
            .iter()
            .position(|(f, _)| f == name)
            .map(|i| flags.swap_remove(i).1)
    };
    let command = match sub.to_str() {
        Some("keygen") => Command::Keygen {
            id: take("--id")
                .ok_or("keygen needs --id")?
                .into_string()
                .map_err(|_| "--id must be UTF-8")?,
            out: take("--out").ok_or("keygen needs --out")?.into(),
        },
        Some("sign") => {
            let program = match (take("--provenance"), take("--program"), take("--subject")) {
                (Some(file), None, subject) => ProgramSource::Provenance {
                    file: file.into(),
                    subject: subject
                        .map(|s| s.into_string().map_err(|_| "--subject must be UTF-8"))
                        .transpose()?,
                },
                (None, Some(file), None) => ProgramSource::File(file.into()),
                (None, Some(_), Some(_)) => {
                    return Err("--subject goes with --provenance".to_owned());
                }
                (Some(_), Some(_), _) => {
                    return Err("give --provenance or --program, not both".to_owned());
                }
                (None, None, _) => return Err("sign needs --provenance or --program".to_owned()),
            };
            let days = match take("--valid-for") {
                None => DEFAULT_DAYS,
                Some(d) => d
                    .to_str()
                    .and_then(|d| d.parse::<u64>().ok())
                    .filter(|d| (1..=MAX_DAYS).contains(d))
                    .ok_or_else(|| format!("--valid-for must be 1 to {MAX_DAYS} days"))?,
            };
            Command::Sign(SignArgs {
                key: take("--key").ok_or("sign needs --key")?.into(),
                grants: take("--grants").ok_or("sign needs --grants")?.into(),
                program,
                days,
                previous: take("--previous").map(PathBuf::from),
                out: take("--out").ok_or("sign needs --out")?.into(),
                signature: take("--signature").ok_or("sign needs --signature")?.into(),
            })
        }
        _ => return Err(format!("unknown command {}", sub.display())),
    };
    if let Some((flag, _)) = flags.first() {
        return Err(format!("unexpected flag {flag}"));
    }
    Ok(command)
}

/// Exactly 64 hexadecimal digits, as 32 bytes.
fn unhex32(text: &str) -> Option<[u8; 32]> {
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != 32 {
        return None;
    }
    let nibble = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut out = [0u8; 32];
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = nibble(hi)?.checked_mul(16)?.checked_add(nibble(lo)?)?;
    }
    Some(out)
}

/// Reads at most `max` bytes of `path`, refusing a longer file.
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > max) {
        return Err(format!("{} is over {max} bytes", path.display()));
    }
    Ok(bytes)
}

/// Creates a key file that only its owner can read, never replacing one.
fn keygen(id: &str, out: &Path) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;
    if corten_std::path::PathSeg::parse(id).is_err() {
        return Err(format!(
            "key ID {id:?} is not a valid name (letters, digits, '-', '_', '.')"
        ));
    }
    let seed = corten_std::random::array::<32>().map_err(|e| e.to_string())?;
    let pair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    writeln!(
        file,
        "{KEY_HEADER}\nid {id}\nseed {}",
        corten_sha256::hex(&seed)
    )
    .map_err(|e| format!("{}: {e}", out.display()))?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pair.pk.as_ref());
    Ok(format!("{id}={}", corten_sha256::hex(&pk)))
}

/// Reads a key file from [`keygen`], refusing one another user could read,
/// write or have planted.
fn read_key(path: &Path, home: &Path) -> Result<(String, ed25519_compact::KeyPair), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let owner = fs::metadata(home)
        .map_err(|e| format!("{}: {e}", home.display()))?
        .uid();
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is accessible to group or others (mode {:o}); chmod 600 it",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    if meta.uid() != owner {
        return Err(format!(
            "{} is owned by uid {}, not by {}'s owner (uid {owner})",
            path.display(),
            meta.uid(),
            home.display()
        ));
    }
    let text = String::from_utf8(read_bounded(path, 4096)?)
        .map_err(|_| format!("{} is not a key file", path.display()))?;
    let mut lines = text.lines();
    let bad = || format!("{} is not a {KEY_HEADER} file", path.display());
    if lines.next() != Some(KEY_HEADER) {
        return Err(bad());
    }
    let id = lines
        .next()
        .and_then(|l| l.strip_prefix("id "))
        .ok_or_else(bad)?;
    let seed = lines
        .next()
        .and_then(|l| l.strip_prefix("seed "))
        .and_then(unhex32)
        .ok_or_else(bad)?;
    if lines.next().is_some() {
        return Err(bad());
    }
    Ok((
        id.to_owned(),
        ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed)),
    ))
}

/// The digest the manifest pins.
fn program_digest(source: &ProgramSource) -> Result<[u8; 32], String> {
    match source {
        ProgramSource::File(path) => Ok(corten_sha256::digest(&read_bounded(path, MAX_PROGRAM)?)),
        ProgramSource::Provenance { file, subject } => {
            let text = String::from_utf8(read_bounded(file, MAX_TEXT)?)
                .map_err(|_| format!("{} is not UTF-8", file.display()))?;
            let json = Json::parse(&text).map_err(|e| format!("{}: {e:?}", file.display()))?;
            let subjects = json
                .get("subject")
                .and_then(Json::as_array)
                .ok_or_else(|| format!("{} has no subject list", file.display()))?;
            let named = |s: &&Json| {
                subject
                    .as_deref()
                    .is_none_or(|want| s.get("name").and_then(Json::as_str) == Some(want))
            };
            let matches: Vec<&Json> = subjects.iter().filter(named).collect();
            let [one] = matches.as_slice() else {
                let listed: Vec<&str> = subjects
                    .iter()
                    .filter_map(|s| s.get("name").and_then(Json::as_str))
                    .collect();
                return Err(match subject {
                    Some(want) => format!("no subject named {want:?} in {listed:?}"),
                    None => format!(
                        "{} subjects {listed:?}: choose one with --subject",
                        listed.len()
                    ),
                });
            };
            one.get("digest")
                .and_then(|d| d.get("sha256"))
                .and_then(Json::as_str)
                .and_then(unhex32)
                .ok_or_else(|| format!("{}: the subject has no sha256 digest", file.display()))
        }
    }
}

/// The `serial` line of an earlier manifest.
fn previous_serial(path: &Path) -> Result<u64, String> {
    let text = String::from_utf8(read_bounded(path, MAX_TEXT)?)
        .map_err(|_| format!("{} is not UTF-8", path.display()))?;
    text.lines()
        .find_map(|l| l.strip_prefix("serial "))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("{} has no serial line", path.display()))
}

/// Writes and signs the manifest; returns a one-line summary.
fn sign(args: &SignArgs, home: &Path, now: u64) -> Result<String, String> {
    let (id, pair) = read_key(&args.key, home)?;
    let serial = now;
    if let Some(previous) = &args.previous {
        let before = previous_serial(previous)?;
        if before >= serial {
            return Err(format!(
                "serial {serial} (the current time) is not above {before} in {}: check the clock, or wait a second",
                previous.display()
            ));
        }
    }
    let not_after = args
        .days
        .checked_mul(DAY)
        .and_then(|s| now.checked_add(s))
        .ok_or("--valid-for overflows the clock")?;
    let program = program_digest(&args.program)?;
    let grants = String::from_utf8(read_bounded(&args.grants, MAX_TEXT)?)
        .map_err(|_| format!("{} is not UTF-8", args.grants.display()))?;
    for (n, line) in (1usize..).zip(grants.lines()) {
        if RESERVED.iter().any(|r| line.starts_with(r)) {
            return Err(format!(
                "{}:{n}: header lines are written by this tool; the file holds grants only",
                args.grants.display()
            ));
        }
    }
    let mut manifest = format!(
        "corten-manifest 3\nkey {id}\nserial {serial}\nnot-after {not_after}\nprogram sha256 {}\n{grants}",
        corten_sha256::hex(&program)
    );
    if !manifest.ends_with('\n') {
        manifest.push('\n');
    }
    let signature = pair.sk.sign(manifest.as_bytes(), None);
    // The launcher's own check, before anything is written.
    let mut keys = corten_std::manifest::TrustedKeys::new();
    keys.add(
        corten_std::manifest::KeyId(&id),
        corten_std::manifest::PublicKey(pair.pk.as_ref()),
    )
    .map_err(|e| e.to_string())?;
    let verified = corten_std::manifest::verify(
        manifest.as_bytes(),
        corten_std::manifest::Signature(signature.as_ref()),
        &keys,
        corten_std::manifest::UnixTime(now),
        corten_std::manifest::MinSerial(serial),
    )
    .map_err(|e| format!("the signed manifest does not verify: {e}"))?;
    fs::write(&args.out, &manifest).map_err(|e| format!("{}: {e}", args.out.display()))?;
    fs::write(&args.signature, signature.as_ref())
        .map_err(|e| format!("{}: {e}", args.signature.display()))?;
    Ok(format!(
        "signed {}: key {id}, serial {serial}, not-after {not_after} ({} days), program sha256 {}, {} grants",
        args.out.display(),
        args.days,
        corten_sha256::hex(&program),
        verified.grants.len()
    ))
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| "HOME is not set to an absolute path".to_owned())
}

fn main() -> ExitCode {
    let command = match parse(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("corten-manifest: {e}\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let result = match command {
        Command::Keygen { id, out } => keygen(&id, &out).map(|line| println!("{line}")),
        Command::Sign(args) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "the system clock is before 1970".to_owned())
            .and_then(|now| sign(&args, &home()?, now.as_secs()))
            .map(|summary| eprintln!("corten-manifest: {summary}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("corten-manifest: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const NOW: u64 = 1_800_000_000;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    /// A fresh private directory, also used as `$HOME` (the owner reference).
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "corten-manifest-test-{name}-{}",
            std::process::id()
        ));
        if let Err(e) = fs::remove_dir_all(&dir) {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
        }
        fs::create_dir(&dir).unwrap();
        dir
    }

    fn sign_args(dir: &Path, program: ProgramSource) -> SignArgs {
        SignArgs {
            key: dir.join("key"),
            grants: dir.join("grants"),
            program,
            days: DEFAULT_DAYS,
            previous: None,
            out: dir.join("m"),
            signature: dir.join("m.sig"),
        }
    }

    #[test]
    fn arguments_are_checked() {
        let base = [
            "sign",
            "--key",
            "k",
            "--grants",
            "g",
            "--out",
            "o",
            "--signature",
            "s",
        ];
        let with = |extra: &[&str]| {
            let mut a = base.to_vec();
            a.extend_from_slice(extra);
            parse(os(&a))
        };
        let Command::Sign(args) = with(&["--program", "p"]).unwrap() else {
            panic!("not sign");
        };
        assert_eq!(args.days, 90);
        assert_eq!(args.program, ProgramSource::File("p".into()));
        for bad in [
            &["--program", "p", "--valid-for", "0"][..],
            &["--program", "p", "--valid-for", "367"],
            &["--program", "p", "--valid-for", "x"],
            &["--program", "p", "--provenance", "q"],
            &["--program", "p", "--subject", "app"],
            &["--program", "p", "--program", "q"],
            &["--program", "p", "--extra", "x"],
            &[],
        ] {
            assert!(with(bad).is_err(), "{bad:?}");
        }
        assert!(with(&["--program", "p", "--valid-for", "366"]).is_ok());
        assert!(parse(os(&["keygen", "--id", "k"])).is_err());
        assert!(parse(os(&["frobnicate"])).is_err());
    }

    #[test]
    fn keygen_then_sign_produces_a_manifest_the_launcher_accepts() {
        let dir = scratch("roundtrip");
        let line = keygen("deploy-1", &dir.join("key")).unwrap();
        let (id, hex) = line.split_once('=').unwrap();
        assert_eq!(id, "deploy-1");
        let mode = fs::metadata(dir.join("key")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(
            keygen("deploy-1", &dir.join("key")).is_err(),
            "overwrote a key"
        );
        fs::write(dir.join("prog"), b"abc").unwrap();
        fs::write(dir.join("grants"), "exec tar /usr/bin/tar").unwrap();
        let summary = sign(
            &sign_args(&dir, ProgramSource::File(dir.join("prog"))),
            &dir,
            NOW,
        )
        .unwrap();
        assert!(summary.contains("1 grants"), "{summary}");
        let manifest = fs::read(dir.join("m")).unwrap();
        let text = String::from_utf8(manifest.clone()).unwrap();
        assert_eq!(
            text,
            format!(
                "corten-manifest 3\nkey deploy-1\nserial {NOW}\nnot-after {}\nprogram sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\nexec tar /usr/bin/tar\n",
                NOW + 90 * DAY
            )
        );
        // Checked the way corten-sandbox checks it, with the printed key.
        let pk = unhex32(hex).unwrap();
        let mut keys = corten_std::manifest::TrustedKeys::new();
        keys.add(
            corten_std::manifest::KeyId("deploy-1"),
            corten_std::manifest::PublicKey(&pk),
        )
        .unwrap();
        let sig = fs::read(dir.join("m.sig")).unwrap();
        let v = corten_std::manifest::verify(
            &manifest,
            corten_std::manifest::Signature(&sig),
            &keys,
            corten_std::manifest::UnixTime(NOW),
            corten_std::manifest::MinSerial(NOW),
        )
        .unwrap();
        assert_eq!(v.program_sha256, corten_sha256::digest(b"abc"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_file_others_can_reach_is_refused() {
        let dir = scratch("keymode");
        keygen("k", &dir.join("key")).unwrap();
        fs::write(dir.join("prog"), b"x").unwrap();
        fs::write(dir.join("grants"), "").unwrap();
        let args = sign_args(&dir, ProgramSource::File(dir.join("prog")));
        fs::set_permissions(dir.join("key"), fs::Permissions::from_mode(0o640)).unwrap();
        let e = sign(&args, &dir, NOW).unwrap_err();
        assert!(e.contains("accessible to group or others"), "{e}");
        fs::set_permissions(dir.join("key"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(dir.join("key"), dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("key")).unwrap();
        let e = sign(&args, &dir, NOW).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        assert!(!dir.join("m").exists(), "a manifest was written");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn grants_are_checked_before_anything_is_written() {
        let dir = scratch("grants");
        keygen("k", &dir.join("key")).unwrap();
        fs::write(dir.join("prog"), b"x").unwrap();
        let args = sign_args(&dir, ProgramSource::File(dir.join("prog")));
        for (grants, why) in [
            ("serial 99\n", "header lines are written by this tool"),
            (
                "program sha256 00\n",
                "header lines are written by this tool",
            ),
            ("exec tar relative/tar\n", "does not verify"),
            ("exec tar /a\nexec tar /b\n", "does not verify"),
        ] {
            fs::write(dir.join("grants"), grants).unwrap();
            let e = sign(&args, &dir, NOW).unwrap_err();
            assert!(e.contains(why), "{grants:?}: {e}");
            assert!(
                !dir.join("m").exists(),
                "{grants:?}: a manifest was written"
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_serial_must_rise_above_the_previous_manifest() {
        let dir = scratch("serial");
        keygen("k", &dir.join("key")).unwrap();
        fs::write(dir.join("prog"), b"x").unwrap();
        fs::write(dir.join("grants"), "").unwrap();
        let mut args = sign_args(&dir, ProgramSource::File(dir.join("prog")));
        sign(&args, &dir, NOW).unwrap();
        fs::rename(dir.join("m"), dir.join("before")).unwrap();
        args.previous = Some(dir.join("before"));
        let e = sign(&args, &dir, NOW).unwrap_err();
        assert!(e.contains("is not above"), "{e}");
        sign(&args, &dir, NOW + 1).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_digest_comes_from_the_chosen_provenance_subject() {
        let dir = scratch("provenance");
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        fs::write(
            dir.join("prov.json"),
            format!(
                r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{{"name":"target/release/app","digest":{{"sha256":"{a}"}}}},{{"name":"target/release/tool","digest":{{"sha256":"{b}"}}}}]}}"#
            ),
        )
        .unwrap();
        let src = |subject: Option<&str>| ProgramSource::Provenance {
            file: dir.join("prov.json"),
            subject: subject.map(str::to_owned),
        };
        let e = program_digest(&src(None)).unwrap_err();
        assert!(e.contains("choose one with --subject"), "{e}");
        assert_eq!(
            program_digest(&src(Some("target/release/tool"))).unwrap(),
            [0xbb; 32]
        );
        let e = program_digest(&src(Some("app"))).unwrap_err();
        assert!(e.contains("no subject named"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
