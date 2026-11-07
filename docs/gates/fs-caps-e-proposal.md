# Strategy 8: which `fs-caps` rows the DirCap API makes inexpressible (first cut, 2026-11-05)

Status: **question 1 decided (owner, 2026-11-06): the three E candidates go ahead; CWE-276, 689 and 708 are E and verified** (`gates/phase-6.md`, "Strategy 8 E claims"). Questions 2 and 3 decided (owner, 2026-11-06): CWE-62 option (D), CWE-434 option (A); both rows stay C.

The 31 ledger rows with strategy `fs-caps` are C. Strategy 8 (`gates/phase-6.md`) built `FileMode`, `ReadSingleLink`/`AppendSingleLink` and `store_upload`. This document asks, row by row, whether a Corten program can still write the weakness.

## The bar

A row is an E candidate only if all of these hold. The bar is question 21 and design principle 1, applied the way the CWE-918 and CWE-378 rows were.
- **The prelude cannot express it.** Read in `crates/corten-std/src/fs.rs` at `59ce90d`, the public filesystem surface is complete:
  - `DirCap::open_dir`, `open_file`, `create_temp`, `store_upload` and `remove_file`;
  - `CapFile::read_to_end` and `write_all`;
  - `OpenMode` (`Read`, `ReadSingleLink`, `CreateExclusive(FileMode)`, `Append`, `AppendSingleLink`);
  - `FileMode` (0600, 0640 or 0644, set exactly with `fchmod`);
  - no trait gives a descriptor out of `DirCap` or `CapFile`.

  There is no directory creation, rename, copy, chmod, chown or metadata API.
- **Every way around the prelude is refused.**
  - `std`: the checker bans `std::fs` functions, `File`, `OpenOptions` and `DirBuilder`, and `std::os::unix::fs::chown`, `lchown` and `symlink` (`crates/cargo-corten/src/profile.rs`).
  - System-call crates (`rustix`, `nix`): the operator's dependency policy refuses them, which is the CWE-918 precedent.
- **Not decided otherwise.** It is not platform-dependent (the amendment in spec section 6), not a choice of deployment root (spec 4.4), and not already decided C by the owner (questions 2 and 4; the doubly disputed ids).
- **No cost to developers.** Nothing more is asked of a developer than today's API asks (principle 1).

## Measured for this proposal (2026-11-05)

**Default ACLs.** A parent directory with a default ACL granting user `nobody` `rwx`. In a `--rm` `rust:1.99.1-slim-bookworm` container, files were created with the two operations `open_file` performs (an exclusive create with the mode, then `fchmod` to the mode), here through Python's `os.open` and `os.fchmod` rather than `openat2`; the `corten-std` test that followed (`gates/phase-6.md`, "Strategy 8 E claims") exercises `open_file` itself:

| Mode | `nobody`'s effective rights | `nobody` appends |
| --- | --- | --- |
| 0600 | `---` | refused |
| 0640 | `r--` | refused |
| 0644 | `r--` | refused |
| Control: a plain create at 0666, no `fchmod` | `rw-` | **succeeded** |

So `fchmod` caps an inherited ACL at the mode's group bits: no one but the owner can write. But an inherited ACL **does** let a named user read a 0640 file, beyond its group. The rows below depend on both results.

**A ban-list gap.** `std::os::unix::fs::fchown` (stable since 1.73.0, read in the 1.99.1 sources) is not banned, while `chown` and `lchown` are. A program can call it on `std::io::stdout()`, which implements `AsFd`. Under the sandbox it needs privilege to succeed, so its impact is small, but it is ambient authority the ban list means to remove. Fix: add it to the banned methods, with a corpus variant. It is the prerequisite of CWE-708 below.

## Per-row first cut

### E candidates (3)

| CWE | Name | Why the API makes it inexpressible | Bad variants the case needs (each must fail under `cargo corten check`) | Open point |
| --- | --- | --- | --- | --- |
| 276 | Incorrect Default Permissions | MITRE: files "set to allow anyone to modify". Every creation names a `FileMode`, the widest is 0644, and the mode is set exactly whatever the `umask` and any inherited ACL (measured above). No API changes a mode later | `File::create` (banned), `OpenOptions` with `OpenOptionsExt::mode` (banned type), `set_permissions` (banned), `DirBuilder` (banned type), `rustix::fs::chmod` and `nix::sys::stat::fchmod` (dependency policy), a hand-made `FileMode` with other bits (it is an enum with no constructor from bits: `absent`, the weakest evidence) | Corten programs are not installers; the row reads "files the program creates". Owner to confirm that reading |
| 689 | Permission Race Condition During Resource Copy | There is no copy API, so permissions are never set after the content: the mode is given at the exclusive create, so the file is never wider than the requested mode, even before the `fchmod` | `std::fs::copy` (banned; it copies permissions), create then `set_permissions` (banned), `rustix`/`nix` chmod after create (dependency policy) | Before the `fchmod`, the file has the requested mode minus the `umask`, or the inherited ACL capped by that mode. That follows from the measurement above, but the moment before `fchmod` was not observed on its own |
| 708 | Incorrect Ownership Assignment | No prelude API assigns an owner; a new file belongs to the process's user, which is deployment | `std::os::unix::fs::chown` and `lchown` (banned), **`fchown` (needs the ban above first)**, `rustix::fs::fchown`, `nix::unistd::chown` (dependency policy) | Needs the `fchown` ban, a checker change |

### Stay C (28)

| CWE | Name | Why a Corten program can still write it |
| --- | --- | --- |
| 41 | Improper Resolution of Path Equivalence | Doubly disputed, decided C: which canonical names reach one object is a property of the filesystem |
| 58 | Path Equivalence: Windows 8.3 Filename | Doubly disputed, decided C: filesystem configuration |
| 62 | UNIX Hard Link | `OpenMode::Read` and `Append` still follow hard links; `ReadSingleLink` is opt-in. Question 2 kept hard-link policy C. *Option for the owner:* making single-link the default would make it inexpressible, but it changes the API and reopens question 2 |
| 65 | Windows Hard Link | `DirCap` refuses off Linux; a Windows backend does not exist (platform) |
| 73 | External Control of File Name or Path | Escape is E (CWE-22); choosing *which* name beneath the capability from input (`rel(input)`) is expressible |
| 178 | Improper Handling of Case Sensitivity | Filesystem property (platform) |
| 219 | Storage of File with Sensitive Data Under Web Root | Which directory is the web root is deployment (spec 4.4, root choice) |
| 220 | Storage of File With Sensitive Data Under FTP Root | As 219 |
| 277 | Insecure Inherited Permissions | Measured: a parent's default ACL lets a named user read a 0640 file. Where the program writes is deployment, and the inherited ACL is outside its view |
| 278 | Insecure Preserved Inherited Permissions | No API copies or extracts with preserved modes, but MITRE's "inherits ... without user awareness" includes the inherited ACL measured above |
| 279 | Incorrect Execution-Assigned Permissions | Picking `ReadableByAll` where the user specified owner-only is expressible: the API offers three modes and cannot know the user's intent |
| 281 | Improper Preservation of Permissions | Reading a 0600 file and writing a copy with `ReadableByAll` is expressible |
| 282 | Improper Ownership Management | The class includes "does not properly verify the ownership" (283) |
| 283 | Unverified Ownership | The prelude offers no ownership check, so a program that reads a critical file without verifying its owner is the default |
| 367 | Time-of-check Time-of-use (TOCTOU) Race Condition | File-name races are closed (CWE-363 is E), but TOCTOU covers any check and use, not only files |
| 377 | Insecure Temporary File | Doubly disputed, decided C: choosing an attacker-reachable directory is policy |
| 379 | Creation of Temporary File in Directory with Insecure Permissions | Doubly disputed, decided C: the directory's permissions are deployment |
| 386 | Symbolic Name not Mapping to Correct Object | Opening one name twice, with a swap between, is expressible |
| 434 | Unrestricted Upload of File with Dangerous Type | `store_upload` is safe, but `open_file(&rel(client_name)?, CreateExclusive(ReadableByAll))` into a served directory is expressible, and an interpreter needs no execute bit. *Option for the owner:* E only if uploads could be stored through `store_upload` alone, which is an API change with a cost to developers |
| 527 | Exposure of Version-Control Repository to an Unauthorized Control Sphere | Deployment; `PathSeg` also accepts `.git` (rule 3 refuses `.` and any `..`, not a leading dot) |
| 528 | Exposure of Core Dump File to an Unauthorized Control Sphere | Where cores go is OS configuration; per-page no-dump is deferred (owner decision 2026-11-04) |
| 529 | Exposure of Access Control List Files to an Unauthorized Control Sphere | Deployment |
| 530 | Exposure of Backup File to an Unauthorized Control Sphere | Creating `config.bak` in a served directory is expressible |
| 552 | Files or Directories Accessible to External Parties | Root choice and deployment |
| 553 | Command Shell in Externally Accessible Directory | A Corten program cannot create an executable file, but MITRE's weakness is a shell present in a served directory, which is deployment |
| 646 | Reliance on File Name or Extension of Externally-Supplied File | `store_upload` ignores the client's name, but branching on the name's extension is plain string logic |
| 706 | Use of Incorrectly-Resolved Name or Reference | Class: covers name resolution well beyond files |
| 732 | Incorrect Permission Assignment for Critical Resource | MITRE includes "read ... by unintended actors": `ReadableByAll` on a secret is expressible |

## What each E claim needs before it moves

1. For CWE-708: the `fchown` ban in `crates/cargo-corten/src/profile.rs`, with a test that it fires (design principle 9).
2. A corpus case per row: `good.rs` creates a file through `DirCap`, and one `bad-*.rs` per variant above, each refused for its own reason. Then a Linux corpus run reporting detection and false rejection with totals (AGENTS.md rule 2).
3. For CWE-276 and 689: the ACL measurement above as a `corten-std` test (`setfacl` in the container), shown to fail when the `fchmod` is removed. That is the same shape as `creation_modes_are_exact_under_umask_077`.
4. A ledger mechanism and reason for each row, then `scripts/applicability-table.py` and `scripts/residual-map.py`.

## Questions for the owner

1. **Do the three E candidates go ahead** (276, 689, 708)?
   - Recommendation: yes. Each rests on an API that already exists and asks developers for nothing more (principle 1). The ban-list gap is worth fixing either way.
   - **Decision (owner, 2026-11-06): yes**, the recommendation.
2. **CWE-62.** Context: the attack needs an unprivileged user to hard-link a file they do not own, which `fs.protected_hardlinks = 1` refuses. The podman VM (Fedora 43) has it at 1, set by systemd's `/usr/lib/sysctl.d/50-default.conf`; the kernel's own default and other distributions were not checked.
   - (A) Keep `ReadSingleLink` opt-in. C; no cost; protection depends on each developer.
   - (B) Single-link by default, with explicit `ReadAnyLink`/`AppendAnyLink`. Still C, because the opt-out keeps it writable. A breaking API change, cheapest now while nothing is released.
   - (C) Single-link only, no opt-out. An E candidate, but it reopens question 2 and costs every developer whose files are legitimately hard-linked (principle 1).
   - (D) (A), plus `corten-sandbox` refusing to start when `fs.protected_hardlinks` is not 1, unless the operator opts out explicitly, with a warning every start. C, because it rests on a kernel setting.
   - Recommendation: (D). It closes the attack in the kernel for every open, costs developers nothing, and fails closed with an explicit, logged opt-out (principles 1 to 3), like `--allow-udp-without-netns`. This replaces the first cut's recommendation of (A), changed by the `protected_hardlinks` finding.
   - **Decision (owner, 2026-11-06): (D)**, the recommendation. Built 2026-11-07 (`gates/phase-6.md`, remaining work); CWE-62 stays C.
3. **CWE-434.**
   - (A) Stay C now; revisit with labels (strategy 9), where a label on request-derived bytes lets only `store_upload` accept them.
   - (B) A `served` flag on manifest `dir` grants, where such a `DirCap` accepts only `store_upload`. Still C (it rests on the operator marking every served directory); a manifest grammar change.
   - (C) `store_upload` as the only way to write client content now. Not feasible: the prelude has no request type before batch 6.
   - Recommendation: (A), with (B) recorded as a batch 6 candidate. (B) is a manifest grammar change, best decided with the web types.
   - **Decision (owner, 2026-11-06): (A)**, the recommendation. CWE-434 stays C; (B) is listed with batch 6 in `gates/phase-6.md`.
