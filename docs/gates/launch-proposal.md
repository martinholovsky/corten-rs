# Design note: how the launcher hands a program its manifest

Status: **decided (owner, 2026-11-17)**, spec section 8, question 26. Built with batch 6's listener work; `corten_std::launch`, `Capabilities::from_launcher`, and `corten-sandbox`'s manifest mode.

## The gap

`Capabilities::load` takes a manifest's bytes, its signature and the trusted keys, but nothing defined how they reach a deployed program. Found on 2026-11-16 while deploying the listener: the demo had to read them with `std::fs`, which `cargo corten check` refuses.

## Decisions (owner, 2026-11-17)

1. **The launcher hands the program the manifest it verified** (the recommendation). Rejected: a fixed, granted path the program reads, which any process with access could swap or read; and deferring, which would leave no checked program deployable.
2. **The channel is a sealed memfd on standard input** (the recommendation, chosen once the constraints below were found). Rejected: a fixed descriptor 3 reached through `/proc/self/fd/3`, which depends on descriptor numbering, works on Linux only, and needs every program's Landlock rules to allow reading `/proc/self/fd`; and one reviewed `unsafe` in `corten-std` to name a raw descriptor, which would break the rule that no crate in the workspace uses `unsafe`.

## The constraints that chose the channel

- A checked program can read neither its environment nor its arguments: the profile bans `std::env::var` and `std::env::args`, and `corten-std` passes the same profile. So descriptor numbers, keys or paths cannot travel in either.
- Naming a raw descriptor needs `unsafe` (`BorrowedFd::borrow_raw`, `OwnedFd::from_raw_fd`), which every crate forbids.
- `rustix::stdio::dup2_stdin` is a safe function, and `std::io::stdin` is not banned, so standard input is the one descriptor both sides reach in safe code.

## The contract

- After verifying the manifest (signature, trusted key, expiry, serial, program digest), `corten-sandbox` writes a **launch document** (`corten_std::launch::document`, so the format has one definition) into a memfd, seals it against writing, growing, shrinking and further sealing, rewinds it, and installs it as the program's standard input.
- The document holds the trusted keys, the signature and the manifest's exact bytes:

  ```text
  corten-launch 1
  trusted-key ID=HEX        one or more
  signature HEX             128 hex digits
  manifest-length L
                            a blank line, then exactly L bytes of manifest
  ```

- `Capabilities::from_launcher()` reads standard input (at most `MAX_LAUNCH` bytes), parses the document strictly, and verifies the manifest itself, as `Capabilities::load` does: signature, key and expiry. The rollback floor stays with the launcher's serial state file; a serial in the document could only repeat the manifest's own, a check that could never fail, so it is not there.
- Under the launcher, a program's standard input is the launch document, not data. A program that needs input takes it through a grant.

## What it cannot claim

- The launcher is trusted (it is in the trusted base, `docs/tcb.md`). Whoever starts the program without it can hand it any manifest signed by any key they choose to call trusted; but they then hold the process outside any sandbox anyway, so this grants them nothing they did not have.
