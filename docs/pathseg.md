# PathSeg grammar and the DirCap monitor (normative)

Status: Phase 0 specification, 2026-10-26. Required by the ratification amendment "Publish a normative `PathSeg` grammar" (spec section 5). The E claims for the path family (CWE-22 to 40, 42 to 57, 59, 61, 64, 66, 67, 69, 72, 363, 1386 and 626) rest on this document and on the monitor described below. A change here is a change to those claims.

## 1. PathSeg

A `PathSeg` is one name inside a directory. It is constructed only by `PathSeg::parse`, which accepts a string when every rule below holds and rejects it otherwise. There is no other constructor.

| # | Rule | Rejects (examples) | Weaknesses it closes |
| --- | --- | --- | --- |
| 1 | Length is 1 to 255 bytes | `""`, a 256-byte name | |
| 2 | Every character is in the POSIX portable filename character set: `A`–`Z`, `a`–`z`, `0`–`9`, `.`, `_`, `-` | `a/b`, `a\b`, `C:x`, `a b`, `a*`, `a?`, `a:stream`, `a~1`, `é`, NUL, control characters | 23 to 40 (separators, drive and UNC forms), 46 to 48 (spaces), 56 (wildcards), 58 (8.3 `~`), 69 and 72 (`:` streams, `/..namedfork`), 626 (NUL) |
| 3 | It is not `.` and contains no `..` | `.`, `..`, `...`, `a..b`, `....` | 24 to 27, 32 to 35, 45, 55, 57 |
| 4 | It does not end with `.` | `name.`, `name...` | 42, 43 |
| 5 | It does not start with `-` | `-rf`, `--help` | Argument injection when a name is passed to a program (CWE-88 stays C; this is defence in depth) |
| 6 | Its base name (the part before the first `.`) is not a Windows device name, compared case-insensitively: `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9` | `con`, `NUL.txt`, `com1.log` | 66, 67 |

Notes:

- **Case.** A `PathSeg` preserves case and compares byte for byte. Whether two names reach one object on a case-insensitive filesystem is the filesystem's property (CWE-41 is C).
- **Unicode.** Version 1 accepts ASCII only, which avoids normalisation entirely. Accepting Unicode later needs NFC normalisation and a confusables policy, and is a grammar change.
- **Leading dot.** Allowed (`.config`), because rule 3 already excludes `.` and `..`.
- **Display names.** Applications that must keep a user's original file name store it as data, and store the file under a generated `PathSeg`.

A `RelPath` is a non-empty sequence of `PathSeg` values. Because no segment contains a separator, joining them with `/` gives exactly one path, with no `.` or `..` component.

## 2. DirCap and the monitor

A `DirCap` is an open directory handle. Only the capability manifest given to `main`, or `DirCap::open_dir` on an existing `DirCap`, produces one. Every open resolves a `RelPath` relative to a `DirCap` with one `openat2(2)` call:

- `resolve` = `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, always. No API takes other resolve flags.
- `flags` always include `O_CLOEXEC` and `O_NOFOLLOW`.
- The kernel resolves the whole path atomically under those flags. A symbolic link anywhere in the path, including the last component, fails the open (`ELOOP`); so does crossing a mount point (`EXDEV`) or leaving the directory (`EXDEV`).

**Fail closed.** If `openat2` is unavailable (not Linux, Linux before 5.6, or `ENOSYS` from a seccomp filter), every `DirCap` operation returns an error. There is no fallback to `openat` or to string paths. The monitor probes once at first use.

**Temporary files.** `DirCap::create_temp` opens with `O_CREAT | O_EXCL | O_CLOEXEC`, mode `0600`, under a name of `tmp-` plus 32 hexadecimal digits from the operating system's random source. Exclusive creation makes a pre-planted file or link fail the call. CWE-378 is E. Which directory is used is the caller's capability choice (CWE-377 and 379 are C).

`RESOLVE_NO_XDEV` goes beyond the three flags in spec section 4.4. It is added so that a bind mount or other mount point inside a granted directory cannot redirect an open (CWE-1386 on Linux). The cost is that files on a submount need their own `DirCap`.

## 3. What stays C

- Choosing the root that a `DirCap` grants, and its permissions (CWE-377, 379, and the policy part of CWE-22).
- Hard links that already exist inside the directory (CWE-62): `openat2` cannot tell a hard link from the original.
- Name equivalence on case-insensitive or normalising filesystems (CWE-41).
- Races on files already inside the directory (CWE-367).
