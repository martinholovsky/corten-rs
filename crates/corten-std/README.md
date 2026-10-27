# corten-std

Corten's capability-oriented prelude (spec sections 4.3 to 4.10; Phase 2). Under `cargo corten check`, application code cannot use ambient `std` filesystem, network, process, environment or clock APIs. This crate is what it uses instead.

| Module | Gives | Weaknesses (ledger) |
| --- | --- | --- |
| `manifest` | `Capabilities::load`: the signed manifest, the only source of a root `DirCap`, an `ExecCap` or a `DeclassifyCap` | |
| `path`, `fs` | `PathSeg`, `RelPath`, `DirCap`, `CapFile`: opens beneath a granted directory via `openat2`; refused off Linux | CWE-22 to 40, 42 to 57, 59, 61, 64, 66, 67, 69, 72, 363, 378, 626, 1386 |
| `process` | `ExecCap`, `ProcessInvocation`, `process!`: argv, no shell, no `PATH` search, operands after `--` | CWE-77, 78, 426 to 428 |
| `sql` | `SqlQuery`, `sql!`, `SqlExecutor` | CWE-89, 564, 943 |
| `html` | `Html`, `html!`, `HtmlWriter` | CWE-79 to 87, 692, 838 |
| `http` | `HeaderName`, `HeaderValue`, `SetCookie`, `HeaderWriter` | CWE-93, 113, 644 |
| `log` | `LogRecord`, `log_record!`, `LogWriter` | CWE-117 |
| `csv` | `CsvCell`, `render_row`, `CsvWriter` | CWE-1236 |
| `text` | `TextMessage`, `text!`, `TextSender` | CWE-1336 |
| `ldap` | `LdapFilter`, `LdapDn`, `ldap_filter!`, `ldap_dn!`, `LdapSearcher` | CWE-90 |
| `xpath` | `XPathExpr`, `XQueryExpr`, `xpath!`, `xquery!`, evaluators | CWE-91, 643, 652 |
| `secret` | `Secret`: wiped, locked, unprintable, constant-time compare | (C: CWE-14, 316) |
| `refine` | `Bounded<MIN, MAX>`, `bounded!` (proved at check time), `Bounded::new` and `copy_into` (runtime checks): the three-outcome rule (Phase 4) | (C) |
| `label` | `Labeled<T, L>` over `Public < Internal < Confidential < Secret`; only `Public` reaches a sink; `declassify` needs a manifest-granted `DeclassifyCap` and is logged (Phase 4) | (C) |
| `sync` | `lock_order!`, `OrderedMutex`, `LockRoot`: locks against the declared order do not compile (Phase 4) | (C) |

## Using the sinks

```rust
use corten_std::sql::Placeholder;

let id = 42;
let q = corten_std::sql!("SELECT name FROM users WHERE id = {}", id);
assert_eq!(q.text(Placeholder::Dollar), "SELECT name FROM users WHERE id = $1");

let page = corten_std::html!("<p class=\"note\">{}</p>", "<b>not bold</b>");
assert_eq!(page.as_str(), "<p class=\"note\">&lt;b&gt;not bold&lt;/b&gt;</p>");
```

Templates are string literals: every `{}` is a value. The checks that a template is safe run at compile time; a misplaced placeholder is a compile error.

## Platform

`DirCap` needs Linux 5.6 or later (`openat2`). On any other target, or a kernel without `openat2`, a manifest with a `dir` entry fails to load and every `DirCap` operation returns `FsError::Unsupported`. There is no fallback.

## Trust

Every encoder here is part of Corten's trusted base ([`docs/tcb.md`](../../docs/tcb.md)). The 26 E claims that rest on an encoder need an independent review before they can be marked verified ([`docs/gates/phase-2.md`](../../docs/gates/phase-2.md) section 5). The crate uses no `unsafe`; its dependencies are `rustix` (Linux), `region`, `zeroize`, `subtle` and `ed25519-compact`.
