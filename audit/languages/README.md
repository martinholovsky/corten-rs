# CWE applicability in other languages

The same per-CWE review as [`../applicability/`](../applicability/) (Rust), for the languages Corten is compared with, so that the comparison in [`docs/language-comparison.md`](../../docs/language-comparison.md) and its chart rests on reviewed answers rather than MITRE's language tags (owner decision, 2026-11-10: C, C++, Java, Go and Python, one language per pull request, with programs checked in CI). Done: **C**, **C++**, **Java**. Next: Go, Python.

## Method

- **One row per CWE, all 944**, in `<lang>/rows.csv`: `cwe_id, with_hatch, without_hatch, evidence, reasoning`. `with_hatch` answers with the language's escape hatch allowed (Java's JNI and `sun.misc.Unsafe`, Go's `unsafe`, Python's `ctypes`), `without_hatch` without it, like Rust's `unsafe` and safe columns. C and C++ have no safe subset their compiler enforces, so their two columns are always equal. Values: `yes` (a program can contain it), `no` (a construct the language lacks), `n/a` (not a weakness of code: hardware, physical, process).
- **Read the way the Rust row is read.** Where the Rust audit counts an analogue (panics and `Result` for the exception weaknesses, an `unsafe` `link_section` entry for a static code block, an `extern` declaration of libc's `gets`), the other language's analogue counts too; where the Rust row reads a CWE strictly (no `finally`, no destructor to call twice), so does the other language. A difference between two languages is then a difference in the language, not in the reading. Reasoning that holds word for word was reused after review; the rest was written for the language. C++ inherits C's rows where C++ keeps the C construct (marked *As in C, which C++ includes*), and has its own reasoning where it adds one: classes, inheritance, destructors, exceptions, static members.
- **A program wherever the compiler decides**: wherever the Rust audit shows the compiler preventing a weakness (safe Rust rejects it, or only `unsafe` writes it), and wherever the other language lacks a construct. `CWE-<n>[.<variant>].<ext>` with a header in its first lines: `// @compiles` or `// @rejected: <exact compiler text>`. A compiling program shows the weakness can be written; whether it exhibits the weakness is the judgement in its comment.
- **The language is what the pinned compiler accepts.** C: gcc 15.3.0 with `-std=c17 -pedantic-errors`; C++: g++ 15.3.0 with `-std=c++20 -pedantic-errors`; both in the `gcc:15` image pinned by digest. Java: javac 25.0.5 in the `eclipse-temurin:25-jdk` image pinned by digest; its escape hatch is JNI (`native` methods), `java.lang.foreign` and the `jdk.unsupported` `sun.misc` classes (`Unsafe`, `Signal`). A `// @compiles: hatch` program must use one and a plain `// @compiles` program must not, which the check enforces; a CWE counts as hatch-only when a hatch program compiles and a `// @rejected:` program shows the plain form fails, as Rust's unsafe-only does. That includes GNU attributes such as `constructor`, which the flags accept, as the Rust audit includes what rustc accepts.

## Checking

```
podman run --rm --network=none --cap-drop=ALL --security-opt=no-new-privileges \
  --read-only --tmpfs /tmp -v "$PWD":/src:ro -w /src \
  docker.io/library/gcc@sha256:51d7ef77d4e5ca232d635ce4a2a3154f18f9ccd01542a14bc06794e853ffddb9 \
  bash scripts/language-check.sh c > c-verdicts.tsv
python3 scripts/language-table.py c c-verdicts.tsv
python3 scripts/language-docs.py
```

`language-check.sh` derives a verdict per CWE from the programs and fails on any program whose header does not hold. `language-table.py` refuses a row that disagrees with its programs, a program no row cites, a missing or duplicate row, or a value outside `yes`, `no`, `n/a`. `language-docs.py` writes `docs/<lang>-applicability.md`, `docs/language-comparison.md` and `docs/assets/cwe-languages.svg`; CI runs all three and fails when a generated file is stale. Never edit the generated files by hand.

Shown to fail before being trusted: the check rejected a program that does not compile, a rejection with the wrong message, and a file without a header (exit 1); the validator rejected a row saying `no` for a CWE whose program compiles (2026-11-10).
