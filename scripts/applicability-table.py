#!/usr/bin/env python3
"""Merges the reviewed rows into audit/applicability/table.csv, checks them
against the programs, and writes docs/rust-applicability.md.

Refuses (exit 1) unless every CWE in the table is covered exactly once, every
value is valid, every cited program exists, and the checker's verdict for
each CWE agrees with the reviewer's answer. The three headline numbers are
counted from the merged table, never typed.

Usage: scripts/applicability-table.py   (run from the repository root)
"""

import csv
import glob
import subprocess
import sys
from collections import Counter
from pathlib import Path

AUDIT = Path("audit/applicability")
TABLE = AUDIT / "table.csv"
LEDGER = Path("ledger/cwe-ledger.csv")
DOC = Path("docs/rust-applicability.md")
ANSWERS = {"yes", "no", "n/a"}


def main() -> int:
    table = list(csv.DictReader(TABLE.open(newline="")))
    ids = [r["cwe_id"] for r in table]
    problems = []

    # The ledger columns are copied from the live ledger on every run, so the
    # Corten status follows the corpus and the applicability check below
    # compares against the real ledger, not a snapshot.
    ledger = {r["cwe_id"]: r for r in csv.DictReader(LEDGER.open(newline=""))}
    for r in table:
        led = ledger[r["cwe_id"]]
        r["ledger_rust_applicability"] = led["rust_applicability"]
        r["ledger_bucket"] = led["bucket"]
        r["ledger_status"] = led["status"]

    reviewed = {}
    for path in sorted(AUDIT.glob("rows-*.csv")):
        for row in csv.DictReader(path.open(newline="")):
            cwe = row["cwe_id"].strip()
            if cwe in reviewed:
                problems.append(f"{cwe}: reviewed twice ({path.name})")
            reviewed[cwe] = row
    missing = [c for c in ids if c not in reviewed]
    extra = [c for c in reviewed if c not in set(ids)]
    if missing:
        problems.append(f"{len(missing)} CWEs not reviewed: {missing[:10]}")
    if extra:
        problems.append(f"rows for CWEs not in the table: {extra[:10]}")

    for cwe, row in reviewed.items():
        for col in ("unsafe_rust", "safe_rust"):
            if row[col] not in ANSWERS:
                problems.append(f"{cwe}: {col}={row[col]!r}")
        if row["safe_rust"] == "yes" and row["unsafe_rust"] != "yes":
            problems.append(f"{cwe}: safe_rust yes but unsafe_rust {row['unsafe_rust']}")
        if not row["reasoning"].strip():
            problems.append(f"{cwe}: no reasoning")
        evidence = row["evidence"].split() if row["evidence"].strip() != "none" else []
        for f in evidence:
            if not (AUDIT / f).is_file():
                problems.append(f"{cwe}: cited program {f} does not exist")
        files = glob.glob(str(AUDIT / f"{cwe}.rs")) + glob.glob(str(AUDIT / f"{cwe}.*.rs"))
        if not evidence and files:
            problems.append(f"{cwe}: programs exist but evidence says none")

    # The checker's verdicts, over every program.
    out = subprocess.run(
        ["bash", "scripts/applicability-check.sh"], capture_output=True, text=True
    )
    if out.returncode != 0:
        problems.append("applicability-check.sh failed:\n" + out.stdout[-2000:])
    verdicts = dict(
        line.split("\t") for line in out.stdout.splitlines() if line.startswith("CWE-") and "\t" in line
    )
    expect = {"safe": ("yes", "yes"), "unsafe-only": ("yes", "no"), "rejected": ("no", "no")}
    for cwe, verdict in verdicts.items():
        row = reviewed.get(cwe)
        if row is None:
            continue
        if verdict == "undecided":
            problems.append(f"{cwe}: programs decide nothing")
        elif (row["unsafe_rust"], row["safe_rust"]) != expect[verdict]:
            problems.append(
                f"{cwe}: checker says {verdict}, review says unsafe={row['unsafe_rust']} safe={row['safe_rust']}"
            )

    # The ledger carries the same verdict; it must agree with the review.
    as_ledger = {("yes", "yes"): "applies", ("yes", "no"): "unsafe-rust-only",
                 ("no", "no"): "not-applicable", ("n/a", "n/a"): "not-coding"}
    for r in table:
        row = reviewed.get(r["cwe_id"])
        if row is None:
            continue
        want = as_ledger.get((row["unsafe_rust"], row["safe_rust"]))
        if want is None:
            problems.append(f"{r['cwe_id']}: no ledger value for {row['unsafe_rust']}/{row['safe_rust']}")
        elif r["ledger_rust_applicability"] != want:
            problems.append(
                f"{r['cwe_id']}: ledger rust_applicability is {r['ledger_rust_applicability']}, review says {want}"
            )

    if problems:
        print("\n".join(problems))
        print(f"{len(problems)} problem(s); table not written", file=sys.stderr)
        return 1

    for r in table:
        row = reviewed[r["cwe_id"]]
        r["unsafe_rust"] = row["unsafe_rust"]
        r["safe_rust"] = row["safe_rust"]
        r["evidence"] = row["evidence"].strip()
        r["reasoning"] = " ".join(row["reasoning"].split())
    with TABLE.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(table[0].keys()))
        w.writeheader()
        w.writerows(table)

    unsafe_incl = sum(r["unsafe_rust"] == "yes" for r in table)
    safe = sum(r["safe_rust"] == "yes" for r in table)
    # Corten: safe-Rust weaknesses minus those it eliminates, verified by the
    # corpus. Its checker also forbids unsafe, so the unsafe-only rows are
    # already outside `safe`.
    corten = sum(
        r["safe_rust"] == "yes" and not (r["ledger_bucket"] == "E" and r["ledger_status"] == "verified")
        for r in table
    )
    proved = sum(r["evidence"] != "none" for r in table)
    print(f"Rust (unsafe allowed): {unsafe_incl}")
    print(f"Safe Rust: {safe}")
    print(f"Safe Rust + Corten: {corten}")
    print(f"rows with programs: {proved} of {len(table)}")
    write_doc(table, unsafe_incl, safe, corten, proved)
    return 0


def corten_cell(r: dict) -> str:
    if r["safe_rust"] != "yes" and r["unsafe_rust"] == "yes":
        return "eliminated (no `unsafe`)"
    if r["safe_rust"] != "yes":
        return "n/a"
    if r["ledger_bucket"] == "E":
        return "eliminated, verified" if r["ledger_status"] == "verified" else "eliminated, claimed"
    return {"C": "checkable", "O": "out of reach", "N": "not code"}.get(r["ledger_bucket"], r["ledger_bucket"])


def write_doc(table, unsafe_incl, safe, corten, proved) -> None:
    by_cat = Counter(r["category"] for r in table)
    lines = [
        "# CWE applicability to Rust and Corten",
        "",
        "Generated by `scripts/applicability-table.py` from `audit/applicability/table.csv`; do not edit by hand.",
        "",
        "For each of the 944 weaknesses in MITRE CWE 4.20: can a Rust program contain it with `unsafe`",
        "allowed, can safe Rust contain it, and what Corten does about it. Answers were reviewed per CWE.",
        "Where the language or compiler prevents a weakness, or where a weakness could plausibly have been",
        "prevented, a program in `audit/applicability/` shows it, and `scripts/applicability-check.sh`",
        "re-checks every program against stock rustc. A compiling program shows the weakness can be written;",
        "whether it exhibits the weakness is the judgement stated in its comment.",
        "",
        "| | CWEs |",
        "| --- | ---: |",
        f"| Rust, `unsafe` allowed | {unsafe_incl} |",
        f"| Safe Rust | {safe} |",
        f"| Safe Rust + Corten (eliminations verified by the corpus) | {corten} |",
        "",
        f"{proved} of {len(table)} rows rest on programs; the rest are logic, design or policy weaknesses no",
        "compiler prevents, or constructs Rust does not have, each with its reasoning.",
        "",
        "Corten column: *eliminated (no `unsafe`)* means only `unsafe` can write it and Corten forbids `unsafe`;",
        "*eliminated, verified* is backed by a compile-fail test in `corpus/`; *claimed* is not yet; *checkable*",
        "means Corten provides the mechanism and a stated policy decides it (bucket C).",
        "",
    ]
    for cat, _ in sorted(by_cat.items(), key=lambda kv: (-kv[1], kv[0])):
        rows = [r for r in table if r["category"] == cat]
        u = sum(r["unsafe_rust"] == "yes" for r in rows)
        s = sum(r["safe_rust"] == "yes" for r in rows)
        lines += [
            f"## {cat} ({len(rows)}: {u} with `unsafe`, {s} in safe Rust)",
            "",
            "| CWE | Name | `unsafe` | Safe | Corten | Reasoning |",
            "| --- | --- | :---: | :---: | --- | --- |",
        ]
        for r in sorted(rows, key=lambda r: int(r["cwe_id"].split("-")[1])):
            name = r["name"].replace("|", "\\|")
            reason = r["reasoning"].replace("|", "\\|")
            if r["evidence"] != "none":
                reason += " (" + ", ".join(f"`{e}`" for e in r["evidence"].split()) + ")"
            n = r["cwe_id"].split("-")[1]
            lines.append(
                f"| [{r['cwe_id']}](https://cwe.mitre.org/data/definitions/{n}.html) | {name} | "
                f"{r['unsafe_rust']} | {r['safe_rust']} | {corten_cell(r)} | {reason} |"
            )
        lines.append("")
    lines += [
        "CWE names are from MITRE CWE 4.20, used under its terms of use (see `ledger/NOTICE`).",
        "",
    ]
    DOC.write_text("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
