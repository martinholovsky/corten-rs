#!/usr/bin/env python3
"""Validates the CWE applicability rows of one comparison language
(audit/languages/<lang>/rows.csv) against the per-CWE list in
audit/applicability/table.csv and against the verdicts its programs produce
(scripts/language-check.sh <lang>, read from standard input or a file).

A row may say yes (writable) or no (not writable) or n/a (not a weakness of
code), with and without the escape hatch. A CWE with a program that compiles
without the hatch must say yes in both columns; one written only through the
hatch (scripts/language-check.sh: hatch-only) must say yes, no; one whose only
programs are rejected must say no in both. Every evidence file must exist.

Usage:
  scripts/language-check.sh c > verdicts.tsv
  scripts/language-table.py c verdicts.tsv            # all 944 rows required
  scripts/language-table.py c verdicts.tsv --partial  # while the audit is in progress
"""

import csv
import sys
from pathlib import Path

LANGS = {"c": ("C", ".c"), "cpp": ("C++", ".cpp"), "java": ("Java", ".java"), "go": ("Go", ".go"), "python": ("Python", ".py")}
TABLE = Path("audit/applicability/table.csv")


def main():
    args = [a for a in sys.argv[1:] if a != "--partial"]
    partial = "--partial" in sys.argv[1:]
    if len(args) != 2 or args[0] not in LANGS:
        sys.exit(f"usage: {sys.argv[0]} <{'|'.join(LANGS)}> <verdicts.tsv> [--partial]")
    lang, verdict_file = args
    _, ext = LANGS[lang]
    d = Path("audit/languages") / lang
    master = {r["cwe_id"]: r for r in csv.DictReader(TABLE.open())}
    rows = list(csv.DictReader((d / "rows.csv").open()))
    verdicts = dict(line.rstrip("\n").split("\t") for line in open(verdict_file) if "\t" in line)

    errors = []
    seen = set()
    for r in rows:
        c = r["cwe_id"]
        if c in seen:
            errors.append(f"{c}: duplicate row")
        seen.add(c)
        if c not in master:
            errors.append(f"{c}: not in {TABLE}")
        wh, woh = r["with_hatch"], r["without_hatch"]
        if wh not in ("yes", "no", "n/a") or woh not in ("yes", "no", "n/a"):
            errors.append(f"{c}: values must be yes, no or n/a")
        if woh == "yes" and wh != "yes":
            errors.append(f"{c}: writable without the escape hatch but not with it")
        if (wh == "n/a") != (woh == "n/a"):
            errors.append(f"{c}: n/a must be in both columns")
        if not r["reasoning"].strip():
            errors.append(f"{c}: no reasoning")
        ev = [] if r["evidence"] == "none" else r["evidence"].split(";")
        for e in ev:
            if not e.startswith(c + ".") or not e.endswith(ext) or not (d / e).is_file():
                errors.append(f"{c}: evidence {e} missing or misnamed")
        v = verdicts.get(c)
        if ev and v is None:
            errors.append(f"{c}: has evidence but no verdict from the check")
        if v == "writable" and (wh, woh) != ("yes", "yes"):
            errors.append(f"{c}: a program compiles without the escape hatch, so both columns must say yes")
        if v == "hatch-only" and (wh, woh) != ("yes", "no"):
            errors.append(f"{c}: only the escape hatch writes it, so the row must say yes, no")
        if v == "rejected" and (wh, woh) != ("no", "no"):
            errors.append(f"{c}: its programs are all rejected, so the row must say no")
        if v == "undecided":
            errors.append(f"{c}: the check could not decide")
    for c in verdicts:
        if c not in seen:
            errors.append(f"{c}: programs exist but no row")
    on_disk = {p.name.split(".")[0] for p in d.glob("CWE-*" + ext)}
    for c in sorted(on_disk - {e.split(".")[0] for r in rows if r["evidence"] != "none" for e in r["evidence"].split(";")}):
        errors.append(f"{c}: a program exists that no row cites")
    missing = sorted(set(master) - seen, key=lambda c: int(c.split("-")[1]))
    if missing and not partial:
        errors.append(f"{len(missing)} CWEs have no row, for example {', '.join(missing[:5])}")

    for e in errors:
        print(e, file=sys.stderr)
    print(f"{lang}: {len(rows)} of {len(master)} rows, {sum(1 for r in rows if r['evidence'] != 'none')} with programs, "
          f"{len(errors)} errors", file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
