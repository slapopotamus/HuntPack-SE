#!/usr/bin/env python3
"""Run the HuntPack static gate suite and optionally write a hash-bound sidecar."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys


def _utf8_console():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError):
                pass


_utf8_console()

HERE = os.path.dirname(os.path.abspath(__file__))
GATES = (
    ("structure_safety", "verify_huntpack.py"),
    ("field_event_heuristic", "lint_cql_fields.py"),
    ("cql_heuristic", "lint_cql_syntax.py"),
    ("ioc_provenance", "check_ioc_provenance.py"),
)


def run_gate(script: str, args: list[str]):
    command = [sys.executable, "-X", "utf8", os.path.join(HERE, script), *args]
    proc = subprocess.run(command, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout


def sha256(path: str):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(pack: str, sources_dir: str | None = None):
    rows = []
    for name, script in GATES:
        args = [pack]
        if name == "ioc_provenance" and sources_dir:
            args = ["--sources-dir", sources_dir, pack]
        code, output = run_gate(script, args)
        print(f"\n=== {name} (exit {code}) ===")
        print(output.rstrip())
        rows.append({"name": name, "exit_code": code,
                     "status": "pass" if code == 0 else "fail",
                     "provenance": "n/a" if "PROVENANCE N/A" in output else
                                   "ok" if "PROVENANCE OK" in output else None})
    return rows


def write_sidecar(pack: str, rows):
    stem, _ = os.path.splitext(pack)
    sidecar = stem + ".validation.json"
    payload = {
        "schema_version": 1,
        "generated_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "pack_file": os.path.basename(pack),
        "pack_sha256": sha256(pack),
        "static_pass": all(row["exit_code"] == 0 for row in rows),
        "tenant_validation": "TENANT UNVERIFIED",
        "gates": rows,
        "statement": "Static local checks only; no Falcon parser or tenant execution was performed.",
    }
    with open(sidecar, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"\nWROTE  {sidecar}")
    return sidecar


def self_test():
    worst = 0
    for name, script in GATES:
        code, output = run_gate(script, ["--self-test"])
        print(f"\n=== {name} self-test (exit {code}) ===")
        print(output.rstrip())
        worst = max(worst, code)
    return worst


def main(argv):
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    write = False
    sources_dir = None
    if "--write-sidecar" in args:
        args.remove("--write-sidecar")
        write = True
    if "--sources-dir" in args:
        index = args.index("--sources-dir")
        try:
            sources_dir = args[index + 1]
        except IndexError:
            print("--sources-dir requires a path", file=sys.stderr)
            return 2
        del args[index:index + 2]
    if len(args) != 1:
        print("usage: validate_huntpack.py [--write-sidecar] [--sources-dir DIR] <pack.html> | --self-test")
        return 2
    pack = args[0]
    if not os.path.isfile(pack):
        print(f"pack not found: {pack}", file=sys.stderr)
        return 2
    rows = validate(pack, sources_dir)
    if write:
        write_sidecar(pack, rows)
    passed = all(row["exit_code"] == 0 for row in rows)
    print(f"\n{'STATIC REVIEW PASSED / TENANT UNVERIFIED' if passed else 'STATIC REVIEW FAILED'}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
