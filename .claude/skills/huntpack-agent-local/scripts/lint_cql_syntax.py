#!/usr/bin/env python3
"""Offline CQL heuristic gate.

Rejects known breaking patterns and obvious malformed text. This is not a CQL
parser and must never be described as tenant parse confirmation.
"""

from __future__ import annotations

import html as htmllib
import re
import sys


def _utf8_console():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError):
                pass


_utf8_console()

CQL_RE = re.compile(r'<pre[^>]*class="[^"]*\bcql\b[^"]*"[^>]*>(.*?)</pre>', re.I | re.S)
FUNCTIONS = {
    "array:contains", "array:filter", "avg", "base64Decode", "case", "cidr", "coalesce",
    "collect", "concat", "count", "default", "defineTable", "drop", "eval", "eventSize",
    "field", "format", "formatTime", "groupBy", "head", "if", "in", "join", "kvParse",
    "length", "lower", "match", "max", "min", "now", "parseCsv", "parseJson", "parseUrl",
    "percentile", "regex", "rename", "replace", "select", "selectFromMax", "selectFromMin",
    "selfJoinFilter", "setField", "sort", "split", "splitString", "stdDev", "sum", "table",
    "tail", "test", "top", "upper",
}


def blocks(page: str):
    for match in CQL_RE.finditer(page):
        text = htmllib.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
        yield text


def executable(text: str):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def mask_literals(text: str):
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    text = re.sub(r'/(?:\\.|[^/\\])+/[ims]*', '//', text)
    return text


def delimiter_errors(text: str):
    masked = mask_literals(text)
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    errors = []
    for char in masked:
        if char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                errors.append("unbalanced delimiters")
                break
    if stack:
        errors.append("unbalanced delimiters")
    return errors


def lint_block(text: str):
    raw = executable(text).strip()
    masked = mask_literals(raw)
    errors = []
    warnings = []
    if not raw:
        return ["empty executable CQL"], warnings
    if not re.search(r'(?:#(?:event_simpleName|repo|event\.dataset)\b|\||:=|(?:==|!=|=|<|>))', masked):
        errors.append("text does not contain a recognizable CQL filter or pipeline")
    errors.extend(delimiter_errors(raw))

    patterns = (
        (r'\b[@\w.]+\s*[<>]=?\s*\(?\s*\w+\s*\(\s*\)',
         "function expression on comparison RHS; wrap the comparison in test()"),
        (r'\bcollect\s*\([^)]*\bas\s*=', "collect() does not accept as=; rename afterward"),
        (r'\bmatch\s*\(\s*\w+\s*\)\s*\{', "old match(field){...} form"),
        (r'\|\s*split\s*\(\s*["\']', "split() is not string splitting; use splitString()"),
        (r'\bformat\s*\(\s*["\']', "format() must use named format= and field= arguments"),
        (r'\bjoin\s*\([^)]*\bfield\s*=\s*(?:Target|Parent|Context|Raw)?ProcessId(?:_decimal)?\b(?![^)]*\baid\b)',
         "PID-only join can collide across hosts; include aid with the process ID"),
    )
    for pattern, message in patterns:
        if re.search(pattern, masked, re.I | re.S):
            if "comparison RHS" in message:
                # A test(...) wrapper is the documented exception.
                bad_lines = [line for line in raw.splitlines()
                             if re.search(pattern, mask_literals(line), re.I) and "test(" not in line]
                if not bad_lines:
                    continue
            errors.append(message)

    for line in masked.splitlines():
        if (re.search(r'\b(?:and|or)\b', line, re.I) and
                re.search(r'\b(?:in|cidr|regex|test)\s*\(', line, re.I)):
            errors.append("function call combined with and/or inside a filter group")

    aliases = set(re.findall(r'\b([A-Za-z_][\w]*)\s*:=', masked))
    aliases.update(re.findall(r'\bas\s*=\s*([A-Za-z_][\w]*)', masked))
    for match in re.finditer(r'(?<![#@:\w])([A-Za-z_][\w:]*)\s*\(', masked):
        name = match.group(1)
        if name in aliases or name in FUNCTIONS:
            continue
        if name.lower() in {x.lower() for x in FUNCTIONS}:
            warnings.append(f"non-canonical function case: {name}")
            continue
        errors.append(f"unknown function: {name}")

    return sorted(set(errors)), sorted(set(warnings))


def lint_page(page: str):
    found = list(blocks(page))
    if not found:
        return [(0, ["no CQL query blocks"], [])]
    return [(i, *lint_block(text)) for i, text in enumerate(found, 1)]


def self_test():
    def page(cql):
        return f'<pre class="cql">{cql}</pre>'
    cases = [
        ("valid", page('#event_simpleName=ProcessRollup2\n| table([ComputerName])'), False),
        ("arbitrary text", page('THIS IS NOT CQL'), True),
        ("unknown function", page('#event_simpleName=ProcessRollup2\n| nonsenseFunction(field=ComputerName)'), True),
        ("unbalanced", page('#event_simpleName=ProcessRollup2\n| groupBy([ComputerName]'), True),
        ("bad format args", page('#event_simpleName=ProcessRollup2\n| X := format("%s", ComputerName)'), True),
        ("function first in OR", page('#event_simpleName=ProcessRollup2\n| (in(FileName, values=[x]) or FileName=y)'), True),
        ("function second in OR", page('#event_simpleName=ProcessRollup2\n| (FileName=y or in(FileName, values=[x]))'), True),
        ("PID-only join", page('#event_simpleName=ProcessRollup2\n| join(query={*}, field=TargetProcessId_decimal)'), True),
        ("zero blocks", '<html></html>', True),
    ]
    failed = 0
    for label, candidate, should_error in cases:
        got = any(errors for _, errors, _ in lint_page(candidate))
        ok = got == should_error
        print(f"{'PASS' if ok else 'FAIL'}  {label}: expected_error={should_error} got={got}")
        failed += 0 if ok else 1
    return 1 if failed else 0


def main(argv):
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if not args:
        print("usage: lint_cql_syntax.py <pack.html> [...] | --self-test", file=sys.stderr)
        return 2
    worst = 0
    for path in args:
        try:
            page = open(path, encoding="utf-8").read()
        except OSError as exc:
            print(f"ERROR  {path}: {exc}")
            worst = max(worst, 2)
            continue
        rows = lint_page(page)
        errors = [(q, e) for q, errs, _ in rows for e in errs]
        warnings = [(q, w) for q, _, warns in rows for w in warns]
        if errors:
            worst = max(worst, 1)
            print(f"CQL HEURISTIC FAIL  {path}")
            for qn, message in errors:
                print(f"  Q{qn}: {message}")
        else:
            print(f"CQL HEURISTIC OK  {path} ({len(rows)} query block(s))")
        for qn, message in warnings:
            print(f"  WARN Q{qn}: {message}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
