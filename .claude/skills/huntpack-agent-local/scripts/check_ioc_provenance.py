#!/usr/bin/env python3
"""Current-run IOC-to-source provenance gate.

Requires source-tagged IOC CSV rows, a source manifest with snapshot hashes, and
literal IOC presence in the specifically cited current snapshot. Literal presence
proves transcription, not maliciousness or safe blocking.
"""

from __future__ import annotations

import csv
import hashlib
import html as htmllib
import ipaddress
import json
import os
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

HASH_RE = re.compile(r'\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b', re.I)
BENIGN_DOMAINS = {
    "example.com", "example.org", "example.net", "attack.mitre.org", "nvd.nist.gov",
    "cisa.gov", "crowdstrike.com", "falcon.crowdstrike.com",
}
# A filename is not a domain. The domain sweep matches any <word>.<tld>-shaped
# string, so a pack that merely names explorer.exe or file.hta in its IOC section
# was being forced to prove provenance for a Windows binary. Anything whose last
# label is a known file extension is excluded before the sweep.
FILE_EXTENSIONS = {
    "bat", "bin", "cab", "cmd", "com", "cpl", "dat", "dll", "doc", "docx", "exe",
    "gif", "hta", "htm", "html", "img", "ini", "iso", "jar", "jpeg", "jpg", "js",
    "jse", "json", "lnk", "log", "msi", "mp3", "mp4", "pdf", "pif", "png", "ps1",
    "psm1", "py", "scr", "sys", "tmp", "txt", "vbe", "vbs", "wav", "wsf", "xls",
    "xlsx", "xml", "zip",
}


def refang(value: str):
    value = htmllib.unescape(value).lower()
    value = value.replace("hxxps", "https").replace("hxxp", "http")
    for token in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        value = value.replace(token, ".")
    return re.sub(r'[\u200b-\u200d\ufeff]', '', value).strip()


def default_sources_dir(pack: str):
    stem, _ = os.path.splitext(pack)
    return stem + "-sources"


def csv_block(page: str):
    match = re.search(r'<pre[^>]*\bid="grab-csv"[^>]*>(.*?)</pre>', page, re.I | re.S)
    return htmllib.unescape(re.sub(r'<[^>]+>', '', match.group(1))) if match else ""


def parse_csv_iocs(page: str):
    rows = []
    block = csv_block(page)
    if not block:
        return rows
    reader = csv.reader(block.splitlines())
    header = None
    for raw in reader:
        if not raw:
            continue
        if header is None:
            header = [x.strip().lower() for x in raw]
            continue
        if len(raw) < 2:
            continue
        record = {header[i]: raw[i].strip() for i in range(min(len(header), len(raw)))}
        value = record.get("value", raw[1].strip())
        if not value or value.upper().startswith("REPLACE_WITH"):
            continue
        tags = record.get("tags", "") + " " + record.get("description", "")
        source_ids = sorted(set(re.findall(r'\bsource:(S\d{2,})\b', tags, re.I)))
        rows.append({"type": record.get("type", raw[0].strip()).lower(),
                     "value": value, "source_ids": [x.upper() for x in source_ids]})
    return rows


def section(page: str, number: int):
    start = re.search(rf'<(?:section|div)[^>]*\bid="s{number}"[^>]*>', page, re.I)
    if not start:
        return ""
    next_section = re.search(r'<(?:section|div)[^>]*\bid="s\d+"[^>]*>', page[start.end():], re.I)
    end = start.end() + next_section.start() if next_section else len(page)
    return htmllib.unescape(re.sub(r'<[^>]+>', ' ', page[start.end():end]))


def is_public_ip(value: str):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or
                ip.is_reserved or ip.is_unspecified)


def swept_iocs(page: str):
    body = refang(section(page, 4) + "\n" + section(page, 9))
    found = set(HASH_RE.findall(body))
    found.update(ip for ip in IPV4_RE.findall(body) if is_public_ip(ip))
    for domain in DOMAIN_RE.findall(body):
        if domain in BENIGN_DOMAINS or domain.endswith(".example.com"):
            continue
        if any(domain == benign or domain.endswith("." + benign) for benign in BENIGN_DOMAINS):
            continue
        if domain.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS:
            continue
        found.add(domain)
    return {refang(x) for x in found}


def load_manifest(source_dir: str):
    path = os.path.join(source_dir, "manifest.json")
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"missing/invalid source manifest: {exc}")
    sources = data.get("sources") if isinstance(data, dict) else data
    if not isinstance(sources, list):
        raise ValueError("source manifest must contain a sources array")
    mapped = {}
    for item in sources:
        required = {"source_id", "url", "accessed_utc", "snapshot", "sha256", "retrieval_status"}
        missing = required - set(item)
        if missing:
            raise ValueError(f"manifest entry missing {sorted(missing)}")
        sid = str(item["source_id"]).upper()
        filename = os.path.basename(str(item["snapshot"]))
        path = os.path.join(source_dir, filename)
        try:
            raw = open(path, "rb").read()
        except OSError as exc:
            raise ValueError(f"{sid} snapshot unreadable: {exc}")
        digest = hashlib.sha256(raw).hexdigest()
        if digest.lower() != str(item["sha256"]).lower():
            raise ValueError(f"{sid} snapshot hash mismatch")
        mapped[sid] = refang(raw.decode("utf-8", errors="replace"))
    return mapped


def exact_present(value: str, corpus: str):
    value = refang(value)
    if HASH_RE.fullmatch(value):
        return re.search(rf'(?<![0-9a-f]){re.escape(value)}(?![0-9a-f])', corpus) is not None
    if IPV4_RE.fullmatch(value):
        return re.search(rf'(?<![\d.]){re.escape(value)}(?![\d.])', corpus) is not None
    return re.search(rf'(?<![A-Za-z0-9.-]){re.escape(value)}(?![A-Za-z0-9-])', corpus) is not None


def check_pack(pack: str, source_dir: str | None = None):
    try:
        page = open(pack, encoding="utf-8").read()
    except OSError as exc:
        print(f"ERROR  {pack}: {exc}")
        return 2, "ERROR"
    rows = parse_csv_iocs(page)
    swept = swept_iocs(page)
    if not rows and not swept:
        print(f"PROVENANCE N/A  {pack} — no atomic IOCs in sections 4/9")
        return 0, "N/A"
    source_dir = source_dir or default_sources_dir(pack)
    try:
        manifest = load_manifest(source_dir)
    except ValueError as exc:
        print(f"PROVENANCE FAIL  {pack} — {exc}")
        return 2, "FAIL"

    errors = []
    row_values = {refang(row["value"]) for row in rows}
    for value in sorted(swept - row_values):
        errors.append(f"atomic IOC appears in s4/s9 but not source-tagged grab-csv: {value}")
    for row in rows:
        if not row["source_ids"]:
            errors.append(f"{row['value']}: missing source:Sxx tag")
            continue
        missing = [sid for sid in row["source_ids"] if sid not in manifest]
        if missing:
            errors.append(f"{row['value']}: unknown source IDs {missing}")
            continue
        if not any(exact_present(row["value"], manifest[sid]) for sid in row["source_ids"]):
            errors.append(f"{row['value']}: absent from specifically cited current snapshots")
    if errors:
        print(f"PROVENANCE FAIL  {pack}")
        for error in errors:
            print(f"  {error}")
        return 1, "FAIL"
    print(f"PROVENANCE OK  {pack} — {len(rows)} IOC(s) bound to current hashed snapshots")
    return 0, "OK"


def self_test():
    failures = 0
    source_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "fixtures", "provenance-sources")
    manifest = load_manifest(source_dir)
    good = '<div id="s4">No extra IOCs</div><div id="s5"></div><div id="s9"><pre id="grab-csv">type,value,action,severity,expiration,description,tags\nsha256,' + ('a' * 64) + ',detect,high,2027-01-01,test,source:S01</pre></div><div id="s10"></div>'
    cases = [
        ("exact current source", good, True),
        ("missing source tag", good.replace("source:S01", "campaign:test"), False),
        ("wrong value", good.replace("a" * 64, "b" * 64), False),
    ]
    filenames = '<div id="s4">explorer.exe file.hta payload.ps1 report.docx</div><div id="s5"></div>'
    swept = swept_iocs(filenames)
    label = "filenames are not domains"
    ok = not swept
    print(f"{'PASS' if ok else 'FAIL'}  {label}: expected=set() got={sorted(swept)}")
    failures += 0 if ok else 1
    for label, page, expected in cases:
        rows = parse_csv_iocs(page)
        traced = bool(rows and rows[0]["source_ids"] and
                      any(exact_present(rows[0]["value"], manifest[sid])
                          for sid in rows[0]["source_ids"] if sid in manifest))
        ok = traced == expected
        print(f"{'PASS' if ok else 'FAIL'}  {label}: expected={expected} got={traced}")
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv):
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    source_dir = None
    if "--sources-dir" in args:
        index = args.index("--sources-dir")
        try:
            source_dir = args[index + 1]
        except IndexError:
            return 2
        del args[index:index + 2]
    if not args:
        print("usage: check_ioc_provenance.py [--sources-dir DIR] <pack.html> [...] | --self-test")
        return 2
    worst = 0
    for pack in args:
        code, _ = check_pack(pack, source_dir)
        worst = max(worst, code)
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
