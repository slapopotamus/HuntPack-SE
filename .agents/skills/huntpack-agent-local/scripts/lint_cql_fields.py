#!/usr/bin/env python3
"""Heuristic Falcon event/field linter for HuntPack CQL.

Uses an explicit maintained vocabulary and inspects filter, projection, join, and
function-argument positions. It does not prove tenant schema compatibility.
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

EVENTS = {
    "AsepValueUpdate", "ActiveDirectoryAuthenticationFailure",
    "ActiveDirectoryAccountLocked", "ActiveDirectoryAccountPasswordUpdate",
    "CommandHistory", "CreateService", "CriticalFileModified", "DnsRequest",
    "DnsRequestBlocked", "DriverLoad", "ELFFileWritten", "EndOfProcess",
    "FileOpenInfo", "FileReadInfo", "ImageHash", "InstalledApplication",
    "JarFileWritten", "NetworkConnectIP4", "NetworkConnectIP6", "NetworkListenIP4",
    "NetworkListenIP6", "NetworkReceiveAcceptIP4", "NetworkReceiveAcceptIP6",
    "NewExecutableRenamed", "NewExecutableWritten", "PeFileWritten", "ProcessBlocked",
    "ProcessRollup2", "ProcessRollup2Stats", "RansomwareOpenFile",
    "RegGenericValueUpdate", "RegSystemConfigValueUpdate", "ScheduledTaskDeleted",
    "ScheduledTaskModified", "ScheduledTaskRegistered", "ScriptControlScanTelemetry",
    "SuspiciousDnsRequest", "SyntheticProcessRollup2", "UserAccountCreated",
    "UserAccountDeleted", "UserLogoff", "UserLogon", "UserLogonFailed2", "ZipFileWritten",
}

FIELDS = {
    "aid", "aip", "cid", "#event_simpleName", "#event.dataset", "#repo",
    "@timestamp", "@ingesttimestamp", "@rawstring",
    "AccountDomain", "ADUser", "ApplicationName", "AuthenticationId",
    "CommandLine", "ComputerName", "ConnectionDirection", "ContextBaseFileName",
    "ContextProcessId", "ContextTimeStamp", "DnsResponseType", "DomainName", "DomainUser",
    "EventType", "FailureReason", "FileExtension", "FileName", "FilePath", "FileSize",
    "GrandparentBaseFileName", "ImageFileName", "ImageHash", "ImageSubsystem",
    "IntegrityLevel", "LocalAddressIP4", "LocalAddressIP6", "LocalPort", "LogonDomain",
    "LogonType", "MD5HashData", "ParentBaseFileName", "ParentCommandLine",
    "ParentProcessId", "ProcessEndTime", "ProcessStartTime", "Protocol", "RawProcessId",
    "RegBinaryValue", "RegObjectName", "RegOperationType", "RegStringValue", "RegType",
    "RegValueName", "RemoteAddressIP4", "RemoteAddressIP6", "RemotePort", "RequestType",
    "SamAccountName", "ScheduledTaskName", "ServiceDisplayName", "ServiceImagePath",
    "ServiceName", "SHA1HashData", "SHA256HashData", "SourceEndpointHostName",
    "SourceFileName", "TargetDirectoryName", "TargetFileName", "TargetProcessId",
    "TaskAuthor", "TaskExecutable", "TaskName", "TemporaryFileName", "TreeId",
    "UserIsAdmin", "UserName", "UserPrincipal", "UserPrincipalName", "UserSid",
    "BytesReceived", "BytesSent", "Protocol_decimal", "ContextProcessId_decimal",
    "TargetProcessId_decimal", "ParentProcessId_decimal", "RawProcessId_decimal",
}

NONFIELDS = {
    "as", "asc", "column", "desc", "end", "field", "format", "function", "include",
    "key", "limit", "mode", "name", "order", "percentiles", "query", "span", "start",
    "strict", "subnet", "table", "then", "timezone", "unit", "values", "where", "with",
    "true", "false", "left", "right", "inner", "distinct",
}

CQL_RE = re.compile(r'<pre[^>]*class="[^"]*\bcql\b[^"]*"[^>]*>(.*?)</pre>', re.I | re.S)


def blocks(page: str):
    for match in CQL_RE.finditer(page):
        yield htmllib.unescape(re.sub(r"<[^>]+>", "", match.group(1)))


def comments(text: str, kind: str):
    values = set()
    pattern = rf'^\s*//\s*{kind}\s+WAIVER:\s*([^|]+)\|\s*evidence:\s*(.+)$'
    for match in re.finditer(pattern, text, re.I | re.M):
        if match.group(2).strip():
            values.update(x.strip() for x in match.group(1).split(",") if x.strip())
    return values


def executable(text: str):
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("//")]
    return "\n".join(lines)


def strip_literals(text: str):
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", "''", text)
    text = re.sub(r'/(?:\\.|[^/\\])+/[ims]*', '//', text)
    return text


def aliases(text: str):
    found = set(re.findall(r'\b([A-Za-z_][\w.]*)\s*:=', text))
    found.update(re.findall(r'\bas\s*=\s*([A-Za-z_][\w.]*)', text))
    return found


def event_names(text: str):
    out = set()
    for match in re.finditer(r'#event_simpleName\s*=\s*(?:/([^/]+)/[ims]*|([A-Za-z][\w]*))', text):
        raw = match.group(1) or match.group(2)
        out.update(tok for tok in re.split(r'[^A-Za-z0-9]+', raw) if re.match(r'^[A-Z]', tok))
    return out


def field_names(text: str):
    clean = strip_literals(text)
    known_aliases = aliases(clean)
    found = set()

    for match in re.finditer(r'(?<![#@\w.])([A-Za-z_][\w.]*)\s*(?:==|!=|<=|>=|=|<|>)', clean):
        found.add(match.group(1))

    for match in re.finditer(r'\b(?:field|key|column)\s*=\s*([#@A-Za-z_][\w.#@]*)', clean):
        found.add(match.group(1))

    for match in re.finditer(r'\b(?:table|select|groupBy|sort|top|collect|sum|avg|min|max|count|formatTime|lower|upper|length|cidr)\s*\(\s*(\[[^\]]+\]|[#@A-Za-z_][\w.#@]*)', clean):
        raw = match.group(1)
        found.update(re.findall(r'[#@A-Za-z_][\w.#@]*', raw))

    for match in re.finditer(r'\b(?:include|field)\s*=\s*\[([^\]]+)\]', clean):
        found.update(re.findall(r'[#@A-Za-z_][\w.#@]*', match.group(1)))

    return {name for name in found if name not in known_aliases and name.lower() not in NONFIELDS}


def normalize(name: str):
    if name.startswith(("#", "@")):
        return name
    return re.sub(r'_(?:decimal|long|ip4|ip6)$', '', name, flags=re.I)


def lint_page(page: str):
    all_errors = []
    query_count = 0
    for query_count, text in enumerate(blocks(page), 1):
        exec_text = executable(text)
        field_waivers = comments(text, "FIELD")
        event_waivers = comments(text, "EVENT")
        for event in sorted(event_names(exec_text)):
            if event not in EVENTS and event not in event_waivers:
                all_errors.append((query_count, "event", event))
        for field in sorted(field_names(exec_text)):
            base = normalize(field)
            if field in FIELDS or base in FIELDS or field in field_waivers or base in field_waivers:
                continue
            all_errors.append((query_count, "field", field))
    if query_count == 0:
        all_errors.append((0, "query", "no CQL blocks"))
    return all_errors


def self_test():
    def page(cql):
        return f'<pre class="cql">{cql}</pre>'
    cases = [
        ("known event/field", page('#event_simpleName=ProcessRollup2\n| table([ComputerName])'), False),
        ("function option is not a field", page('#event_simpleName=ProcessRollup2\n| count(aid, distinct=true)'), False),
        ("fake comparison field", page('#event_simpleName=ProcessRollup2\n| DefinitelyFakeField=x'), True),
        ("fake function field", page('#event_simpleName=NetworkConnectIP4\n| cidr(TotallyFakeField, subnet="10.0.0.0/8")'), True),
        ("fake join field", page('#event_simpleName=ProcessRollup2\n| join(query={*}, field=InventedJoinKey)'), True),
        ("fake event", page('#event_simpleName=FileCreateInfo\n| table([ComputerName])'), True),
        ("evidenced field waiver", page('// FIELD WAIVER: tenant.special | evidence: sampled row 2026-08-19\n#repo=x\n| tenant.special=x'), False),
        ("zero blocks", '<html></html>', True),
    ]
    failed = 0
    for label, candidate, should_error in cases:
        got = bool(lint_page(candidate))
        ok = got == should_error
        print(f"{'PASS' if ok else 'FAIL'}  {label}: expected_error={should_error} got={got}")
        failed += 0 if ok else 1
    return 1 if failed else 0


def main(argv):
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if not args:
        print("usage: lint_cql_fields.py <pack.html> [...] | --self-test", file=sys.stderr)
        return 2
    worst = 0
    for path in args:
        try:
            page = open(path, encoding="utf-8").read()
        except OSError as exc:
            print(f"ERROR  {path}: {exc}")
            worst = max(worst, 2)
            continue
        errors = lint_page(page)
        if errors:
            worst = max(worst, 1)
            print(f"FIELD/EVENT REVIEW FAIL  {path}")
            for qn, kind, value in errors:
                print(f"  Q{qn}: unknown {kind}: {value}")
        else:
            print(f"FIELDS/EVENTS STATIC OK  {path}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
