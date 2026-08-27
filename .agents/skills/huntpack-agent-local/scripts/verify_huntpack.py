#!/usr/bin/env python3
"""Static HuntPack HTML structure and safety gate.

This gate checks packaging invariants. It does not parse CQL, contact Falcon, or
prove detection semantics. Exit 0 means the local HTML contract passed.
"""

from __future__ import annotations

import datetime as dt
import html as htmllib
import re
import sys


def _utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError):
                pass


_utf8_console()

CLOUDS = (
    "falcon.crowdstrike.com",
    "falcon.us-2.crowdstrike.com",
    "falcon.eu-1.crowdstrike.com",
    "falcon.laggar.gcw.crowdstrike.com",
    "falcon.us-gov-2.crowdstrike.mil",
)
REQUIRED_META = (
    "HUNT", "HYPOTHESIS", "USE", "MITRE", "CONF", "FP", "COST",
    "TIMEFRAME", "REQUIRES", "FALSE POSITIVES", "VALIDATION",
)
NOISY_FP = {"med", "medium", "high", "med-high", "medium-high"}
CQL_PRE = re.compile(
    r'<pre(?P<attrs>[^>]*class="[^"]*\bcql\b[^"]*"[^>]*)>(?P<body>.*?)</pre>',
    re.I | re.S,
)


def clean_pre(body: str) -> str:
    return htmllib.unescape(re.sub(r"<[^>]+>", "", body))


def query_blocks(page: str):
    blocks = []
    for match in CQL_PRE.finditer(page):
        attrs = match.group("attrs")
        qid = re.search(r'\bid="([^"]+)"', attrs, re.I)
        lookback = re.search(r'\bdata-lookback="([^"]+)"', attrs, re.I)
        blocks.append({
            "id": qid.group(1) if qid else "",
            "lookback": lookback.group(1) if lookback else "",
            "text": clean_pre(match.group("body")),
        })
    return blocks


def strip_inert(page: str) -> str:
    """Page with <style> and <script> removed.

    Every "does the pack contain X" check must run against this, not the raw
    page: the template inlines its own stylesheet, so `"tier-imm" in page` is
    true for a pack whose hardening section is empty.
    """
    return re.sub(r"<(script|style)\b.*?</\1>", " ", page, flags=re.I | re.S)


def section_body(page: str, number: int) -> str:
    """Markup of one numbered section, stylesheet and scripts removed."""
    start = re.search(rf'<(?:section|div)\b[^>]*\bid="s{number}"[^>]*>', page, re.I)
    if not start:
        return ""
    rest = page[start.end():]
    nxt = re.search(r'<(?:section|div)\b[^>]*class="[^"]*\bsection\b[^"]*"[^>]*\bid="s\d+"',
                    rest, re.I)
    end = nxt.start() if nxt else len(rest)
    return strip_inert(rest[:end])


def check(page: str):
    results: list[tuple[bool, str, str]] = []
    add = results.append

    section_ids = re.findall(
        r'<(?:section|div)\b[^>]*class="[^"]*\bsection\b[^"]*"[^>]*\bid="(s\d+)"',
        page, re.I,
    )
    missing_sections = [f"s{i}" for i in range(1, 16) if f"s{i}" not in section_ids]
    duplicate_sections = sorted({x for x in section_ids if section_ids.count(x) > 1})
    add((not missing_sections and not duplicate_sections, "15 unique required sections",
         "s1-s15 present" if not missing_sections and not duplicate_sections else
         f"missing={missing_sections or 'none'} duplicate={duplicate_sections or 'none'}"))

    sidebar_css = re.search(r'#sidebar\s*\{[^}]*\}', page, re.I | re.S)
    sidebar_text = sidebar_css.group(0) if sidebar_css else ""
    layout_ok = (
        'id="sidebar"' in page and "position: fixed" in sidebar_text and
        "left: 0" in sidebar_text and
        re.search(r'#main\s*\{[^}]*margin-left\s*:\s*\d', page, re.I | re.S)
    )
    add((bool(layout_ok), "fixed left navigation", "sidebar and main offset present"))

    toggle_ok = all(x in page for x in ("toc-toggle", "toggleToc", "toc-collapsed", "toc-shown"))
    add((toggle_ok, "desktop/mobile TOC toggle", "requires collapsed and mobile shown states"))

    s7 = re.search(r'<(?:section|div)[^>]*\bid="s7"[^>]*>(.*?)<(?:section|div)[^>]*\bid="s8"',
                   page, re.I | re.S)
    selector_ok = bool(s7 and 'id="cloud-region"' in s7.group(1))
    add((selector_ok, "Falcon cloud selector in s7", "selector must be inside CQL section"))

    missing_clouds = [cloud for cloud in CLOUDS if cloud not in page]
    add((not missing_clouds, "all five Falcon cloud hosts", ", ".join(missing_clouds) or "present"))

    blocks = query_blocks(page)
    ids = [b["id"] for b in blocks]
    unique_ids = bool(ids) and all(ids) and len(ids) == len(set(ids))
    add((bool(blocks), "at least one CQL query", f"{len(blocks)} query block(s)"))
    add((unique_ids, "unique CQL IDs", "all IDs unique" if unique_ids else f"ids={ids}"))

    cards = len(re.findall(r'class="[^"]*\bquery-card\b', page, re.I))
    add((cards == len(blocks) and cards > 0, "one query card per CQL block",
         f"cards={cards}, blocks={len(blocks)}"))

    action_errors = []
    for b in blocks:
        qid = re.escape(b["id"])
        if not re.search(rf"copyQuery\(\s*['\"]{qid}['\"]", page):
            action_errors.append(f"{b['id']}:copy")
        if not re.search(rf"openFalcon\(\s*['\"]{qid}['\"]", page):
            action_errors.append(f"{b['id']}:open")
    add((not action_errors, "Copy and Open actions per query", ", ".join(action_errors) or "wired"))

    meta_errors = []
    for b in blocks:
        headers = {m.group(1).upper(): m.group(2).strip()
                   for m in re.finditer(r'^\s*//\s*([A-Z][A-Z ]+):\s*(.+)$', b["text"], re.M)}
        missing = [name for name in REQUIRED_META if name not in headers]
        use = headers.get("USE", "").lower()
        validation = headers.get("VALIDATION", "").upper()
        fp = headers.get("FP", "").split()[0].lower() if headers.get("FP") else ""
        if missing:
            meta_errors.append(f"{b['id']}:missing {','.join(missing)}")
        if use not in {"inventory", "hunt", "alert-candidate"}:
            meta_errors.append(f"{b['id']}:bad USE")
        if validation not in {"STATIC-ONLY", "TENANT-PARSED", "CANARY-TESTED", "DEPLOYED"}:
            meta_errors.append(f"{b['id']}:bad VALIDATION")
        if fp in NOISY_FP and "TUNING" not in headers:
            meta_errors.append(f"{b['id']}:missing TUNING")
        if not re.fullmatch(r"\d+[mhdw]", b["lookback"], re.I):
            meta_errors.append(f"{b['id']}:bad data-lookback")
    add((not meta_errors, "canonical metadata and lookback per query",
         "; ".join(meta_errors[:8]) or "complete"))

    s9 = section_body(page, 9)
    grid_ok = "ioc-grab-grid" in s9 and "copyBlock(" in s9
    add((grid_ok, "grouped IOC quick-copy grid",
         "grid and copy action present in s9" if grid_ok else
         "s9 needs an .ioc-grab-grid of .ioc-grab cards with copyBlock() actions, "
         "or a specific dated statement that no atomic IOCs were published"))

    # ---- gold parity: analyst rationale on every query card -------------------
    # The published packs open every card with one plain-language sentence pair:
    # "Looks for: <what the query matches>. Accomplishes: <why an analyst cares>."
    # It is the difference between a query dump and a hunt pack a reader can use,
    # and it is interpretation of the analyst's own query -- it makes no source
    # claim, so it costs nothing in provenance terms.
    card_blocks = re.findall(r'(<div[^>]*class="[^"]*\bquery-card\b[^"]*"[^>]*>.*?)(?=<div[^>]*class="[^"]*\bquery-card\b|\Z)',
                             page, re.I | re.S)
    note_errors = []
    for idx, card in enumerate(card_blocks, 1):
        note = re.search(r'class="[^"]*\bqc-note\b[^"]*"[^>]*>(.*?)</p>', card, re.I | re.S)
        qid = re.search(r'\bid="([^"]+)"', card)
        label = qid.group(1) if qid else f"card{idx}"
        if not note:
            note_errors.append(f"{label}:no .qc-note")
            continue
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", note.group(1))).strip()
        low = text.lower()
        if "looks for" not in low or "accomplishes" not in low:
            note_errors.append(f"{label}:note needs 'Looks for:' and 'Accomplishes:'")
        elif len(text) < 90:
            note_errors.append(f"{label}:note only {len(text)} chars")
    add((not note_errors, "analyst rationale on every query card",
         "; ".join(note_errors[:6]) or f"{len(card_blocks)} card(s) carry Looks for / Accomplishes"))

    # ---- every card is filterable -------------------------------------------
    # Without data-use the filter buttons hide every card and the section goes
    # blank on screen. The value must also agree with the query's own // USE:.
    use_errors = []
    for idx, card in enumerate(card_blocks, 1):
        qid = re.search(r'\bid="([^"]+)"', card)
        label = qid.group(1) if qid else f"card{idx}"
        attr = re.search(r'\bdata-use="([^"]*)"', card)
        if not attr:
            use_errors.append(f"{label}:no data-use")
            continue
        value = attr.group(1).strip().lower()
        if value not in {"inventory", "hunt", "alert-candidate"}:
            use_errors.append(f"{label}:data-use={value or 'empty'}")
            continue
        header = re.search(r'//\s*USE:\s*([a-z-]+)', htmllib.unescape(card), re.I)
        if header and header.group(1).strip().lower() != value:
            use_errors.append(f"{label}:data-use={value} but // USE: {header.group(1)}")
    add((not use_errors, "query cards carry a matching data-use",
         "; ".join(use_errors[:6]) or "all cards filterable"))

    # ---- gold parity: hardening carries all three tiers -----------------------
    s10 = section_body(page, 10)
    tiers = {"immediate": "tier-imm", "near-term": "tier-near", "strategic": "tier-strat"}
    missing_tiers = [name for name, cls in tiers.items()
                     if not re.search(rf'class="[^"]*\b{cls}\b[^"]*"', s10)]
    add((not missing_tiers, "hardening covers all three tiers",
         "immediate, near-term, strategic present" if not missing_tiers else
         "missing: %s -- populate the tier or state why no safe control exists there"
         % ", ".join(missing_tiers)))

    # ---- gold parity: the hunt ticket is paste-ready --------------------------
    # A ticket rendered as prose cannot be pasted into an ITSM tool, which is the
    # entire point of the section.
    ticket_seg = section_body(page, 13)
    ticket_ok = bool(re.search(r'class="[^"]*\bticket\b', ticket_seg)) and "<pre" in ticket_seg \
        and "copyBlock(" in ticket_seg
    add((ticket_ok, "hunt ticket is a copyable block",
         "ticket block with copy action" if ticket_ok else
         "s13 needs .ticket + <pre> + a copyBlock() button so it can be pasted into a ticket"))

    # ---- gold parity: changelog uses the library's entry markup --------------
    s14 = section_body(page, 14)
    chg_ok = bool(re.search(r'class="[^"]*\bchg-entry\b', s14)) and "chg-ver" in s14
    add((chg_ok, "changelog entries use library markup",
         "chg-entry/chg-ver present" if chg_ok else "s14 needs .chg-entry with .chg-ver/.chg-date"))

    # ---- no stub sections ----------------------------------------------------
    # The old gate accepted a pack whose every section body was the word
    # "content". A section that thin is a gap, not a section: either write it or
    # state the specific, dated reason it is empty.
    bodies = re.findall(
        r'<(?:section|div)\b[^>]*class="[^"]*\bsection\b[^"]*"[^>]*\bid="(s\d+)"(.*?)(?=<(?:section|div)\b[^>]*class="[^"]*\bsection\b[^"]*"[^>]*\bid="s\d+"|</main>|<div class="hp-footer")',
        page, re.I | re.S)
    thin = []
    for sid, body in bodies:
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
        if len(text) < 180:
            thin.append(f"{sid}:{len(text)}c")
    add((not thin, "no stub sections",
         "; ".join(thin[:8]) + " -- each section needs real content or a specific dated absence statement"
         if thin else "all sections carry content"))

    unresolved = re.findall(r"(?:populate from hunt findings|TODO|TBD|<fill in>|REPLACE_WITH_(?!HOSTNAME|USERNAME|AID|TIMESTAMP))",
                            page, re.I)
    add((not unresolved, "no unresolved mandatory placeholders",
         "none" if not unresolved else ", ".join(sorted(set(unresolved))[:8])))

    unsafe = []
    checks = {
        "javascript URL": r'javascript\s*:',
        "active frame/form/object": r'<\s*(?:iframe|form|object|embed)\b',
        "external script": r'<script\b[^>]*\bsrc\s*=',
        "external stylesheet": r'<link\b[^>]*\brel\s*=\s*["\']?stylesheet',
        "dangerous event attribute": r'\s(?:onerror|onload|onmouseover|onfocus|onanimationstart)\s*=',
        "meta refresh": r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh',
    }
    for label, pattern in checks.items():
        if re.search(pattern, page, re.I):
            unsafe.append(label)
    add((not unsafe, "offline HTML safety", ", ".join(unsafe) or "no active injected content"))

    raw_ge = [n for n, line in enumerate(strip_inert(page).splitlines(), 1)
              if ">=" in line]
    add((not raw_ge, "CQL comparison escaping",
         "escaped" if not raw_ge else
         "raw >= on lines %s -- write it as &gt;= inside pre blocks so the HTML stays valid"
         % raw_ge[:8]))

    bad_tokens = []
    allowed_tags = {"span", "/span", "code", "/code", "b", "/b", "i", "/i", "em", "/em",
                    "strong", "/strong", "br"}
    for pre in re.finditer(r"<pre[^>]*>(.*?)</pre>", page, re.I | re.S):
        for token in re.finditer(r"<(/?[A-Za-z][\w:-]*)>", pre.group(1)):
            if token.group(1).lower() not in allowed_tags:
                bad_tokens.append(token.group(0))
    add((not bad_tokens, "escaped angle tokens in pre blocks",
         ", ".join(sorted(set(bad_tokens))[:8]) or "escaped"))

    banner = "STATIC REVIEW PASSED" in page and any(x in page for x in
        ("TENANT UNVERIFIED", "TENANT PARSE CONFIRMED", "CANARY TESTED", "DEPLOYED"))
    add((banner, "visible validation-state banner", "static and tenant state visible"))
    # ---- gold parity: the published-library template vocabulary --------------
    # These class names are what the online HuntPack library uses. Matching them
    # is what makes a local pack look like a published one, and the publish-side
    # tooling reads .mk/.mv specifically -- .meta-label/.meta-value parse as
    # nothing. Local-only additions (.state, .qc-note, .query-tools, .hp-footer)
    # are deliberately NOT listed: they are improvements over gold, not drift.
    GOLD_CLASSES = (
        "sidebar-logo", "brand", "pack-name", "version", "nav-section",
        "hp-header", "subtitle", "meta-grid", "meta-item", "mk", "mv",
        "section", "section-hdr", "section-body", "snum",
        "query-card", "qc-header", "qc-title", "qc-body", "badge",
        "cloud-sel", "callout", "code", "cql",
    )
    present = {c for attr in re.findall(r'class="([^"]+)"', page) for c in attr.split()}
    absent = [c for c in GOLD_CLASSES if c not in present]
    add((not absent, "gold template class vocabulary",
         "all %d present" % len(GOLD_CLASSES) if not absent else
         "missing: %s -- rename to the published-library names" % ", ".join(absent[:8])))

    # ---- gold parity: the cloud-selector hint, inline beside the selector ----
    hint = "Pick your tenant's cloud first"
    ci = page.find('class="cloud-sel"')
    nested = False
    if ci >= 0:
        sel = page.find("</select>", ci)
        end = page.find("</div>", sel) if sel >= 0 else -1
        nested = end >= 0 and hint in page[ci:end]
    wrapped = re.search(r"\.cloud-sel[^{]*\{[^}]*flex-wrap:\s*wrap", page) is not None
    add((hint in page and nested and wrapped, "cloud-selector hint inline",
         "hint shares the selector row" if (hint in page and nested and wrapped) else
         "hint missing, outside .cloud-sel, or .cloud-sel lacks flex-wrap:wrap"))

    # ---- Executive Summary must carry the threat, not the build config ------
    # S1 is the only section most readers finish. Measured across 196 published
    # packs: median 2,135 chars of visible text, 100% carry a callout, 94% use
    # bold lead-ins, 94% close on a "Defender priority:" line. A summary that
    # opens with the generator's scope mode burns the most valuable line in the
    # pack, so the banned-phrase list is a hard failure, not a warning.
    i1, i2 = page.find('id="s1"'), page.find('id="s2"')
    if i1 >= 0 and i2 > i1:
        seg = page[i1:i2]
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", seg)).strip()
        probs = []
        if len(text) < 1500:
            probs.append("%d chars of visible text, need >=1500" % len(text))
        if "callout" not in seg:
            probs.append("no callout")
        if len(re.findall(r"<strong>", seg)) < 2:
            probs.append("fewer than 2 bold lead-ins")
        if "defender priority" not in text.lower():
            probs.append("no 'Defender priority:' line")
        banned = [b for b in ("General mode", "General-mode", "No TECH_STACK",
                              "unscoped", "stack-scoped", "TECH_STACK.md")
                  if b.lower() in text.lower()]
        if banned:
            probs.append("build-config wording in the summary: %s" % ", ".join(banned))
        add((not probs, "Executive Summary carries the threat",
             "%d chars, callout, bold lead-ins, defender priority" % len(text)
             if not probs else "; ".join(probs)))
    # Build-config wording is banned EVERYWHERE reader-facing, not just in S1.
    # The first version of this check scanned only section 1, which let a
    # "Scope: General mode - unscoped" meta-item in the page header through
    # untouched -- and the header is the most prominent place in the pack.
    doc = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                 re.sub(r"<(script|style).*?</\1>", " ", page, flags=re.S)))
    leaked = [b for b in ("General mode", "General-mode", "No TECH_STACK",
                          "unscoped", "stack-scoped", "TECH_STACK.md")
              if b.lower() in doc.lower()]
    add((not leaked, "no build-config wording in reader-facing output",
         "clean" if not leaked else
         "found %s -- scope mode is a build-time input, not threat intelligence; "
         "state coverage limits in telemetry terms instead" % ", ".join(leaked)))



    return results


def valid_fixture() -> str:
    # A minimal pack that satisfies every gate. Deliberately boring prose, but
    # *complete* prose: the fixture has to exercise the same floors a real pack
    # does, or the gates rot.
    filler = (
        "<p>This fixture section carries enough real sentences to clear the stub-section "
        "floor. It names the behavior under test, the telemetry it depends on, and the "
        "limitation a reader should carry forward into their own tenant. Nothing here is "
        "threat intelligence; it exists so the structural gates have something honest to "
        "measure.</p>"
    )
    summary = (
        "<p><strong>What happened:</strong> a fixture vendor published a fixture report on "
        "2026-01-01 describing a loader that arrives as a signed installer and drops a "
        "scheduled task. <strong>How it works:</strong> the installer writes a small "
        "JScript file into the user profile, registers a task that runs it through "
        "wscript.exe every thirty minutes, and beacons over HTTPS to a rotating set of "
        "hosts using a fixed user-agent string. Persistence survives reboot because the "
        "task is registered under the user hive rather than the machine hive. "
        "<strong>Where detection lives:</strong> the durable signal is the script host "
        "executing a file from a user-writable path with a task-scheduler parent; the "
        "network infrastructure rotates weekly and the file names change per build, so "
        "neither is a durable anchor. Hunt the behavior, enrich with the atomics, and "
        "expect the domains to age out within days of publication. This fixture text "
        "exists to satisfy the executive-summary floor with the same shape a real pack "
        "uses, including the closing instruction below.</p>"
        '<p><strong>Why the atomics age out:</strong> the fixture campaign rotates its delivery hosts on a weekly cadence and recompiles the dropper for each wave, so hashes and domains published on the day of the report are stale within about ten days. Treat them as enrichment for a hit you already have, never as the primary hunt. The scheduled task name varies per install, but the parent-child shape does not: taskeng or svchost spawns the script host, the script host reads from a path the user can write, and the process exits quickly after the first beacon. That shape is what the queries in this fixture anchor on, and it is what a reader should carry into their own tenant even if every indicator in the appendix has expired by the time they read it.</p>'
        '<div class="callout callout-info"><strong>Defender priority:</strong> hunt '
        "script-host execution from user-writable paths before chasing the atomic "
        "indicators.</div>"
    )
    cql_card = '''<div class="query-card" data-use="hunt">
<div class="qc-header"><span class="qc-title">Q1 &middot; script host running a file from a user-writable path</span>
<div class="qc-badges"><span class="badge b-low">CONF HIGH</span><span class="badge b-low">FP LOW</span><span class="badge b-low">COST LOW</span></div>
<div class="qc-actions"><button class="btn-copy" onclick="copyQuery('cql1',this)">Copy CQL</button><button class="btn-falcon" onclick="openFalcon('cql1')">Open in Falcon</button></div></div>
<div class="qc-body">
<p class="qc-note"><strong>Looks for:</strong> wscript.exe or cscript.exe executing a script from a user-writable directory. <strong>Accomplishes:</strong> catches the loader at execution, which is the one stage that does not change between builds.</p>
<pre class="cql" id="cql1" data-lookback="7d"><span class="cm">// HUNT: Script host executes from a user-writable path</span>
// HYPOTHESIS: H01
// USE: hunt
// MITRE: T1059.007
// CONF: medium
// FP: medium
// COST: low
// TIMEFRAME: 7d &mdash; covers a full patch week
// REQUIRES: ProcessRollup2, FileName, CommandLine
// FALSE POSITIVES: administrators running approved automation
// TUNING: exclude approved scripts under the software distribution path
// VALIDATION: STATIC-ONLY
#event_simpleName=ProcessRollup2
| table([ComputerName])</pre></div></div>'''
    ioc = ('<div class="ioc-grab-grid">'
           '<div class="ioc-grab"><div class="igh"><span class="igt">CSV</span>'
           '<span class="igc">1 row</span></div>'
           '<button onclick="copyBlock(\'grab-csv\',this)" data-label="Copy CSV">Copy CSV</button>'
           '<pre class="code" id="grab-csv">type,value,source,volatility</pre></div></div>' + filler)
    tiers = ('<div class="tier-blk tier-imm"><div class="tier-lbl">Immediate</div>'
             '<ul><li><strong>Constrain script hosts</strong> for standard users (M1038).</li></ul></div>'
             '<div class="tier-blk tier-near"><div class="tier-lbl">Near-term</div>'
             '<ul><li><strong>Baseline scheduled-task creation</strong> per business unit (M1047).</li></ul></div>'
             '<div class="tier-blk tier-strat"><div class="tier-lbl">Strategic</div>'
             '<ul><li><strong>Application control</strong> for interpreters (M1038).</li></ul></div>' + filler)
    ticket = ('<div class="ticket"><button onclick="copyBlock(\'ticket-block\',this)" '
              'data-label="Copy ticket">Copy ticket</button>'
              '<pre class="code" id="ticket-block">TITLE: Fixture hunt\nSEVERITY: medium\n'
              'SCOPE: fixture\nQUERIES RUN: Q1\nDO FIRST: run Q1 over 7d\nFINDINGS: none recorded\n'
              'GAPS: tenant parse unverified\nOWNER: cybersecurity analyst\nVERSION: v0.1</pre></div>'
              + filler)
    changelog = ('<div class="chg-entry"><span class="chg-ver">v0.1</span>'
                 '<span class="chg-date">2026-01-01</span><span>Initial fixture draft.</span></div>'
                 + filler)
    cloud = ('<div class="cloud-sel"><label for="cloud-region">Falcon cloud</label>'
             '<select id="cloud-region">'
             '<option value="https://falcon.crowdstrike.com">US-1</option>'
             '<option value="https://falcon.us-2.crowdstrike.com">US-2</option>'
             '<option value="https://falcon.eu-1.crowdstrike.com">EU-1</option>'
             '<option value="https://falcon.laggar.gcw.crowdstrike.com">US-GOV-1</option>'
             '<option value="https://falcon.us-gov-2.crowdstrike.mil">US-GOV-2</option></select>'
             '<span class="cloud-hint">Pick your tenant\'s cloud first &mdash; every "Open in '
             'Falcon" button below uses this selection.</span></div>')

    special = {1: summary, 7: cloud + cql_card + filler, 9: ioc, 10: tiers, 13: ticket, 14: changelog}
    sections = []
    for i in range(1, 16):
        body = special.get(i, filler)
        sections.append(
            f'<div class="section" id="s{i}"><div class="section-hdr"><span class="snum">'
            f'{i:02d}</span><h2>Fixture section {i}</h2></div>'
            f'<div class="section-body">{body}</div></div>'
        )
    head = '''<!doctype html><style>#sidebar { position: fixed; top: 0; left: 0; width: 210px; }
#main { margin-left: 210px; } .cloud-sel { display: flex; flex-wrap: wrap; }
.toc-shown{display:block} .toc-collapsed{display:block}</style>
<button id="toc-toggle" onclick="toggleToc()">x</button>
<nav id="sidebar"><div class="sidebar-logo"><div class="brand">HUNTPACK</div>
<div class="pack-name">Fixture</div><div class="version">v0.1</div></div>
<nav><div class="nav-section">Overview</div><a href="#s1">1</a></nav></nav><main id="main">
<div class="hp-header"><h1>Fixture pack</h1><div class="subtitle">Structural fixture, not threat intelligence.</div>
<div class="meta-grid"><div class="meta-item"><div class="mk">Threat</div><div class="mv">Fixture</div></div></div></div>
<div class="state"><span class="state-dot"></span><strong>STATIC REVIEW PASSED / TENANT UNVERIFIED</strong></div>
<p>Fixture body uses <code>code</code> spans.</p>'''
    tail = '''</main><script>
function toggleToc(){document.body.classList.toggle('toc-collapsed');document.body.classList.toggle('toc-shown')}
function copyQuery(){} function openFalcon(){} function copyBlock(){}
var sections=[]; window.addEventListener('scroll',function(){var scrollY=window.scrollY; if(scrollY >= 0){}});</script>'''
    return head + "".join(sections) + tail


def self_test() -> int:
    fixture = valid_fixture()
    cases = [
        ("valid fixture", fixture, True),
        ("zero query blocks", re.sub(r'<div class="query-card".*?</pre></div></div>', "", fixture, flags=re.S), False),
        ("missing section", re.sub(r'<div class="section" id="s6">.*?(?=<div class="section" id="s7")', "", fixture, flags=re.S), False),
        ("duplicate query id", fixture.replace('</main>', '<div class="section" id="extra"><pre class="cql" id="cql1" data-lookback="7d">x</pre></div></main>'), False),
        ("injected javascript", fixture.replace("<h2>Fixture section 2</h2>", '<img src=x onerror="alert(1)">', 1), False),
        ("missing metadata", fixture.replace("// HYPOTHESIS: H01\n", ""), False),
        ("stub section", re.sub(r'(<div class="section" id="s6">.*?<div class="section-body">).*?(</div></div>)', r"\1content\2", fixture, flags=re.S), False),
        ("query card without rationale", re.sub(r'<p class="qc-note">.*?</p>', "", fixture, flags=re.S), False),
        ("prose-only hunt ticket", re.sub(r'<div class="ticket">.*?</div>\s*(?=<p>This fixture)', "<p>Ticket as prose.</p>", fixture, flags=re.S), False),
        ("hardening tier removed", re.sub(r'<div class="tier-blk tier-near">.*?</div></div>', "", fixture, flags=re.S), False),
        ("changelog entry removed", re.sub(r'<div class="chg-entry">.*?</div>\s*(?=<p>This fixture)', "", fixture, flags=re.S), False),
        ("IOC grab grid removed", re.sub(r'<div class="ioc-grab-grid">.*?</div></div>\s*(?=<p>This fixture)', "", fixture, flags=re.S), False),
        ("query card without data-use", fixture.replace('<div class="query-card" data-use="hunt">', '<div class="query-card">', 1), False),
        ("data-use disagrees with // USE:", fixture.replace('<div class="query-card" data-use="hunt">', '<div class="query-card" data-use="inventory">', 1), False),
    ]
    failures = 0
    for label, page, expected in cases:
        got = all(item[0] for item in check(page))
        ok = got == expected
        print(f"{'PASS' if ok else 'FAIL'}  {label}: expected={expected} got={got}")
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if not args:
        print("usage: verify_huntpack.py <pack.html> [...] | --self-test", file=sys.stderr)
        return 2
    all_ok = True
    for path in args:
        try:
            with open(path, encoding="utf-8") as handle:
                page = handle.read()
        except OSError as exc:
            print(f"FAIL  {path}: {exc}")
            all_ok = False
            continue
        results = check(page)
        ok = all(item[0] for item in results)
        all_ok &= ok
        print(f"\n{'PASS' if ok else 'FAIL'}  {path}")
        for passed, label, detail in results:
            print(f"  {'OK' if passed else 'FAIL'}  {label} — {detail}")
        today = dt.date.today().isoformat()
        print(f"  {'INFO' if today in page else 'WARN'}  current date {today} {'present' if today in page else 'absent'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
