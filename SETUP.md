# HuntPack Local — Setup

## Prerequisites

- OpenAI Codex or Claude Code.
- Python 3.9+ for static validation.
- PowerShell 7 only if you want the optional menu or distribution builder.

## Open the project

Clone or extract into a new folder and open that folder as the working project.
Codex reads `AGENTS.md` and `.agents/skills/`; Claude Code reads `CLAUDE.md` and
`.claude/skills/`.

Run `python scripts/doctor.py`. It verifies both skill trees, mirror parity, the
pack directory, the ad-hoc runner, and all local self-tests, and seeds the
Git-ignored `index.html` from `dist/index.template.html` when a fresh clone has
no library yet.

## First hunt

Paste one of these requests:

```text
Build a local hunt pack for CVE-2026-XXXXX
Run a local hunt on <actor, campaign, or malware>
Hunt this locally: <intel URL>
```

Output appears under `packs/<YYYY-MM>/` only after mandatory static gates pass. Failed/unpublished work remains under `.runs/` and is not indexed.

For a terminal-launched run, use:

```bash
python3 scripts/huntpack.py CVE-2026-XXXXX
```

The launcher auto-detects Codex CLI or Claude Code and uses the repository-local
skill. Select one explicitly with `--agent codex` or `--agent claude`; use
`--agent prompt` when you only want a copy/paste request. It never supplies a
dangerous permission-bypass flag.

## Optional advanced scope

General mode needs no setup. To add environment-specific scope:

```text
Configure my HuntPack local technology stack
```

Or copy `TECH_STACK.example.md` to `TECH_STACK.md` and complete it. Include products, versions, licensed/queryable telemetry, and §10 in/out-of-scope rules. Do not include credentials, real IPs, hostnames, internal domains, or secrets.

## Validation states

- `STATIC REVIEW PASSED`: local gates passed.
- `TENANT UNVERIFIED`: no Falcon execution evidence yet.
- `TENANT PARSE CONFIRMED`: intended repo accepted the query.
- `CANARY TESTED`: safe positive and benign tests were recorded.
- `DEPLOYED`: approved production use with measured behavior.

Only the last two states support “Good” operational coverage. A test plan is not test evidence.

## Troubleshooting

- Missing skill: confirm `.agents/skills/huntpack-agent-local/SKILL.md` for Codex or `.claude/skills/huntpack-agent-local/SKILL.md` for Claude Code.
- Missing Python: install Python 3.9+ and rerun `python scripts/doctor.py`.
- No `TECH_STACK.md`: valid; the hunt uses General mode.
- Pack not in the library: inspect `.runs/`; failed candidates are intentionally not self-healed into the index.
- No `index.html` after cloning: expected, it is local-only and Git-ignored. Run `python scripts/doctor.py` to seed it from `dist/index.template.html`.
- Ad-hoc run says a lock exists: verify no Codex/Claude generation is still active, then run `python scripts/huntpack.py --unlock`.
- Agent not found: add `codex` or `claude` to `PATH`, or use `--agent prompt` and paste the generated request into the desktop app.
- Wrong scope: update `TECH_STACK.md` §10 and build a new pack version.
- Shell launcher permission denied on macOS/Linux: run `chmod +x quick-start.sh`, or
  use `sh quick-start.sh`.
