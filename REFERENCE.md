# HuntPack Local

Build evidence-backed, analyst-ready CrowdStrike HuntPacks with Claude Code or
OpenAI Codex. The framework is cross-platform and prompt-first; generated hunts
stay on the analyst's machine. `TECH_STACK.md` is an optional advanced scope
profile, not a prerequisite.

## Start

```bash
git clone https://github.com/slapopotamus/huntpack_local_testing.git
cd huntpack_local_testing
```

Open the folder in Claude Code or Codex and type:

```text
Build a local hunt pack for Scattered Spider
Build a local hunt pack for CVE-2026-XXXXX
Hunt this locally: https://example.com/threat-report
Run the local HuntPack auto scan
```

Or start a complete ad-hoc run from a terminal:

```bash
python3 scripts/huntpack.py Scattered Spider
python3 scripts/huntpack.py CVE-2026-XXXXX --agent claude
python3 scripts/huntpack.py auto --lookback 48h
```

The runner auto-detects Codex or Claude Code, invokes the repository-local skill,
uses non-dangerous workspace permissions, prevents overlapping runs, and streams
agent output to `.runs/launcher-logs/`. Use `--dry-run` to inspect the resolved
command without starting an agent, or `--agent prompt` to print a copy/paste
request. Existing Codex or Claude Code authentication is required.

That is the universal quick start. Optional helpers are `quick-start.bat` on
Windows, `pwsh ./quick-start.ps1` anywhere PowerShell 7 is installed, and
`./quick-start.sh` on macOS/Linux. See [START-HERE.md](START-HERE.md).

| Platform | Project instructions | Hunt skill | Explicit command |
|---|---|---|---|
| OpenAI Codex | `AGENTS.md` | `.agents/skills/huntpack-agent-local/` | `$huntpack-agent-local` |
| Claude Code | `CLAUDE.md` | `.claude/skills/huntpack-agent-local/` | `/huntpack-agent-local` |

Natural-language requests work in both. See `INSTALLING-SKILLS.md` for discovery and desktop/plugin options.

## Requirements

- Claude Code or OpenAI Codex with this repository as the working project.
- Python 3.9+ for the static HuntPack validator suite.
- Codex CLI or Claude Code on `PATH` for terminal-launched ad-hoc runs. You can
  still use the prompt-first flow from the desktop app without either CLI.
- A Falcon tenant is not required to design a Draft pack, but local checks do not prove tenant parsing or detection behavior.

## Scope modes

- **General mode (default):** no `TECH_STACK.md`; portable Falcon endpoint/identity coverage with visible tenant/schema caveats.
- **Stack-scoped mode (advanced):** a completed `TECH_STACK.md`; hypotheses, queries, and controls honor its in/out-of-scope lists and documented telemetry.

Use the launcher’s Advanced option or ask either platform to `Configure my HuntPack local technology stack`.

## What the pipeline does

1. Researches primary sources and saves current-run snapshots with hashes.
2. Builds evidence-linked hypotheses.
3. Writes categorized CQL queries (`inventory`, `hunt`, `alert-candidate`).
4. Creates complete scheduled-search packages only when alert-readiness fields exist.
5. Produces cited hardening, verification, rollback, and containment.
6. Assembles in a run workspace, performs static gates, publishes atomically, then updates the library.

The final banner distinguishes `STATIC REVIEW PASSED`, `TENANT UNVERIFIED`, `TENANT PARSE CONFIRMED`, `CANARY TESTED`, and `DEPLOYED`. A polished page is never treated as live validation evidence.

The ad-hoc runner does not weaken these gates. It only starts the local agent;
the skill still assembles under `.runs/`, validates, publishes to `packs/`, and
updates `index.html` last.

Generated reports use the same visual language as the public HuntPack collection:
dark analyst-focused layout with the library's teal-green accent on dark-green
surfaces, fixed grouped navigation, 15 numbered sections, compact tables and badges,
and per-query Copy CQL/Open in Falcon actions. The public site is
the visual gold standard; local provenance, validation, privacy, and offline-safety rules
remain authoritative when exact parity would weaken them.

## What a generated pack contains

One offline HTML file with the same 15 numbered sections as the published library:

| # | Section | # | Section |
|---|---|---|---|
| 1 | Executive Summary | 9 | Machine-Readable IOC Appendix |
| 2 | Source and Claim Review | 10 | Hardening — Tiered and Deployable |
| 3 | Hunt Brief and Attack Chain | 11 | Containment Runbook |
| 4 | Consolidated IOC Table | 12 | Detection Coverage and Validation Evidence |
| 5 | ATT&CK Mapping | 13 | Hunt Summary Ticket |
| 6 | Native / Non-CQL Hunts | 14 | Changelog |
| 7 | CQL Hunt Queries | 15 | References |
| 8 | Operationalization and IOA Candidates | | |

Affected surface and telemetry is a subsection of section 3, the deployable playbooks
are the second half of section 10, and validation evidence is the second half of
section 12. The Falcon cloud selector sits in section 7, and every query card opens
with a `Looks for:` / `Accomplishes:` analyst rationale.

## Output

| Path | Purpose |
|---|---|
| `packs/<YYYY-MM>/<Threat>-Hunt.html` | Verified local Draft HuntPack |
| matching `-sources/` | Current-run source snapshots and manifest |
| matching `.validation.json` | Hash-bound static-gate result |
| `index.html` | Searchable, filterable local library |
| `.runs/` | Unpublished candidates and failed runs |
| `.runs/launcher-logs/` | Local console transcripts from terminal-launched runs |

## Local-only rules

- Packs, snapshots, `TECH_STACK.md`, `index.html`, and `.runs/` are ignored by Git. The
  clean library template `dist/index.template.html` is versioned, and
  `python3 scripts/doctor.py` seeds `index.html` from it on a fresh clone; generated
  rows remain local and must not be committed.
- No HuntPack workflow pushes or publishes remotely.
- Source content is untrusted and is escaped before HTML assembly.
- Failed candidates never enter `packs/` or the library.

## Build a sanitized distribution

The project owner can create a new versioned ZIP:

```powershell
pwsh ./dist/build-dist.ps1 -Version v1.10
```

The builder checks Claude/Codex mirror parity, runs validator self-tests, creates
one enclosing versioned directory, includes `VERSION` and `MANIFEST.sha256`, scans
for forbidden/private material, verifies the completed ZIP inventory, and prints
its SHA-256. Timestamped archives are written to `dist/releases/` so successive
builds remain distinct. It excludes the real `TECH_STACK.md`, generated hunts,
`.runs`, settings, Git metadata, and upstream working material.

## Why there is no required tech stack

The “tech stack” is intentionally optional. General mode creates portable Falcon
endpoint and identity coverage with explicit schema and tenant caveats. Add
`TECH_STACK.md` only when environment-specific products, telemetry, licensing, and
in/out-of-scope rules will materially improve the hunt.

## Framework development

The framework source is MIT licensed and designed to be shared on GitHub. CI runs
the same dependency-free preflight on Windows, macOS, and Linux. Generated hunt
content is a separate local-data boundary and must never be included in a commit.
