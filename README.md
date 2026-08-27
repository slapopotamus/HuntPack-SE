# HuntPack SE

Build evidence-backed, analyst-ready CrowdStrike HuntPacks with Claude Code or
OpenAI Codex. The framework is cross-platform and prompt-first, and **generated
hunts never leave your machine**.

## Quick start

```bash
git clone https://github.com/slapopotamus/HuntPack-SE.git
cd HuntPack-SE
```

Open the folder in Claude Code or Codex and ask for a hunt:

```text
Build a local hunt pack for Scattered Spider
Build a local hunt pack for CVE-2026-XXXXX
Hunt this locally: https://example.com/threat-report
Run the local HuntPack auto scan
```

Or run one from a terminal:

```bash
python3 scripts/huntpack.py Scattered Spider
```

The runner auto-detects Codex or Claude Code, uses non-dangerous workspace
permissions, and streams output to `.runs/launcher-logs/`. Add `--dry-run` to
inspect the resolved command without starting an agent.

## Requirements

- Claude Code or OpenAI Codex, with this repository as the working project
- Python 3.9+ for the static validator suite

A Falcon tenant is not required to design a Draft pack. Local checks do not prove
tenant parsing or detection behavior.

## What you get

One offline HTML file per hunt, written to `packs/<YYYY-MM>/`, with 15 numbered
sections covering the executive summary, source review, attack chain, IOC tables,
ATT&CK mapping, CQL queries, tiered hardening, containment runbook, and validation
evidence. Every query card carries a `Looks for:` / `Accomplishes:` rationale plus
Copy CQL and Open in Falcon actions.

## Scope modes

- **General mode (default)** — no setup; portable Falcon endpoint and identity
  coverage with explicit schema and tenant caveats.
- **Stack-scoped mode (advanced)** — add a `TECH_STACK.md` and hypotheses, queries,
  and controls honor its in/out-of-scope lists. Optional, not a prerequisite.

## Local-only boundary

Generated hunts are local data, not source. Packs, source snapshots, `TECH_STACK.md`,
`index.html`, and `.runs/` are all Git-ignored and must never be committed. The
framework source itself is MIT licensed and meant to be shared.

## More

- [START-HERE.md](START-HERE.md) — guided first run
- [SETUP.md](SETUP.md) — install and configuration
- [INSTALLING-SKILLS.md](INSTALLING-SKILLS.md) — skill discovery, desktop and plugin options
- [REFERENCE.md](REFERENCE.md) — full framework reference

## Credits

Created and maintained by [**slapopotamus**](https://github.com/slapopotamus).

Licensed under the [MIT License](LICENSE).
