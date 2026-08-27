# HuntPack Local — Quick Start

1. Clone the repository or extract the release ZIP into a new folder.
2. Open that folder as a Claude Code or Codex project.
3. Paste a direct request such as `Build a local HuntPack for Scattered Spider.`
4. Open `index.html` after the hunt completes.

No launcher is required. Optional helpers are `quick-start.bat` on Windows,
`pwsh ./quick-start.ps1` with PowerShell 7, and `./quick-start.sh` on macOS/Linux.

Direct requests:

```text
Build a local hunt pack for Scattered Spider
Build a local hunt pack for CVE-2026-XXXXX
Hunt this locally: https://example.com/threat-report
Run the local HuntPack auto scan
```

Direct terminal runs:

```bash
python3 scripts/huntpack.py Scattered Spider
python3 scripts/huntpack.py CVE-2026-XXXXX --agent claude
python3 scripts/huntpack.py auto --lookback 48h
```

Use `--dry-run` to preview without starting an agent. The launcher prevents
overlapping runs and stores its console transcript under `.runs/launcher-logs/`.

| Platform | Explicit invocation |
|---|---|
| Claude Code | `/huntpack-agent-local` |
| OpenAI Codex | `$huntpack-agent-local` |

No technology stack is required. Without `TECH_STACK.md`, the pipeline runs in General mode. Stack setup is an advanced option for environment-specific scope.

Python 3.9+ is required for the static release gates. Run
`python scripts/doctor.py` to check the installation; on a fresh clone it also seeds
the Git-ignored `index.html` from `dist/index.template.html`. The gates check
structure and content depth — all 15 sections present and non-stub, a rationale on
every query card, all three hardening tiers, a copyable hunt ticket, a changelog
entry — plus safety, field/event vocabulary, known CQL anti-patterns, and IOC
provenance; they do not contact Falcon. A new pack normally ships as
`STATIC REVIEW PASSED / TENANT UNVERIFIED`.

Everything stays local: packs, source snapshots, validation sidecars, and the library are not published.
