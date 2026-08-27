# Start Here

HuntPack Local is prompt-first. You do not need to install a web stack, package
manager, database, or server.

## 1. Get the project

```bash
git clone https://github.com/slapopotamus/huntpack_local_testing.git
cd huntpack_local_testing
```

Open that folder in either Claude Code or OpenAI Codex. The repository carries the
same local skill for both agents.

## 2. Paste a prompt

```text
Build a local HuntPack for Scattered Spider.
```

Other useful starting prompts:

```text
Build a local HuntPack for CVE-2026-XXXXX.
Hunt this report locally: https://example.com/threat-report
Find a broadly relevant current threat and build a local HuntPack for it.
Configure my optional HuntPack technology-stack profile.
Check this HuntPack Local installation.
```

Natural language is the universal interface. Explicit skill commands are optional:

| Agent | Hunt | Optional stack setup |
|---|---|---|
| OpenAI Codex | `$huntpack-agent-local` | `$huntpack-local-setup` |
| Claude Code | `/huntpack-agent-local` | `/huntpack-local-setup` |

### Terminal shortcut

If Codex CLI or Claude Code is installed and authenticated, run the same local
skill directly from a terminal:

```bash
python3 scripts/huntpack.py Scattered Spider
python3 scripts/huntpack.py CVE-2026-XXXXX --agent codex
python3 scripts/huntpack.py auto --lookback 48h
```

The default `--agent auto` prefers Codex when both CLIs are available. Set
`HUNTPACK_AGENT=claude` or pass `--agent claude` to choose Claude Code. Preview
the invocation safely with `--dry-run`. If a process is interrupted and leaves a
stale mutex, first verify no generation is active and then run
`python3 scripts/huntpack.py --unlock`.

## 3. Open the result

Successful packs appear under `packs/<YYYY-MM>/` and in `index.html`. Open either
HTML file directly in a browser; no local server is required.

Each pack is one offline HTML file with the published library's 15 numbered sections:
executive summary, source and claim review, hunt brief and attack chain, IOC table,
ATT&CK mapping, native hunts, CQL hunt queries, operationalization and IOA candidates,
machine-readable IOC appendix, tiered and deployable hardening, containment runbook,
detection coverage and validation evidence, hunt summary ticket, changelog, and
references.

Python 3.9+ is needed for generation-time validation. Run `python scripts/doctor.py`
to check the installation. On a fresh clone it also seeds `index.html` from
`dist/index.template.html`, because the library is local-only and Git-ignored. Optional menus are available through `quick-start.bat`,
`pwsh ./quick-start.ps1`, or `./quick-start.sh`.

On macOS/Linux, `./quick-start.sh Scattered Spider` runs preflight and then starts
the ad-hoc runner. Calling `./quick-start.sh` with no arguments remains a read-only
installation check.

`TECH_STACK.md` is optional. Without it, HuntPack Local uses portable General mode.
Generated hunts, source snapshots, local stack details, and run workspaces are
ignored by Git and must remain local.
