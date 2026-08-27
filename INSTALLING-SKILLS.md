# HuntPack Local Skill Discovery

The repository carries equivalent project-local skill trees for both engines. No
global skill installation is required when the repository itself is the project.

## OpenAI Codex

Open the extracted kit as the project. Codex reads `AGENTS.md` and discovers repository skills under:

```text
.agents/skills/huntpack-agent-local/
.agents/skills/huntpack-local-setup/
```

Use natural language or `$huntpack-agent-local` / `$huntpack-local-setup`.

## Claude Code

Open the extracted kit as the working directory. Claude Code reads `CLAUDE.md` and discovers project skills under:

```text
.claude/skills/huntpack-agent-local/
.claude/skills/huntpack-local-setup/
```

Use natural language or `/huntpack-agent-local` / `/huntpack-local-setup`.

## Desktop/account skills and plugins

Desktop products that do not scan project skill folders may require uploading each individual skill or installing a plugin. The project folder must still be available as writable context because the pipeline creates `.runs/`, `packs/`, validation sidecars, source snapshots, and `index.html` locally.

When distributing to many users, package the two skills as a platform-supported plugin. That is separate from generating HuntPacks and must not upload hunt output.

## Verify discovery

Run `python scripts/doctor.py`. Both skill trees, mirror parity, the library, the
pack directory, Python 3.9+, and validator self-tests should report `OK`.

The distribution build fails if the Claude and Codex hunt skill trees differ by even one file or byte.
