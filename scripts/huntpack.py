#!/usr/bin/env python3
"""Run the repository-local HuntPack skill on demand with Codex or Claude Code."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / ".runs"
LOCK = RUNS / ".ad-hoc.lock"
LOGS = RUNS / "launcher-logs"
AGENTS = ("auto", "codex", "claude", "prompt")
LOOKBACK = re.compile(r"^\d+[hdw]$", re.IGNORECASE)


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug or "hunt")[:60]


def normalize_target(parts: list[str]) -> str:
    target = " ".join(parts).strip()
    if not target:
        raise ValueError("provide a threat, actor, campaign, malware, CVE, URL, or 'auto'")
    if "\x00" in target or "\r" in target or "\n" in target:
        raise ValueError("the target must be a single line")
    if len(target) > 1000:
        raise ValueError("the target is too long (maximum 1000 characters)")
    return target


def build_prompt(target: str, lookback: str | None) -> str:
    if target.casefold() == "auto":
        window = lookback or "48h"
        return (
            "Use the repository-local huntpack-agent-local skill to run the local "
            f"HuntPack auto scan with a {window} lookback. Keep all generated artifacts "
            "local. Never push, publish, upload, sync, or commit generated output."
        )
    if lookback:
        raise ValueError("--lookback is only valid when the target is 'auto'")
    return (
        "Use the repository-local huntpack-agent-local skill to build a local HuntPack "
        f"for: {target}. Keep all generated artifacts local. Never push, publish, upload, "
        "sync, or commit generated output."
    )


def executable(agent: str) -> str | None:
    return shutil.which(agent)


def resolve_agent(requested: str) -> tuple[str, str | None]:
    if requested == "prompt":
        return requested, None
    if requested in {"codex", "claude"}:
        path = executable(requested)
        if not path:
            raise RuntimeError(f"{requested} was requested but is not on PATH")
        return requested, path
    for candidate in ("codex", "claude"):
        path = executable(candidate)
        if path:
            return candidate, path
    raise RuntimeError("neither codex nor claude is on PATH; use --agent prompt to print the request")


def build_command(agent: str, exe: str, prompt: str) -> list[str]:
    if agent == "codex":
        return [
            exe,
            "exec",
            "--cd",
            str(ROOT),
            "--sandbox",
            "workspace-write",
            "--approve-for-me",
            "--color",
            "auto",
            prompt,
        ]
    if agent == "claude":
        return [
            exe,
            "--print",
            "--permission-mode",
            "acceptEdits",
            "--output-format",
            "text",
            prompt,
        ]
    raise ValueError(f"unsupported executable agent: {agent}")


def prompt_for_agent(agent: str, prompt: str) -> str:
    prefix = "$huntpack-agent-local" if agent == "codex" else "/huntpack-agent-local"
    return f"{prefix} {prompt}"


def acquire_lock(agent: str, target: str) -> None:
    RUNS.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "agent": agent,
        "target": target,
        "created_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    try:
        descriptor = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        detail = LOCK.read_text(encoding="utf-8", errors="replace").strip()
        raise RuntimeError(
            "another ad-hoc run is active or left a stale lock at "
            f"{LOCK}. Verify no run is active, then use --unlock.\n{detail}"
        ) from exc
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def release_lock() -> None:
    try:
        payload = json.loads(LOCK.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if payload.get("pid") == os.getpid():
        LOCK.unlink(missing_ok=True)


def unlock() -> int:
    if not LOCK.exists():
        print("No ad-hoc run lock exists.")
        return 0
    detail = LOCK.read_text(encoding="utf-8", errors="replace").strip()
    LOCK.unlink()
    print(f"Removed stale lock: {LOCK}")
    if detail:
        print(detail)
    return 0


def run_agent(command: list[str], agent: str, target: str) -> int:
    LOGS.mkdir(parents=True, exist_ok=True)
    log_path = LOGS / f"{utc_stamp()}-{slugify(target)}-{agent}.log"
    print(f"Agent: {agent}")
    print(f"Workspace: {ROOT}")
    print(f"Local log: {log_path}")
    print("Remote publication: disabled by project rules\n")

    with log_path.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"agent: {agent}\nworkspace: {ROOT}\ntarget: {target}\n\n")
        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                print(line, end="")
                log.write(line)
                log.flush()
            return proc.wait()
        except KeyboardInterrupt:
            print("\nInterrupted; stopping the agent.", file=sys.stderr)
            if proc is None:
                return 130
            proc.terminate()
            try:
                return proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                return 130


def self_test() -> int:
    failures: list[str] = []

    def expect(label: str, condition: bool) -> None:
        print(f"{'PASS' if condition else 'FAIL'}  {label}")
        if not condition:
            failures.append(label)

    named = build_prompt("Scattered Spider", None)
    auto = build_prompt("auto", "72h")
    codex = build_command("codex", "/bin/codex", named)
    claude = build_command("claude", "/bin/claude", named)
    expect("named target prompt", "Scattered Spider" in named and "Never push" in named)
    expect("auto lookback prompt", "72h" in auto and "auto scan" in auto)
    expect("safe Codex mode", "workspace-write" in codex and "dangerously" not in " ".join(codex))
    expect("safe Claude mode", "acceptEdits" in claude and "dangerously" not in " ".join(claude))
    expect("argument-safe target", codex[-1] == named and len(codex) == 10)
    expect("stable slug", slugify("CVE-2026-1234 / Test") == "cve-2026-1234-test")
    return 1 if failures else 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Run a local-only HuntPack generation with Codex or Claude Code.",
        epilog=(
            "examples:\n"
            "  python scripts/huntpack.py Scattered Spider\n"
            "  python scripts/huntpack.py CVE-2026-12345 --agent claude\n"
            "  python scripts/huntpack.py auto --lookback 72h\n"
            "  python scripts/huntpack.py Scattered Spider --dry-run"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    result.add_argument("target", nargs="*", help="hunt target, URL, or the literal 'auto'")
    result.add_argument(
        "--agent",
        choices=AGENTS,
        default=os.environ.get("HUNTPACK_AGENT", "auto").lower(),
        help="runner to use (default: HUNTPACK_AGENT or auto)",
    )
    result.add_argument("--lookback", help="auto-mode lookback such as 48h, 7d, or 2w")
    result.add_argument("--dry-run", action="store_true", help="show the resolved request without running it")
    result.add_argument("--unlock", action="store_true", help="remove a stale ad-hoc run lock and exit")
    result.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.self_test:
        return self_test()
    if args.unlock:
        return unlock()
    try:
        if args.agent not in AGENTS:
            raise ValueError(f"invalid HUNTPACK_AGENT value: {args.agent}")
        target = normalize_target(args.target)
        if args.lookback and not LOOKBACK.fullmatch(args.lookback):
            raise ValueError("--lookback must use a value such as 48h, 7d, or 2w")
        prompt = build_prompt(target, args.lookback)
        agent, exe = resolve_agent(args.agent)
    except (ValueError, RuntimeError) as exc:
        parser().error(str(exc))

    if agent == "prompt":
        print("Codex:\n" + prompt_for_agent("codex", prompt))
        print("\nClaude Code:\n" + prompt_for_agent("claude", prompt))
        return 0

    assert exe is not None
    command = build_command(agent, exe, prompt)
    if args.dry_run:
        print(f"Resolved agent: {agent}")
        print(f"Command: {shlex.join(command)}")
        print("No agent was started and no files were changed.")
        return 0

    try:
        acquire_lock(agent, target)
        return run_agent(command, agent, target)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        release_lock()


if __name__ == "__main__":
    raise SystemExit(main())
