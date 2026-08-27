#!/usr/bin/env python3
"""Cross-platform, dependency-free HuntPack Local installation check."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def tree_hashes(root: Path) -> dict[str, str]:
    """Hash the mirrored skill source. Interpreter caches are build noise, not drift."""
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def ensure_library() -> bool:
    """index.html is local-only and Git-ignored, so a fresh clone starts without one."""
    library = ROOT / "index.html"
    if library.is_file():
        return True
    template = ROOT / "dist" / "index.template.html"
    if not template.is_file():
        return False
    library.write_bytes(template.read_bytes())
    print("Seeded index.html from dist/index.template.html")
    return True


def main() -> int:
    agents = ROOT / ".agents" / "skills" / "huntpack-agent-local"
    claude = ROOT / ".claude" / "skills" / "huntpack-agent-local"
    checks = {
        "Python 3.9+": sys.version_info >= (3, 9),
        "Codex skill": (agents / "SKILL.md").is_file(),
        "Claude skill": (claude / "SKILL.md").is_file(),
        "Ad-hoc runner": (ROOT / "scripts" / "huntpack.py").is_file(),
        "Local library": ensure_library(),
        "Pack directory": (ROOT / "packs").is_dir(),
    }
    if checks["Codex skill"] and checks["Claude skill"]:
        checks["Claude/Codex parity"] = tree_hashes(agents) == tree_hashes(claude)

    validator = agents / "scripts" / "validate_huntpack.py"
    if validator.is_file():
        result = subprocess.run(
            [sys.executable, "-X", "utf8", str(validator), "--self-test"],
            cwd=ROOT,
            check=False,
        )
        checks["Validator self-tests"] = result.returncode == 0
    else:
        checks["Validator self-tests"] = False

    runner = ROOT / "scripts" / "huntpack.py"
    if runner.is_file():
        result = subprocess.run(
            [sys.executable, "-X", "utf8", str(runner), "--self-test"],
            cwd=ROOT,
            check=False,
        )
        checks["Runner self-tests"] = result.returncode == 0
    else:
        checks["Runner self-tests"] = False

    print("\nHuntPack Local preflight")
    for label, passed in checks.items():
        print(f"  [{'OK' if passed else 'FAIL'}] {label}")
    failed = [label for label, passed in checks.items() if not passed]
    if failed:
        print("\nFix the failed checks before generating a pack.")
        return 1
    print("\nReady. Open this folder in Claude Code or Codex and start with a prompt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
