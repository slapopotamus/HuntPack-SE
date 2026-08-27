#!/usr/bin/env python3
"""Build a sanitized HuntPack Local distribution ZIP.

Cross-platform port of `dist/build-dist.ps1`, for hosts without PowerShell 7.
It performs the same checks in the same order and produces the same layout:

  1. Claude/Codex skill mirror parity.
  2. Validator self-tests.
  3. Stage the public file set into one enclosing versioned directory.
  4. Leak guard: forbidden artifacts, environment markers, secret patterns.
  5. MANIFEST.sha256 over the staged tree.
  6. ZIP, then verify the archive's inventory and single root.
  7. Print the ZIP's SHA-256.

Usage:
    python3 dist/build_dist.py                 # version from VERSION
    python3 dist/build_dist.py --version v1.11
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

DIST = Path(__file__).resolve().parent
ROOT = DIST.parent
RELEASES = DIST / "releases"

SKILLS = ("huntpack-agent-local", "huntpack-local-setup")
PUBLIC_FILES = (
    ".gitignore", "AGENTS.md", "CLAUDE.md", "INSTALLING-SKILLS.md", "LICENSE",
    "quick-start.bat", "quick-start.ps1", "quick-start.sh", "QUICKSTART.md",
    "README.md", "SETUP.md", "START-HERE.md", "TECH_STACK.example.md",
)
FORBIDDEN_NAMES = ("TECH_STACK.md", "settings.local.json", ".git", "pipeline-upstream", ".runs")
# Assembled at runtime so the builder can scan a copy of itself without
# matching its own deny-list definitions.
PRIVATE_MARKERS = (
    "FortiGate" + "-100F", "FAC" + "300F", "FPR" + "-3105",
    "Nasu" + "ni", "Mitel Connect" + " Director",
)
SECRET_PATTERNS = (
    r"(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    r"(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*["'][^"']{8,}""",
    r"(?i)\bBearer\s+[A-Za-z0-9._-]{20,}",
    r"(?i)C:\\Users\\[^\\\s]+\\",
    r"(?i)/(?:Users|home)/[^/\s]+/",
)
SKIP_DIRS = {"__pycache__"}


class BuildError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_dir() or SKIP_DIRS.intersection(path.parts):
            continue
        yield path


def digest_map(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)).replace("\\", "/"): sha256(p) for p in tree_files(root)}


def assert_skill_parity() -> None:
    agents = digest_map(ROOT / ".agents/skills/huntpack-agent-local")
    claude = digest_map(ROOT / ".claude/skills/huntpack-agent-local")
    drift = sorted(
        name for name in set(agents) | set(claude)
        if agents.get(name) != claude.get(name)
    )
    if drift:
        raise BuildError("Claude/Codex hunt skill drift detected: " + ", ".join(drift))
    print(f"  parity      OK  {len(claude)} files identical in both mirrors")


def run_validator_self_tests() -> None:
    validator = ROOT / ".agents/skills/huntpack-agent-local/scripts/validate_huntpack.py"
    if not validator.exists():
        raise BuildError(f"Validator orchestrator missing: {validator}")
    result = subprocess.run([sys.executable, "-X", "utf8", str(validator), "--self-test"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise BuildError("HuntPack validator self-tests failed.")
    print("  self-tests  OK  all gate suites green")


def stage(release_root: Path) -> None:
    for mirror in (".agents", ".claude"):
        for skill in SKILLS:
            src = ROOT / mirror / "skills" / skill
            if not src.exists():
                raise BuildError(f"missing skill tree: {src}")
            shutil.copytree(src, release_root / mirror / "skills" / skill,
                            ignore=shutil.ignore_patterns(*SKIP_DIRS))
    for name in PUBLIC_FILES:
        shutil.copy2(ROOT / name, release_root / name)

    (release_root / "scripts").mkdir(parents=True, exist_ok=True)
    for name in ("doctor.py", "huntpack.py"):
        shutil.copy2(ROOT / "scripts" / name, release_root / "scripts" / name)

    (release_root / "dist").mkdir(parents=True, exist_ok=True)
    shutil.copy2(DIST / "build-dist.ps1", release_root / "dist/build-dist.ps1")
    shutil.copy2(Path(__file__), release_root / "dist/build_dist.py")
    shutil.copy2(DIST / "index.template.html", release_root / "dist/index.template.html")
    shutil.copy2(DIST / "index.template.html", release_root / "index.html")

    (release_root / "packs").mkdir(parents=True, exist_ok=True)
    (release_root / "packs/.gitkeep").touch()


def assert_release_safe(release_root: Path) -> None:
    for path in sorted(release_root.rglob("*")):
        if path.name in FORBIDDEN_NAMES:
            raise BuildError(f"Leak guard: forbidden artifact found: {path.name}")
    for path in tree_files(release_root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for marker in PRIVATE_MARKERS:
            if marker in text:
                raise BuildError(f"Leak guard: environment marker {marker} in {path}")
        for pattern in SECRET_PATTERNS:
            hit = re.search(pattern, text)
            if hit:
                raise BuildError(f"Leak guard: sensitive pattern in {path}: {hit.group(0)[:60]}")
    print("  leak guard  OK  no forbidden artifacts, markers, or secret patterns")


def write_manifest(release_root: Path) -> None:
    manifest = release_root / "MANIFEST.sha256"
    lines = [f"{sha256(p)}  {p.relative_to(release_root).as_posix()}"
             for p in tree_files(release_root) if p != manifest]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  manifest    OK  {len(lines)} files hashed")


def build_zip(work_root: Path, release_name: str, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in tree_files(work_root):
            archive.write(path, path.relative_to(work_root).as_posix())


def assert_zip_inventory(zip_path: Path, release_name: str) -> None:
    prefix = f"{release_name}/"
    required = [
        f"{prefix}.agents/skills/huntpack-agent-local/SKILL.md",
        f"{prefix}.claude/skills/huntpack-agent-local/SKILL.md",
        f"{prefix}AGENTS.md", f"{prefix}CLAUDE.md", f"{prefix}README.md",
        f"{prefix}index.html", f"{prefix}packs/.gitkeep", f"{prefix}scripts/huntpack.py",
        f"{prefix}VERSION", f"{prefix}MANIFEST.sha256",
    ]
    with zipfile.ZipFile(zip_path) as archive:
        entries = archive.namelist()
    missing = [name for name in required if name not in entries]
    if missing:
        raise BuildError("ZIP verification failed: missing " + ", ".join(missing))
    stray = [name for name in entries if not name.startswith(prefix)]
    if stray:
        raise BuildError("ZIP verification failed: archive has more than one top-level root.")
    for forbidden in ("TECH_STACK.md", "settings.local.json", "/.git/", "pipeline-upstream", "/.runs/"):
        if any(forbidden in name for name in entries):
            raise BuildError(f"ZIP verification failed: forbidden entry {forbidden}")
    print(f"  inventory   OK  {len(entries)} entries under a single root")


def main() -> int:
    default_version = (ROOT / "VERSION").read_text(encoding="utf-8").strip() \
        if (ROOT / "VERSION").exists() else "v1.0"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=default_version)
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+", args.version):
        raise SystemExit(f"version must look like v1.10, got {args.version!r}")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")
    release_name = f"huntpack-local-kit-{args.version}"
    RELEASES.mkdir(parents=True, exist_ok=True)
    zip_path = RELEASES / f"{release_name}_{stamp}.zip"
    if zip_path.exists():
        raise SystemExit(f"Distribution already exists: {zip_path}")

    print(f"building {release_name} ({stamp})")
    try:
        assert_skill_parity()
        run_validator_self_tests()
        with tempfile.TemporaryDirectory(prefix=".build-") as work:
            work_root = Path(work)
            release_root = work_root / release_name
            release_root.mkdir()
            stage(release_root)
            (release_root / "VERSION").write_text(args.version + "\n", encoding="utf-8")
            assert_release_safe(release_root)
            write_manifest(release_root)
            build_zip(work_root, release_name, zip_path)
        assert_zip_inventory(zip_path, release_name)
    except BuildError as exc:
        if zip_path.exists():
            zip_path.unlink()
        print(f"\nBUILD FAILED: {exc}")
        return 1

    print(f"\n  path    {zip_path}")
    print(f"  bytes   {zip_path.stat().st_size:,}")
    print(f"  sha256  {sha256(zip_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
