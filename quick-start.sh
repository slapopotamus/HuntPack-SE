#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON=python
else
  printf '%s\n' 'Python 3 was not found. Install it before generating a HuntPack.' >&2
  exit 1
fi

printf '%s\n' 'HuntPack Local'
printf '%s\n' '--------------'
"$PYTHON" scripts/doctor.py
if [ "$#" -gt 0 ]; then
  printf '\n%s\n' 'Starting an ad-hoc local HuntPack run...'
  exec "$PYTHON" scripts/huntpack.py "$@"
fi
printf '\n%s\n' 'Open this folder in Claude Code or Codex, then paste:'
printf '%s\n' '  Build a local HuntPack for <threat, actor, malware, CVE, or URL>.'
printf '\n%s\n' 'Or run it directly from this terminal:'
printf '%s\n' '  ./quick-start.sh Scattered Spider'
printf '%s\n' '  python3 scripts/huntpack.py auto --lookback 48h'
printf '\n%s\n' 'See START-HERE.md for more prompts. Open index.html after the hunt passes validation.'
