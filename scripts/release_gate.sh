#!/usr/bin/env bash
# Release gate for containment: install, lint, test, eval, placeholder scan.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# Prefer project venv for all subsequent steps.
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install -e ".[dev]"

ruff check src tests

pytest

python -m containment.cli eval --suite fixtures

# Placeholder / unfinished markers must be absent from ship surfaces.
if rg -n 'TODO|FIXME|NotImplemented|pass  #|placeholder|TBD' src tests docs README.md SKILL.md; then
  echo "release_gate: placeholder scan FOUND hits (fail)" >&2
  exit 1
fi
echo "release_gate: placeholder scan clean"

echo "release_gate: OK"
exit 0
