#!/usr/bin/env bash
# Clean-clone walkthrough: venv, dependencies, tests, baseline, v1/v2 compare.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python

if [ ! -d venv ]; then
  echo "Creating virtual environment in venv/ ..."
  "$PYTHON" -m venv venv
fi

if [ -f venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
else
  # Windows Git Bash / venv layout
  source venv/Scripts/activate
fi

echo "Installing requirements ..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo "Running tests ..."
python -m pytest

echo "Running the policy-free baseline ..."
python -m agentfence attack --agent sample --out reports/baseline.json

echo "Comparing v1 and v2 enforcement ..."
python -m agentfence compare \
  --baseline reports/baseline.json \
  --policy policies/generated.yaml \
  --policy-v2 policies/v2.yaml \
  --out reports/compare.json

echo
echo "Done."
echo "  JSON report:   reports/compare.json"
echo "  HTML report:   reports/compare.html"
echo "  Dashboard:     http://127.0.0.1:8000/ui/"
echo "  Start it with: venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000"
