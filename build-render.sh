#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PYTHON_BIN="python"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN="python3"
fi

echo "==> Upgrading pip"
"$PYTHON_BIN" -m pip install --upgrade pip wheel setuptools

echo "==> Installing dependencies from requirements.txt"
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "==> Build finished OK"

