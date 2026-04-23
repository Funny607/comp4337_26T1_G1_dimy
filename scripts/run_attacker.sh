#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[run_attacker] starting attacker..."
echo "[run_attacker] note: current src/Attacker.py uses hardcoded attack parameters"

exec env PYTHONPATH="$ROOT_DIR" "$PYTHON_BIN" -m src.Attacker