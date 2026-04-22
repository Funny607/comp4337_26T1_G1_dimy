#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

T="${T:-15}"
K="${K:-3}"
N="${N:-5}"

TARGET_IP="${TARGET_IP:-255.255.255.255}"
TARGET_PORT="${TARGET_PORT:-37020}"
FAKE_NODES="${FAKE_NODES:-3}"

echo "[run_attacker] starting attacker..."
echo "[run_attacker] t=$T k=$K n=$N target=$TARGET_IP:$TARGET_PORT fake_nodes=$FAKE_NODES"

exec env PYTHONPATH="$ROOT_DIR" "$PYTHON_BIN" src/Attacker.py \
  "$T" "$K" "$N" \
  --target-ip "$TARGET_IP" \
  --target-port "$TARGET_PORT" \
  --fake-nodes "$FAKE_NODES"