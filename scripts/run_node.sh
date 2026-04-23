#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

T="${T:-15}"
K="${K:-3}"
N="${N:-5}"
P="${P:-20}"

SERVER_IP="${SERVER_IP:-127.0.0.1}"
SERVER_PORT="${SERVER_PORT:-55000}"

NODE_ID="${NODE_ID:-nodeA}"

BIND_IP="${BIND_IP:-0.0.0.0}"
BIND_PORT="${BIND_PORT:-37020}"
TARGET_IP="${TARGET_IP:-255.255.255.255}"
TARGET_PORT="${TARGET_PORT:-37020}"

QUIET="${QUIET:-0}"

CMD=(
  "$PYTHON_BIN" -m src.Dimy
  "$T" "$K" "$N" "$P" "$SERVER_IP" "$SERVER_PORT"
  --node-id "$NODE_ID"
  --bind-ip "$BIND_IP"
  --bind-port "$BIND_PORT"
  --target-ip "$TARGET_IP"
  --target-port "$TARGET_PORT"
)

if [[ "$QUIET" == "1" ]]; then
  CMD+=(--quiet)
fi

echo "[run_node] starting node..."
echo "[run_node] node_id=$NODE_ID t=$T k=$K n=$N p=$P server=$SERVER_IP:$SERVER_PORT"
echo "[run_node] bind=$BIND_IP:$BIND_PORT target=$TARGET_IP:$TARGET_PORT"

exec env PYTHONPATH="$ROOT_DIR" "${CMD[@]}"