#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
BIND_IP="${BIND_IP:-0.0.0.0}"
BIND_PORT="${BIND_PORT:-55000}"
QUIET="${QUIET:-0}"

CMD=(
  "$PYTHON_BIN" -m src.DimyServer
  --bind-ip "$BIND_IP"
  --bind-port "$BIND_PORT"
)

if [[ "$QUIET" == "1" ]]; then
  CMD+=(--quiet)
fi

echo "[run_server] starting DIMY backend server..."
echo "[run_server] bind_ip=$BIND_IP bind_port=$BIND_PORT"

exec env PYTHONPATH="$ROOT_DIR" "${CMD[@]}"