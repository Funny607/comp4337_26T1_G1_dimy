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

BIND_IP="${BIND_IP:-0.0.0.0}"
NODE_BIND_PORT="${NODE_BIND_PORT:-37020}"
TARGET_IP="${TARGET_IP:-255.255.255.255}"
TARGET_PORT="${TARGET_PORT:-37020}"

PIDS=()

cleanup() {
  echo
  echo "[test_runner] stopping all processes..."
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait || true
}

trap cleanup EXIT INT TERM

echo "[test_runner] starting full DIMY demo..."

BIND_IP="$BIND_IP" \
BIND_PORT="$SERVER_PORT" \
PYTHON_BIN="$PYTHON_BIN" \
bash "$ROOT_DIR/scripts/run_server.sh" &
PIDS+=($!)

sleep 1

for NODE_ID in nodeA nodeB nodeC; do
  T="$T" \
  K="$K" \
  N="$N" \
  P="$P" \
  SERVER_IP="$SERVER_IP" \
  SERVER_PORT="$SERVER_PORT" \
  NODE_ID="$NODE_ID" \
  BIND_IP="$BIND_IP" \
  BIND_PORT="$NODE_BIND_PORT" \
  TARGET_IP="$TARGET_IP" \
  TARGET_PORT="$TARGET_PORT" \
  PYTHON_BIN="$PYTHON_BIN" \
  bash "$ROOT_DIR/scripts/run_node.sh" &
  PIDS+=($!)
done

sleep 1

PYTHON_BIN="$PYTHON_BIN" \
bash "$ROOT_DIR/scripts/run_attacker.sh" &
PIDS+=($!)

echo "[test_runner] all processes started"
echo "[test_runner] press Ctrl+C to stop"

wait