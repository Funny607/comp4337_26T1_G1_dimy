#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[cleanup] stopping DIMY processes..."

pkill -f "src\.DimyServer" 2>/dev/null || true
pkill -f "src\.Attacker" 2>/dev/null || true
pkill -f " -m src\.Dimy " 2>/dev/null || true

if [[ -d "$ROOT_DIR/logs" ]]; then
  find "$ROOT_DIR/logs" -maxdepth 1 -type f ! -name ".gitkeep" -delete
fi

echo "[cleanup] done"