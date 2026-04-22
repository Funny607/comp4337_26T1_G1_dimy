#!/usr/bin/env bash
set -e

trap "kill 0" EXIT

echo "[test_runner] starting full DIMY demo..."

python3 -m src.DimyServer &
sleep 1

python3 -m src.Dimy 15 3 5 20 127.0.0.1 55000 --node-id nodeA &
python3 -m src.Dimy 15 3 5 20 127.0.0.1 55000 --node-id nodeB &
python3 -m src.Dimy 15 3 5 20 127.0.0.1 55000 --node-id nodeC &

sleep 1

python3 -m src.Attacker 15 3 5 --bind-port 37020 &

echo "[test_runner] all processes started"
echo "[test_runner] press Ctrl+C to stop"

wait