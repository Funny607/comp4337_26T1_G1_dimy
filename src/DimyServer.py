from __future__ import annotations

import argparse
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from src.bloom import from_bytes as bloom_from_bytes
from src.dbf_manager import BloomFilter
from src.network_tcp import TCPBackendServer


@dataclass
class StoredCBF:
    """One uploaded Contact Bloom Filter stored by the backend."""

    node_id: str
    received_at: float
    bloom: BloomFilter
    bit_count: int = field(init=False)

    def __post_init__(self) -> None:
        self.bit_count = self.bloom.set_bit_count()


@dataclass
class DimyServerConfig:
    bind_ip: str = "0.0.0.0"
    bind_port: int = 55000
    filter_size_bytes: int = 100 * 1024
    hash_count: int = 3
    min_intersection_bits: int = 3
    debug: bool = True


class DimyServer:
    """Backend DIMY server responsible for CBF storage and QBF matching."""

    def __init__(self, config: Optional[DimyServerConfig] = None) -> None:
        self.config = config or DimyServerConfig()
        self._lock = threading.RLock()
        self._stored_cbfs: dict[str, StoredCBF] = {}

        self.tcp_server = TCPBackendServer(
            self.config.bind_ip,
            self.config.bind_port,
            on_upload_cbf=self.handle_upload_cbf,
            on_query_qbf=self.handle_query_qbf,
            expected_size_bytes=self.config.filter_size_bytes,
            expected_hash_count=self.config.hash_count,
            debug=self.config.debug,
        )

    def _debug(self, message: str) -> None:
        if self.config.debug:
            print(f"[DIMY_SERVER] {message}")

    def start(self) -> None:
        self.tcp_server.start()

    def stop(self) -> None:
        self.tcp_server.stop()

    def serve_forever(self) -> None:
        self.start()
        self._debug(
            f"listening on {self.config.bind_ip}:{self.config.bind_port}; press Ctrl+C to stop"
        )
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print()
            self.stop()

    def handle_upload_cbf(self, node_id: str, cbf_bytes: bytes) -> dict[str, Any]:
        if not isinstance(node_id, str) or not node_id.strip():
            return {"ok": False, "result": "error", "message": "node_id must be a non-empty string"}
        if not isinstance(cbf_bytes, (bytes, bytearray)):
            return {"ok": False, "result": "error", "message": "cbf_bytes must be bytes-like"}
        if len(cbf_bytes) != self.config.filter_size_bytes:
            return {
                "ok": False,
                "result": "error",
                "message": f"cbf_bytes must be exactly {self.config.filter_size_bytes} bytes",
            }

        cbf = bloom_from_bytes(
            bytes(cbf_bytes),
            size_bytes=self.config.filter_size_bytes,
            hash_count=self.config.hash_count,
        )
        stored = StoredCBF(node_id=node_id.strip(), received_at=time.time(), bloom=cbf)

        with self._lock:
            replaced = stored.node_id in self._stored_cbfs
            self._stored_cbfs[stored.node_id] = stored
            stored_count = len(self._stored_cbfs)

        self._debug(
            f"stored CBF from node={stored.node_id} bytes={len(stored.bloom.to_bytes())} "
            f"total_stored={stored_count} replaced_existing={replaced}"
        )
        return {
            "ok": True,
            "result": "uploaded",
            "message": "CBF stored successfully",
            "stored_cbfs": stored_count,
            "replaced_existing": replaced,
            "node_id": stored.node_id,
        }

    def handle_query_qbf(self, node_id: str, qbf_bytes: bytes) -> dict[str, Any]:
        if not isinstance(node_id, str) or not node_id.strip():
            return {"ok": False, "result": "error", "message": "node_id must be a non-empty string"}
        if not isinstance(qbf_bytes, (bytes, bytearray)):
            return {"ok": False, "result": "error", "message": "qbf_bytes must be bytes-like"}
        if len(qbf_bytes) != self.config.filter_size_bytes:
            return {
                "ok": False,
                "result": "error",
                "message": f"qbf_bytes must be exactly {self.config.filter_size_bytes} bytes",
            }

        qbf = bloom_from_bytes(
            bytes(qbf_bytes),
            size_bytes=self.config.filter_size_bytes,
            hash_count=self.config.hash_count,
        )

        with self._lock:
            stored_cbfs = list(self._stored_cbfs.values())

        if not stored_cbfs:
            self._debug(f"query from node={node_id.strip()} -> not matched (no CBF stored)")
            return {
                "ok": True,
                "result": "not_matched",
                "message": "no CBF available",
                "matched_cbf_count": 0,
                "min_intersection_bits": self.config.min_intersection_bits,
            }

        best_match: Optional[StoredCBF] = None
        best_intersection = 0
        qbf_bytes_exact = qbf.to_bytes()
        for stored in stored_cbfs:
            intersection_bits = _intersection_bit_count(qbf_bytes_exact, stored.bloom.to_bytes())
            if intersection_bits > best_intersection:
                best_intersection = intersection_bits
                best_match = stored

        if best_match is not None and best_intersection >= self.config.min_intersection_bits:
            self._debug(
                f"query from node={node_id.strip()} -> matched stored_node={best_match.node_id} "
                f"intersection_bits={best_intersection}"
            )
            return {
                "ok": True,
                "result": "matched",
                "message": "match found",
                "matched_node_id": best_match.node_id,
                "intersection_bits": best_intersection,
                "min_intersection_bits": self.config.min_intersection_bits,
                "stored_cbfs": len(stored_cbfs),
            }

        self._debug(
            f"query from node={node_id.strip()} -> not matched best_intersection={best_intersection}"
        )
        return {
            "ok": True,
            "result": "not_matched",
            "message": "no match found",
            "matched_cbf_count": len(stored_cbfs),
            "best_intersection_bits": best_intersection,
            "min_intersection_bits": self.config.min_intersection_bits,
        }

    def get_stored_cbfs(self) -> list[StoredCBF]:
        with self._lock:
            return [self._stored_cbfs[key] for key in sorted(self._stored_cbfs.keys())]


def _intersection_bit_count(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("Bloom filters must have the same size")
    return sum((left_byte & right_byte).bit_count() for left_byte, right_byte in zip(left, right))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY backend server")
    parser.add_argument("--bind-ip", default="0.0.0.0")
    parser.add_argument("--bind-port", type=int, default=55000)
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = DimyServer(
        DimyServerConfig(bind_ip=args.bind_ip, bind_port=args.bind_port, debug=not args.quiet),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
