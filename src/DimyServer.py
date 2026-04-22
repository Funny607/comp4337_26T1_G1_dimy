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
	debug: bool = True


class DimyServer:
	"""
	Backend DIMY server responsible for CBF storage and QBF matching.

	This class owns the application state, while TCPBackendServer handles
	the socket lifecycle and request framing.
	"""

	def __init__(self, config: Optional[DimyServerConfig] = None) -> None:
		self.config = config or DimyServerConfig()
		self._lock = threading.RLock()
		self._stored_cbfs: list[StoredCBF] = []

		self.tcp_server = TCPBackendServer(
			self.config.bind_ip,
			self.config.bind_port,
			on_upload_cbf=self.handle_upload_cbf,
			on_query_qbf=self.handle_query_qbf,
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
		"""Block the main thread until interrupted."""
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
			return {
				"ok": False,
				"result": "error",
				"message": "node_id must be a non-empty string",
			}
		if not isinstance(cbf_bytes, (bytes, bytearray)):
			return {
				"ok": False,
				"result": "error",
				"message": "cbf_bytes must be bytes-like",
			}
		if len(cbf_bytes) != self.config.filter_size_bytes:
			return {
				"ok": False,
				"result": "error",
				"message": (
					f"cbf_bytes must be exactly {self.config.filter_size_bytes} bytes"
				),
			}

		cbf = bloom_from_bytes(bytes(cbf_bytes))
		stored = StoredCBF(
			node_id=node_id.strip(),
			received_at=time.time(),
			bloom=cbf,
		)

		with self._lock:
			self._stored_cbfs.append(stored)
			stored_count = len(self._stored_cbfs)

		self._debug(
			f"stored CBF from node={stored.node_id} "
			f"bytes={len(stored.bloom.to_bytes())} total_stored={stored_count}"
		)

		return {
			"ok": True,
			"result": "uploaded",
			"message": "CBF stored successfully",
			"stored_cbfs": stored_count,
		}

	def handle_query_qbf(self, node_id: str, qbf_bytes: bytes) -> dict[str, Any]:
		if not isinstance(node_id, str) or not node_id.strip():
			return {
				"ok": False,
				"result": "error",
				"message": "node_id must be a non-empty string",
			}
		if not isinstance(qbf_bytes, (bytes, bytearray)):
			return {
				"ok": False,
				"result": "error",
				"message": "qbf_bytes must be bytes-like",
			}
		if len(qbf_bytes) != self.config.filter_size_bytes:
			return {
				"ok": False,
				"result": "error",
				"message": (
					f"qbf_bytes must be exactly {self.config.filter_size_bytes} bytes"
				),
			}

		qbf = bloom_from_bytes(bytes(qbf_bytes))

		with self._lock:
			stored_cbfs = list(self._stored_cbfs)

		if not stored_cbfs:
			self._debug(f"query from node={node_id.strip()} -> not matched (no CBF stored)")
			return {
				"ok": True,
				"result": "not_matched",
				"message": "no CBF available",
				"matched_cbf_count": 0,
			}

		for stored in stored_cbfs:
			intersection_bits = _intersection_bit_count(qbf.to_bytes(), stored.bloom.to_bytes())
			if intersection_bits > 0:
				self._debug(
					f"query from node={node_id.strip()} -> matched stored_node={stored.node_id} "
					f"intersection_bits={intersection_bits}"
				)
				return {
					"ok": True,
					"result": "matched",
					"message": "match found",
					"matched_node_id": stored.node_id,
					"intersection_bits": intersection_bits,
				}

		self._debug(f"query from node={node_id.strip()} -> not matched")
		return {
			"ok": True,
			"result": "not_matched",
			"message": "no match found",
			"matched_cbf_count": len(stored_cbfs),
		}

	def get_stored_cbfs(self) -> list[StoredCBF]:
		with self._lock:
			return list(self._stored_cbfs)


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
		DimyServerConfig(
			bind_ip=args.bind_ip,
			bind_port=args.bind_port,
			debug=not args.quiet,
		),
	)
	server.serve_forever()


if __name__ == "__main__":
	main()
