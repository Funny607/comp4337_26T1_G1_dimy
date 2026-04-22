from __future__ import annotations

import base64
import json
import socket
import threading
import time
from typing import Any, Callable, Optional


DEFAULT_TCP_TIMEOUT = 5.0
DEFAULT_MAX_LINE_BYTES = 2 * 1024 * 1024

UploadCBFHandler = Callable[[str, bytes], dict[str, Any]]
QueryQBFHandler = Callable[[str, bytes], dict[str, Any]]


class TCPProtocolError(RuntimeError):
	"""Raised when a TCP message is malformed or violates protocol constraints."""


class TCPBackendClient:
	"""
	Thin TCP client for DIMY backend communication.

	Responsibilities:
	- send one JSON request per connection
	- receive one JSON response
	- provide Task 9/10 helpers for CBF upload and QBF query

	Non-responsibilities:
	- no Bloom filter hashing logic
	- no backend matching logic
	"""

	def __init__(
		self,
		server_ip: str,
		server_port: int,
		*,
		timeout: float = DEFAULT_TCP_TIMEOUT,
		max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
		debug: bool = False,
	) -> None:
		self.server_ip = _require_non_empty_text(server_ip, "server_ip")
		self.server_port = _validate_port(server_port)
		self.timeout = _validate_timeout(timeout)
		if not isinstance(max_line_bytes, int) or max_line_bytes <= 0:
			raise ValueError("max_line_bytes must be a positive integer")
		self.max_line_bytes = max_line_bytes
		self.debug = bool(debug)

	def _debug(self, message: str) -> None:
		if self.debug:
			print(f"[TCP] {message}")

	def send_request(self, message: dict[str, Any]) -> dict[str, Any]:
		request_bytes = _encode_json_line(message)

		with socket.create_connection((self.server_ip, self.server_port), timeout=self.timeout) as sock:
			sock.settimeout(self.timeout)
			sock.sendall(request_bytes)

			reader = sock.makefile("rb")
			line = reader.readline(self.max_line_bytes + 1)

		if len(line) > self.max_line_bytes:
			raise TCPProtocolError("server response exceeded max_line_bytes")

		response = _decode_json_line(line)
		self._debug(
			f"request_type={message.get('type', '?')} "
			f"response_keys={sorted(response.keys())}"
		)
		return response

	def upload_cbf(
		self,
		*,
		node_id: str,
		cbf_bytes: bytes,
		size_bytes: int,
		hash_count: int,
	) -> dict[str, Any]:
		request = make_upload_cbf_request(
			node_id=node_id,
			bloom_bytes=cbf_bytes,
			size_bytes=size_bytes,
			hash_count=hash_count,
		)
		return self.send_request(request)

	def query_qbf(
		self,
		*,
		node_id: str,
		qbf_bytes: bytes,
		size_bytes: int,
		hash_count: int,
	) -> dict[str, Any]:
		request = make_query_qbf_request(
			node_id=node_id,
			bloom_bytes=qbf_bytes,
			size_bytes=size_bytes,
			hash_count=hash_count,
		)
		return self.send_request(request)


class TCPBackendServer:
	"""
	Thin TCP server for DIMY backend.

	Responsibilities:
	- listen for incoming client connections
	- parse upload_cbf and query_qbf requests
	- dispatch to handler callbacks
	- send JSON responses

	Non-responsibilities:
	- no storage logic (delegated to handlers)
	- no matching logic (delegated to handlers)
	"""

	def __init__(
		self,
		bind_ip: str,
		bind_port: int,
		*,
		on_upload_cbf: Optional[UploadCBFHandler] = None,
		on_query_qbf: Optional[QueryQBFHandler] = None,
		max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
		debug: bool = False,
	) -> None:
		self.bind_ip = _require_non_empty_text(bind_ip, "bind_ip")
		self.bind_port = _validate_port(bind_port)
		self.on_upload_cbf = on_upload_cbf
		self.on_query_qbf = on_query_qbf
		if not isinstance(max_line_bytes, int) or max_line_bytes <= 0:
			raise ValueError("max_line_bytes must be a positive integer")
		self.max_line_bytes = max_line_bytes
		self.debug = bool(debug)

		self._lock = threading.Lock()
		self._running = threading.Event()
		self._listen_sock: Optional[socket.socket] = None
		self._accept_thread: Optional[threading.Thread] = None

	def _debug(self, message: str) -> None:
		if self.debug:
			print(f"[TCP_SERVER] {message}")

	def start(self) -> None:
		"""Start the backend server in a background accept loop."""
		with self._lock:
			if self._running.is_set():
				raise RuntimeError("TCPBackendServer is already running")

			self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

			try:
				self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			except (AttributeError, OSError):
				pass

			self._listen_sock.bind((self.bind_ip, self.bind_port))
			self._listen_sock.listen(5)
			self._listen_sock.settimeout(0.5)

			self._running.set()
			self._accept_thread = threading.Thread(
				target=self._accept_loop,
				name=f"TCPBackendServer:{self.bind_ip}:{self.bind_port}",
				daemon=True,
			)
			self._accept_thread.start()

			self._debug(
				f"server started bind=({self.bind_ip},{self.bind_port}) "
				f"has_upload_handler={self.on_upload_cbf is not None} "
				f"has_query_handler={self.on_query_qbf is not None}"
			)

	def stop(self) -> None:
		"""Stop the accept loop and close the listening socket."""
		with self._lock:
			self._running.clear()

			if self._listen_sock is not None:
				try:
					self._listen_sock.close()
				except OSError:
					pass
				self._listen_sock = None

			accept_thread = self._accept_thread
			self._accept_thread = None

		if accept_thread is not None and accept_thread.is_alive():
			accept_thread.join(timeout=1.0)

		self._debug("server stopped")

	def _accept_loop(self) -> None:
		while self._running.is_set():
			sock = self._listen_sock
			if sock is None:
				break

			try:
				client_sock, client_addr = sock.accept()
			except socket.timeout:
				continue
			except OSError:
				break

			threading.Thread(
				target=self._handle_connection,
				args=(client_sock, client_addr),
				daemon=True,
			).start()

	def _handle_connection(self, client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
		try:
			reader = client_sock.makefile("rb")
			request_line = reader.readline(self.max_line_bytes + 1)

			if len(request_line) > self.max_line_bytes:
				response = {
					"ok": False,
					"result": "error",
					"message": "request exceeded max size",
				}
			else:
				try:
					request = _decode_json_line(request_line)
					response = self._dispatch_request(request)
				except TCPProtocolError as exc:
					response = {
						"ok": False,
						"result": "error",
						"message": str(exc),
					}
				except Exception as exc:
					self._debug(f"handler error from {client_addr}: {exc!r}")
					response = {
						"ok": False,
						"result": "error",
						"message": "internal server error",
					}

			response_bytes = _encode_json_line(response)
			client_sock.sendall(response_bytes)

		except Exception as exc:
			self._debug(f"connection error from {client_addr}: {exc!r}")
		finally:
			try:
				client_sock.close()
			except OSError:
				pass

	def _dispatch_request(self, request: dict[str, Any]) -> dict[str, Any]:
		request_type = request.get("type")

		if request_type == "upload_cbf":
			return self._handle_upload_cbf(request)
		elif request_type == "query_qbf":
			return self._handle_query_qbf(request)
		else:
			raise TCPProtocolError(f"unknown request type: {request_type}")

	def _handle_upload_cbf(self, request: dict[str, Any]) -> dict[str, Any]:
		try:
			node_id = str(request["node_id"])
			bloom_b64 = str(request["bloom_b64"])
			bloom_bytes = decode_bloom_bytes(bloom_b64)
		except (KeyError, TypeError, ValueError) as exc:
			raise TCPProtocolError(f"invalid upload_cbf request: {exc!r}") from exc

		if self.on_upload_cbf is None:
			return {
				"ok": False,
				"result": "error",
				"message": "upload not supported",
			}

		try:
			result = self.on_upload_cbf(node_id, bloom_bytes)
			self._debug(f"upload_cbf from {node_id}: result={result.get('result')}")
			return result
		except Exception as exc:
			self._debug(f"upload handler raised: {exc!r}")
			raise TCPProtocolError(f"upload handler error: {exc!r}") from exc

	def _handle_query_qbf(self, request: dict[str, Any]) -> dict[str, Any]:
		try:
			node_id = str(request["node_id"])
			bloom_b64 = str(request["bloom_b64"])
			bloom_bytes = decode_bloom_bytes(bloom_b64)
		except (KeyError, TypeError, ValueError) as exc:
			raise TCPProtocolError(f"invalid query_qbf request: {exc!r}") from exc

		if self.on_query_qbf is None:
			return {
				"ok": False,
				"result": "error",
				"message": "query not supported",
			}

		try:
			result = self.on_query_qbf(node_id, bloom_bytes)
			self._debug(f"query_qbf from {node_id}: result={result.get('result')}")
			return result
		except Exception as exc:
			self._debug(f"query handler raised: {exc!r}")
			raise TCPProtocolError(f"query handler error: {exc!r}") from exc


def _require_non_empty_text(value: str, field_name: str) -> str:
	if not isinstance(value, str):
		raise TypeError(f"{field_name} must be a string")
	value = value.strip()
	if not value:
		raise ValueError(f"{field_name} must be non-empty")
	return value


def _validate_port(port: int) -> int:
	if not isinstance(port, int):
		raise TypeError("server_port must be an integer")
	if not (1 <= port <= 65535):
		raise ValueError("server_port must be in range 1..65535")
	return port


def _validate_timeout(timeout: float) -> float:
	if not isinstance(timeout, (int, float)):
		raise TypeError("timeout must be a number")
	timeout = float(timeout)
	if timeout <= 0:
		raise ValueError("timeout must be positive")
	return timeout


def encode_bloom_bytes(bloom_bytes: bytes) -> str:
	"""Encode bloom filter bytes into ASCII base64 for JSON transport."""
	if not isinstance(bloom_bytes, (bytes, bytearray)):
		raise TypeError("bloom_bytes must be bytes-like")
	return base64.b64encode(bytes(bloom_bytes)).decode("ascii")


def decode_bloom_bytes(encoded: str) -> bytes:
	"""Decode base64 bloom bytes from JSON transport payload."""
	if not isinstance(encoded, str):
		raise TypeError("encoded bloom must be a string")
	try:
		return base64.b64decode(encoded.encode("ascii"), validate=True)
	except Exception as exc:
		raise ValueError("Invalid base64 bloom payload") from exc


def _validate_bloom_shape(bloom_bytes: bytes, size_bytes: int, hash_count: int) -> None:
	if not isinstance(size_bytes, int) or size_bytes <= 0:
		raise ValueError("size_bytes must be a positive integer")
	if not isinstance(hash_count, int) or hash_count <= 0:
		raise ValueError("hash_count must be a positive integer")
	if len(bloom_bytes) != size_bytes:
		raise ValueError(
			f"Bloom payload length mismatch: expected {size_bytes} bytes, got {len(bloom_bytes)}"
		)


def make_upload_cbf_request(
	*,
	node_id: str,
	bloom_bytes: bytes,
	size_bytes: int,
	hash_count: int,
	timestamp: Optional[float] = None,
) -> dict[str, Any]:
	"""Build a backend request for Task 9 CBF upload."""
	node_id = _require_non_empty_text(node_id, "node_id")
	bloom_bytes = bytes(bloom_bytes)
	_validate_bloom_shape(bloom_bytes, size_bytes, hash_count)

	if timestamp is None:
		timestamp = time.time()

	return {
		"type": "upload_cbf",
		"version": 1,
		"node_id": node_id,
		"size_bytes": size_bytes,
		"hash_count": hash_count,
		"bloom_b64": encode_bloom_bytes(bloom_bytes),
		"timestamp": float(timestamp),
	}


def make_query_qbf_request(
	*,
	node_id: str,
	bloom_bytes: bytes,
	size_bytes: int,
	hash_count: int,
	timestamp: Optional[float] = None,
) -> dict[str, Any]:
	"""Build a backend request for Task 10 QBF query."""
	node_id = _require_non_empty_text(node_id, "node_id")
	bloom_bytes = bytes(bloom_bytes)
	_validate_bloom_shape(bloom_bytes, size_bytes, hash_count)

	if timestamp is None:
		timestamp = time.time()

	return {
		"type": "query_qbf",
		"version": 1,
		"node_id": node_id,
		"size_bytes": size_bytes,
		"hash_count": hash_count,
		"bloom_b64": encode_bloom_bytes(bloom_bytes),
		"timestamp": float(timestamp),
	}


def _encode_json_line(message: dict[str, Any]) -> bytes:
	if not isinstance(message, dict):
		raise TypeError("message must be a dict")
	try:
		return (json.dumps(message, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
	except (TypeError, ValueError) as exc:
		raise ValueError("message must be JSON-serializable") from exc


def _decode_json_line(line: bytes) -> dict[str, Any]:
	if not line:
		raise TCPProtocolError("no response from server")
	try:
		payload = json.loads(line.decode("utf-8"))
	except (UnicodeDecodeError, json.JSONDecodeError) as exc:
		raise TCPProtocolError("server returned invalid UTF-8 JSON") from exc

	if not isinstance(payload, dict):
		raise TCPProtocolError("server response must be a JSON object")
	return payload


def send_request(
	*,
	server_ip: str,
	server_port: int,
	message: dict[str, Any],
	timeout: float = DEFAULT_TCP_TIMEOUT,
	max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
) -> dict[str, Any]:
	"""Backward-compatible functional wrapper around TCPBackendClient."""
	client = TCPBackendClient(
		server_ip=server_ip,
		server_port=server_port,
		timeout=timeout,
		max_line_bytes=max_line_bytes,
	)
	return client.send_request(message)


def upload_cbf(
	*,
	server_ip: str,
	server_port: int,
	node_id: str,
	cbf_bytes: bytes,
	size_bytes: int,
	hash_count: int,
	timeout: float = DEFAULT_TCP_TIMEOUT,
) -> dict[str, Any]:
	"""Backward-compatible functional wrapper around TCPBackendClient."""
	client = TCPBackendClient(
		server_ip=server_ip,
		server_port=server_port,
		timeout=timeout,
	)
	return client.upload_cbf(
		node_id=node_id,
		cbf_bytes=cbf_bytes,
		size_bytes=size_bytes,
		hash_count=hash_count,
	)


def query_qbf(
	*,
	server_ip: str,
	server_port: int,
	node_id: str,
	qbf_bytes: bytes,
	size_bytes: int,
	hash_count: int,
	timeout: float = DEFAULT_TCP_TIMEOUT,
) -> dict[str, Any]:
	"""Backward-compatible functional wrapper around TCPBackendClient."""
	client = TCPBackendClient(
		server_ip=server_ip,
		server_port=server_port,
		timeout=timeout,
	)
	return client.query_qbf(
		node_id=node_id,
		qbf_bytes=qbf_bytes,
		size_bytes=size_bytes,
		hash_count=hash_count,
	)
