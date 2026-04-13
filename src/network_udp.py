from __future__ import annotations

import json
import random
import socket
import threading
from typing import Any, Callable, Optional


PacketHandler = Callable[[dict[str, Any], tuple[str, int]], None]


class UDPShareTransport:
    """
    Thin UDP transport for DIMY share advertisements.

    Responsibilities:
    - send JSON packets over UDP
    - receive JSON packets on a background thread
    - simulate probabilistic packet drops at the receiver
    - optionally ignore packets sent by this node itself

    Non-responsibilities:
    - no Shamir logic
    - no crypto logic
    - no Bloom filter logic
    """

    def __init__(
        self,
        bind_ip: str,
        bind_port: int,
        target_ip: str,
        target_port: int,
        drop_prob: float,
        on_packet: PacketHandler,
        *,
        node_id: Optional[str] = None,
        ignore_self: bool = True,
        debug: bool = False,
        recv_buffer_size: int = 65535,
        socket_timeout: float = 0.2,
    ) -> None:
        if not isinstance(bind_ip, str) or not bind_ip:
            raise ValueError("bind_ip must be a non-empty string")
        if not isinstance(target_ip, str) or not target_ip:
            raise ValueError("target_ip must be a non-empty string")
        if not isinstance(bind_port, int) or not (1 <= bind_port <= 65535):
            raise ValueError("bind_port must be an integer in range 1..65535")
        if not isinstance(target_port, int) or not (1 <= target_port <= 65535):
            raise ValueError("target_port must be an integer in range 1..65535")
        if not callable(on_packet):
            raise TypeError("on_packet must be callable")
        if not isinstance(drop_prob, (int, float)):
            raise TypeError("drop_prob must be a number")
        if not (0.0 <= float(drop_prob) <= 1.0):
            raise ValueError("drop_prob must be in range 0.0..1.0")
        if recv_buffer_size <= 0:
            raise ValueError("recv_buffer_size must be positive")
        if socket_timeout <= 0:
            raise ValueError("socket_timeout must be positive")

        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.drop_prob = float(drop_prob)
        self.on_packet = on_packet
        self.node_id = node_id
        self.ignore_self = ignore_self
        self.debug = debug
        self.recv_buffer_size = recv_buffer_size
        self.socket_timeout = socket_timeout

        self._send_sock: Optional[socket.socket] = None
        self._recv_sock: Optional[socket.socket] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._lock = threading.Lock()

    def start(self) -> None:
        """
        Start UDP transport and background receive loop.
        Safe to call once.
        """
        with self._lock:
            if self._running.is_set():
                raise RuntimeError("UDPShareTransport is already running")

            self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                self._recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass

            self._recv_sock.bind((self.bind_ip, self.bind_port))
            self._recv_sock.settimeout(self.socket_timeout)

            self._running.set()
            self._recv_thread = threading.Thread(
                target=self._recv_loop,
                name=f"UDPShareTransport:{self.bind_ip}:{self.bind_port}",
                daemon=True,
            )
            self._recv_thread.start()

            if self.debug:
                print(
                    f"[UDP] started bind=({self.bind_ip},{self.bind_port}) "
                    f"target=({self.target_ip},{self.target_port}) "
                    f"drop_prob={self.drop_prob:.2f}"
                )

    def stop(self) -> None:
        """
        Stop background receive loop and close sockets.
        Safe to call multiple times.
        """
        with self._lock:
            self._running.clear()

            if self._recv_sock is not None:
                try:
                    self._recv_sock.close()
                except OSError:
                    pass
                self._recv_sock = None

            if self._send_sock is not None:
                try:
                    self._send_sock.close()
                except OSError:
                    pass
                self._send_sock = None

            recv_thread = self._recv_thread
            self._recv_thread = None

        if recv_thread is not None and recv_thread.is_alive():
            recv_thread.join(timeout=1.0)

        if self.debug:
            print("[UDP] stopped")

    def send_packet(self, packet: dict[str, Any]) -> None:
        """
        Send one JSON packet to the configured target endpoint.
        """
        if not isinstance(packet, dict):
            raise TypeError("packet must be a dict")

        sock = self._send_sock
        if sock is None or not self._running.is_set():
            raise RuntimeError("UDPShareTransport is not running")

        payload = self.encode_packet(packet)
        sock.sendto(payload, (self.target_ip, self.target_port))

        if self.debug:
            packet_type = packet.get("type", "?")
            print(
                f"[UDP] sent type={packet_type} "
                f"to=({self.target_ip},{self.target_port}) bytes={len(payload)}"
            )

    def encode_packet(self, packet: dict[str, Any]) -> bytes:
        """
        Encode a packet dict into UTF-8 JSON bytes.
        """
        try:
            return json.dumps(packet, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Packet must be JSON-serializable") from exc

    def decode_packet(self, payload: bytes) -> dict[str, Any]:
        """
        Decode UTF-8 JSON bytes into a packet dict.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes-like")

        try:
            obj = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Received payload is not valid UTF-8 JSON") from exc

        if not isinstance(obj, dict):
            raise ValueError("Decoded packet must be a JSON object")
        return obj

    def _should_drop(self) -> bool:
        return random.random() < self.drop_prob

    def _is_self_packet(self, packet: dict[str, Any]) -> bool:
        if not self.ignore_self:
            return False
        if self.node_id is None:
            return False
        sender_id = packet.get("sender_id")
        return isinstance(sender_id, str) and sender_id == self.node_id

    def _recv_loop(self) -> None:
        while self._running.is_set():
            recv_sock = self._recv_sock
            if recv_sock is None:
                break

            try:
                payload, addr = recv_sock.recvfrom(self.recv_buffer_size)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                packet = self.decode_packet(payload)
            except ValueError:
                if self.debug:
                    print("[UDP] dropped invalid JSON payload")
                continue

            if self._is_self_packet(packet):
                if self.debug:
                    print("[UDP] ignored self packet")
                continue

            if self._should_drop():
                if self.debug:
                    print("[UDP] simulated drop")
                continue

            try:
                self.on_packet(packet, addr)
            except Exception as exc:
                if self.debug:
                    print(f"[UDP] packet handler raised: {exc!r}")
                continue
