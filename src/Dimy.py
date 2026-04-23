from __future__ import annotations

import argparse
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from src.config import (
    DEFAULT_BLOOM_HASH_COUNT,
    DEFAULT_BLOOM_SIZE_BYTES,
    DEFAULT_SERVER_IP,
    DEFAULT_SERVER_PORT,
    DEFAULT_UDP_BIND_IP,
    DEFAULT_UDP_BROADCAST_IP,
    DEFAULT_UDP_PORT,
    MIN_K,
    MIN_N,
    VALID_P_VALUES,
    VALID_T_VALUES,
)
from src.crypto_utils import (
    LocalEphID,
    derive_encounter_id,
    generate_ephid_keypair,
    short_hex,
    verify_ephid_hash,
)
from src.dbf_manager import DBFManager, DBFState, QBFState
from src.network_tcp import query_qbf, upload_cbf
from src.network_udp import UDPShareTransport
from src.protocol_utils import SHARE_PACKET_TYPE, make_share_packet
from src.shamir_utils import (
    ShamirShare,
    combine_shares,
    deserialize_share,
    serialize_share,
    split_secret,
)


EncounterHandler = Callable[[bytes, dict[str, Any]], None]
QBFHandler = Callable[[QBFState], None]


@dataclass
class DimyNodeConfig:
    node_id: str
    t: int
    k: int
    n: int
    p: int

    server_ip: str = DEFAULT_SERVER_IP
    server_port: int = DEFAULT_SERVER_PORT

    bind_ip: str = DEFAULT_UDP_BIND_IP
    bind_port: int = DEFAULT_UDP_PORT
    target_ip: str = DEFAULT_UDP_BROADCAST_IP
    target_port: int = DEFAULT_UDP_PORT

    filter_size_bytes: int = DEFAULT_BLOOM_SIZE_BYTES
    hash_count: int = DEFAULT_BLOOM_HASH_COUNT

    debug: bool = True
    enable_udp: bool = True
    keep_recent_epochs: int = 3
    enable_qbf_scheduler: bool = True
    auto_query_backend: bool = True
    enable_interactive_commands: bool = True
    positive_after: Optional[float] = None


@dataclass
class LocalEpochState:
    epoch_id: int
    created_at: float
    ephid: LocalEphID
    shares: list[ShamirShare]
    next_share_cursor: int = 0

    @property
    def ephid_hash(self) -> str:
        return self.ephid.ephid_hash

    @property
    def ephid_bytes(self) -> bytes:
        return self.ephid.public_key_bytes


@dataclass
class PeerShareBuffer:
    epoch_id: int
    sender_id: str
    ephid_hash: str
    k: int
    n: int
    first_seen: float
    last_seen: float
    shares_by_index: dict[int, ShamirShare] = field(default_factory=dict)
    reconstructed: bool = False


class DimyNode:
    def __init__(
        self,
        config: DimyNodeConfig,
        encounter_handler: Optional[EncounterHandler] = None,
        qbf_handler: Optional[QBFHandler] = None,
        dbf_manager: Optional[DBFManager] = None,
    ) -> None:
        self.config = config
        self.encounter_handler = encounter_handler
        self.qbf_handler = qbf_handler

        self._lock = threading.RLock()
        self._running = threading.Event()
        self._epoch_thread: Optional[threading.Thread] = None
        self._broadcast_thread: Optional[threading.Thread] = None
        self._qbf_thread: Optional[threading.Thread] = None
        self._positive_thread: Optional[threading.Thread] = None
        self._stdin_thread: Optional[threading.Thread] = None

        self._cbf_uploaded = False
        self._last_backend_result: Optional[dict[str, Any]] = None

        self.local_epochs: dict[int, LocalEpochState] = {}
        self.peer_buffers: dict[tuple[int, str, str], PeerShareBuffer] = {}
        self.seen_encounter_ids: set[str] = set()

        self.dbf_manager = dbf_manager or DBFManager(
            t=self.config.t,
            filter_size_bytes=self.config.filter_size_bytes,
            hash_count=self.config.hash_count,
            debug_hook=self._debug if self.config.debug else None,
        )

        self.transport: Optional[UDPShareTransport] = None
        if self.config.enable_udp:
            self.transport = UDPShareTransport(
                bind_ip=self.config.bind_ip,
                bind_port=self.config.bind_port,
                target_ip=self.config.target_ip,
                target_port=self.config.target_port,
                drop_prob=self.config.p / 100.0,
                on_packet=self.handle_udp_packet,
                node_id=self.config.node_id,
                ignore_self=True,
                debug=self.config.debug,
            )

    def start(self) -> None:
        with self._lock:
            if self._running.is_set():
                raise RuntimeError("DimyNode is already running")

            self._running.set()

            current_epoch = self.current_epoch_id()
            self.ensure_epoch(current_epoch)
            self.dbf_manager.rotate_if_needed()

            if self.transport is not None:
                self.transport.start()

            self._epoch_thread = threading.Thread(
                target=self._epoch_loop,
                name=f"DimyEpochLoop:{self.config.node_id}",
                daemon=True,
            )
            self._broadcast_thread = threading.Thread(
                target=self._broadcast_loop,
                name=f"DimyBroadcastLoop:{self.config.node_id}",
                daemon=True,
            )
            self._epoch_thread.start()
            self._broadcast_thread.start()

            if self.config.enable_qbf_scheduler:
                self._qbf_thread = threading.Thread(
                    target=self._qbf_loop,
                    name=f"DimyQBFLoop:{self.config.node_id}",
                    daemon=True,
                )
                self._qbf_thread.start()

            if self.config.positive_after is not None:
                self._positive_thread = threading.Thread(
                    target=self._positive_after_loop,
                    name=f"DimyPositiveAfter:{self.config.node_id}",
                    daemon=True,
                )
                self._positive_thread.start()

            if self.config.enable_interactive_commands and sys.stdin and sys.stdin.isatty():
                self._stdin_thread = threading.Thread(
                    target=self._stdin_loop,
                    name=f"DimyInteractive:{self.config.node_id}",
                    daemon=True,
                )
                self._stdin_thread.start()

            self._debug(
                f"node started; epoch={current_epoch} "
                f"t={self.config.t} k={self.config.k} n={self.config.n} p={self.config.p}% "
                f"server={self.config.server_ip}:{self.config.server_port}"
            )
            if self.config.enable_interactive_commands and sys.stdin and sys.stdin.isatty():
                self._debug("interactive commands: upload | status | quit")

    def stop(self) -> None:
        with self._lock:
            self._running.clear()

            transport = self.transport
            epoch_thread = self._epoch_thread
            broadcast_thread = self._broadcast_thread
            qbf_thread = self._qbf_thread
            positive_thread = self._positive_thread

            self._epoch_thread = None
            self._broadcast_thread = None
            self._qbf_thread = None
            self._positive_thread = None

        if transport is not None:
            transport.stop()

        if epoch_thread is not None and epoch_thread.is_alive():
            epoch_thread.join(timeout=1.0)
        if broadcast_thread is not None and broadcast_thread.is_alive():
            broadcast_thread.join(timeout=1.0)
        if qbf_thread is not None and qbf_thread.is_alive():
            qbf_thread.join(timeout=1.0)
        if positive_thread is not None and positive_thread.is_alive():
            positive_thread.join(timeout=1.0)

        self._debug("node stopped")

    def is_running(self) -> bool:
        return self._running.is_set()

    def current_epoch_id(self) -> int:
        return int(time.time() // self.config.t)

    def ensure_epoch(self, epoch_id: Optional[int] = None) -> LocalEpochState:
        if epoch_id is None:
            epoch_id = self.current_epoch_id()

        with self._lock:
            existing = self.local_epochs.get(epoch_id)
            if existing is not None:
                return existing

            ephid = generate_ephid_keypair()
            shares = split_secret(ephid.public_key_bytes, k=self.config.k, n=self.config.n)

            state = LocalEpochState(
                epoch_id=epoch_id,
                created_at=time.time(),
                ephid=ephid,
                shares=shares,
            )
            self.local_epochs[epoch_id] = state
            self._prune_old_state_locked()

        self._debug(
            f"new EphID epoch={epoch_id} "
            f"ephid={short_hex(state.ephid_bytes)} "
            f"hash={state.ephid_hash[:12]}..."
        )
        self._debug(f"generated {len(state.shares)} shares for epoch={epoch_id}")
        return state

    def _epoch_loop(self) -> None:
        while self._running.is_set():
            try:
                self.ensure_epoch(self.current_epoch_id())
            except Exception as exc:
                self._debug(f"epoch loop error: {exc!r}")
            time.sleep(0.2)

    def _qbf_loop(self) -> None:
        last_period_id: Optional[int] = None

        while self._running.is_set():
            try:
                now = time.time()
                self.dbf_manager.rotate_if_needed(now)

                if self._cbf_uploaded:
                    time.sleep(0.2)
                    continue

                period_id = self.dbf_manager.current_qbf_period_id(now)
                if period_id != last_period_id:
                    qbf = self.dbf_manager.build_qbf(now, force=True)
                    last_period_id = period_id

                    if qbf is not None and self.qbf_handler is not None:
                        self.qbf_handler(qbf)

                    if qbf is not None and self.config.auto_query_backend:
                        self.query_backend_for_qbf(qbf)
            except Exception as exc:
                self._debug(f"qbf loop error: {exc!r}")

            time.sleep(0.2)

    def _positive_after_loop(self) -> None:
        assert self.config.positive_after is not None
        deadline = time.time() + self.config.positive_after

        while self._running.is_set() and time.time() < deadline:
            time.sleep(0.2)

        if self._running.is_set() and not self._cbf_uploaded:
            self._debug("positive-after timer fired; uploading CBF")
            self.upload_current_cbf()

    def _stdin_loop(self) -> None:
        while self._running.is_set():
            try:
                line = sys.stdin.readline()
            except Exception:
                break

            if not line:
                break

            command = line.strip().lower()
            if not command:
                continue

            if command == "upload":
                self.upload_current_cbf()
            elif command == "status":
                last_qbf = self.get_last_qbf()
                self._debug(
                    f"status cbf_uploaded={self._cbf_uploaded} "
                    f"dbfs={len(self.get_dbfs())} "
                    f"last_qbf_period={None if last_qbf is None else last_qbf.period_id} "
                    f"last_backend_result={None if self._last_backend_result is None else self._last_backend_result.get('result')}"
                )
            elif command == "quit":
                self.stop()
                break
            else:
                self._debug("unknown command; available: upload | status | quit")

    def _prune_old_state_locked(self) -> None:
        if not self.local_epochs:
            return

        epoch_ids = sorted(self.local_epochs.keys())
        while len(epoch_ids) > self.config.keep_recent_epochs:
            oldest = epoch_ids.pop(0)
            self.local_epochs.pop(oldest, None)

        if epoch_ids:
            min_epoch_to_keep = epoch_ids[0]
            stale_keys = [
                key for key in self.peer_buffers.keys()
                if key[0] < min_epoch_to_keep
            ]
            for key in stale_keys:
                self.peer_buffers.pop(key, None)

    def _broadcast_loop(self) -> None:
        while self._running.is_set():
            try:
                self.send_next_share()
            except Exception as exc:
                self._debug(f"broadcast loop error: {exc!r}")
            time.sleep(3.0)

    def send_next_share(self) -> None:
        state = self.ensure_epoch(self.current_epoch_id())
        if not state.shares:
            return

        share = state.shares[state.next_share_cursor]
        packet = self.build_share_packet(state, share)

        with self._lock:
            state.next_share_cursor = (state.next_share_cursor + 1) % len(state.shares)

        if self.transport is None:
            self._debug(
                f"(no UDP) prepared share epoch={state.epoch_id} "
                f"share_index={share.index}/{self.config.n}"
            )
            return

        self.transport.send_packet(packet)
        self._debug(
            f"broadcast share epoch={state.epoch_id} "
            f"share_index={share.index}/{self.config.n} "
            f"hash={state.ephid_hash[:12]}..."
        )

    def build_share_packet(self, state: LocalEpochState, share: ShamirShare) -> dict[str, Any]:
        return make_share_packet(
            sender_id=self.config.node_id,
            epoch_id=state.epoch_id,
            ephid_hash=state.ephid_hash,
            k=self.config.k,
            n=self.config.n,
            serialized_share=serialize_share(share),
            timestamp=time.time(),
        )

    def handle_udp_packet(self, packet: dict[str, Any], addr: tuple[str, int]) -> None:
        if not isinstance(packet, dict):
            return
        if packet.get("type") != SHARE_PACKET_TYPE:
            return

        try:
            sender_id = str(packet["sender_id"])
            epoch_id = int(packet["epoch_id"])
            ephid_hash = str(packet["ephid_hash"]).lower()
            k = int(packet["k"])
            n = int(packet["n"])
            share_text = str(packet["share"])
        except (KeyError, TypeError, ValueError):
            self._debug("received malformed share packet")
            return

        try:
            share = deserialize_share(share_text)
        except Exception:
            self._debug("received invalid serialized share")
            return

        buffer_key = (epoch_id, ephid_hash, sender_id)

        with self._lock:
            buffer = self.peer_buffers.get(buffer_key)
            if buffer is None:
                buffer = PeerShareBuffer(
                    epoch_id=epoch_id,
                    sender_id=sender_id,
                    ephid_hash=ephid_hash,
                    k=k,
                    n=n,
                    first_seen=time.time(),
                    last_seen=time.time(),
                )
                self.peer_buffers[buffer_key] = buffer

            buffer.last_seen = time.time()

            if share.index in buffer.shares_by_index:
                self._debug(
                    f"duplicate share ignored sender={sender_id} "
                    f"epoch={epoch_id} share_index={share.index}"
                )
                return

            if buffer.reconstructed:
                return

            buffer.shares_by_index[share.index] = share
            share_count = len(buffer.shares_by_index)

        self._debug(
            f"received share sender={sender_id} epoch={epoch_id} "
            f"share_index={share.index}/{n} total_distinct={share_count}"
        )

        if share_count >= k:
            self._attempt_reconstruction(buffer_key)

    def _attempt_reconstruction(self, buffer_key: tuple[int, str, str]) -> None:
        with self._lock:
            buffer = self.peer_buffers.get(buffer_key)
            if buffer is None or buffer.reconstructed:
                return

            if len(buffer.shares_by_index) < buffer.k:
                return

            shares = list(buffer.shares_by_index.values())[:buffer.k]
            local_state = self.local_epochs.get(buffer.epoch_id)

            if local_state is None:
                self._debug(
                    f"cannot reconstruct sender={buffer.sender_id} "
                    f"epoch={buffer.epoch_id}: no matching local epoch retained"
                )
                return

        try:
            reconstructed_ephid = combine_shares(shares, k=buffer.k)
        except Exception as exc:
            self._debug(
                f"reconstruction failed sender={buffer.sender_id} "
                f"epoch={buffer.epoch_id}: {exc!r}"
            )
            return

        if not verify_ephid_hash(reconstructed_ephid, buffer.ephid_hash):
            self._debug(
                f"reconstruction hash mismatch sender={buffer.sender_id} "
                f"epoch={buffer.epoch_id}"
            )
            return

        self._debug(
            f"reconstruction OK sender={buffer.sender_id} "
            f"epoch={buffer.epoch_id} ephid={short_hex(reconstructed_ephid)}"
        )

        try:
            encid = derive_encounter_id(
                my_private_key=local_state.ephid.private_key,
                peer_ephid_bytes=reconstructed_ephid,
                my_ephid_hash=local_state.ephid_hash,
                peer_ephid_hash=buffer.ephid_hash,
            )
        except Exception as exc:
            self._debug(
                f"EncID derivation failed sender={buffer.sender_id} "
                f"epoch={buffer.epoch_id}: {exc!r}"
            )
            return

        metadata = {
            "sender_id": buffer.sender_id,
            "epoch_id": buffer.epoch_id,
            "peer_ephid_hash": buffer.ephid_hash,
            "local_ephid_hash": local_state.ephid_hash,
            "peer_share_count": len(buffer.shares_by_index),
            "source": "udp",
        }

        with self._lock:
            encid_hex = encid.hex()
            if encid_hex in self.seen_encounter_ids:
                buffer.reconstructed = True
                self._debug(
                    f"duplicate EncID ignored sender={buffer.sender_id} "
                    f"epoch={buffer.epoch_id}"
                )
                return

            self.seen_encounter_ids.add(encid_hex)
            buffer.reconstructed = True

        self._debug(
            f"EncID derived sender={buffer.sender_id} "
            f"epoch={buffer.epoch_id} encid={short_hex(encid)}"
        )
        self._emit_encounter(encid, metadata)

    def _store_encounter_in_dbf(self, encid: bytes) -> DBFState:
        dbf = self.dbf_manager.add_encounter(encid)
        self._debug(
            f"EncID encoded into DBF window={dbf.window_id} "
            f"encounters={dbf.encounter_count}"
        )
        return dbf

    def _emit_encounter(self, encid: bytes, metadata: dict[str, Any]) -> None:
        self._store_encounter_in_dbf(encid)

        if self.encounter_handler is not None:
            self.encounter_handler(encid, metadata)
        else:
            self._debug(
                f"encounter stored; EncID deleted after DBF insert "
                f"sender={metadata.get('sender_id')} encid={short_hex(encid)}"
            )

    def upload_current_cbf(self) -> dict[str, Any]:
        with self._lock:
            if self._cbf_uploaded:
                response = {
                    "ok": True,
                    "result": "already_uploaded",
                    "message": "CBF has already been uploaded",
                }
                self._last_backend_result = response
                return response

        cbf = self.dbf_manager.build_cbf()
        response = upload_cbf(
            server_ip=self.config.server_ip,
            server_port=self.config.server_port,
            node_id=self.config.node_id,
            cbf_bytes=cbf.to_bytes(),
            size_bytes=self.config.filter_size_bytes,
            hash_count=self.config.hash_count,
        )

        with self._lock:
            self._last_backend_result = response
            if response.get("ok") and response.get("result") == "uploaded":
                self._cbf_uploaded = True
                self.dbf_manager.set_qbf_enabled(False)

        self._debug(
            f"CBF upload result={response.get('result')} "
            f"message={response.get('message')}"
        )
        if self._cbf_uploaded:
            self._debug("CBF uploaded successfully; QBF generation disabled")
        return response

    def query_backend_for_qbf(self, qbf: Optional[QBFState] = None) -> dict[str, Any]:
        with self._lock:
            if self._cbf_uploaded:
                response = {
                    "ok": False,
                    "result": "skipped",
                    "message": "CBF already uploaded; QBF query disabled",
                }
                self._last_backend_result = response
                return response

        if qbf is None:
            qbf = self.dbf_manager.build_qbf(force=True)

        if qbf is None:
            response = {
                "ok": False,
                "result": "skipped",
                "message": "QBF not available",
            }
            with self._lock:
                self._last_backend_result = response
            return response

        response = query_qbf(
            server_ip=self.config.server_ip,
            server_port=self.config.server_port,
            node_id=self.config.node_id,
            qbf_bytes=qbf.bloom.to_bytes(),
            size_bytes=self.config.filter_size_bytes,
            hash_count=self.config.hash_count,
        )

        with self._lock:
            self._last_backend_result = response

        self._debug(
            f"QBF query result={response.get('result')} "
            f"message={response.get('message')}"
        )
        return response

    def get_dbfs(self) -> list[DBFState]:
        return self.dbf_manager.get_dbfs()

    def get_last_qbf(self) -> Optional[QBFState]:
        return self.dbf_manager.get_last_qbf()

    def get_last_backend_result(self) -> Optional[dict[str, Any]]:
        with self._lock:
            return self._last_backend_result

    def _debug(self, message: str) -> None:
        if self.config.debug:
            print(f"[{self.config.node_id}] {message}")


def _validate_assignment_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.k < MIN_K:
        parser.error(f"k must be >= {MIN_K}")
    if args.n < MIN_N:
        parser.error(f"n must be >= {MIN_N}")
    if args.k >= args.n:
        parser.error("k must be < n")
    if args.server_port < 1 or args.server_port > 65535:
        parser.error("server_port must be in range 1..65535")
    if args.bind_port < 1 or args.bind_port > 65535:
        parser.error("bind_port must be in range 1..65535")
    if args.target_port < 1 or args.target_port > 65535:
        parser.error("target_port must be in range 1..65535")
    if args.positive_after is not None and args.positive_after <= 0:
        parser.error("--positive-after must be positive")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY frontend node (Tasks 1-10 core).")
    parser.add_argument("t", type=int, choices=VALID_T_VALUES, help="EphID rotation interval in seconds")
    parser.add_argument("k", type=int, help="Shamir reconstruction threshold")
    parser.add_argument("n", type=int, help="Number of shares")
    parser.add_argument("p", type=int, choices=VALID_P_VALUES, help="Receive-side drop probability in percent")
    parser.add_argument("server_ip", nargs="?", default=DEFAULT_SERVER_IP)
    parser.add_argument("server_port", nargs="?", type=int, default=DEFAULT_SERVER_PORT)

    parser.add_argument("--node-id", default=None)
    parser.add_argument("--bind-ip", default=DEFAULT_UDP_BIND_IP)
    parser.add_argument("--bind-port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("--target-ip", default=DEFAULT_UDP_BROADCAST_IP)
    parser.add_argument("--target-port", type=int, default=DEFAULT_UDP_PORT)

    parser.add_argument("--positive-after", type=float, default=None)
    parser.add_argument("--no-backend-query", action="store_true")
    parser.add_argument("--no-interactive", action="store_true")
    parser.add_argument("--quiet", action="store_true")

    args = parser.parse_args()
    _validate_assignment_args(parser, args)
    return args


def main() -> None:
    args = parse_args()

    node_id = args.node_id or f"node-{uuid.uuid4().hex[:8]}"
    config = DimyNodeConfig(
        node_id=node_id,
        t=args.t,
        k=args.k,
        n=args.n,
        p=args.p,
        server_ip=args.server_ip,
        server_port=args.server_port,
        bind_ip=args.bind_ip,
        bind_port=args.bind_port,
        target_ip=args.target_ip,
        target_port=args.target_port,
        debug=not args.quiet,
        enable_udp=True,
        enable_qbf_scheduler=True,
        auto_query_backend=not args.no_backend_query,
        enable_interactive_commands=not args.no_interactive,
        positive_after=args.positive_after,
    )

    node = DimyNode(config=config)
    node.start()

    try:
        while node.is_running():
            time.sleep(1.0)
    except KeyboardInterrupt:
        print()
        node.stop()


if __name__ == "__main__":
    main()