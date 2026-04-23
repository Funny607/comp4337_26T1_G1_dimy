from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Callable, Optional


DebugHook = Optional[Callable[[str], None]]


@dataclass
class BloomFilter:
    size_bytes: int = 100 * 1024
    hash_count: int = 3
    bits: bytearray = field(init=False)

    def __post_init__(self) -> None:
        if self.size_bytes <= 0:
            raise ValueError("size_bytes must be positive")
        if self.hash_count <= 0:
            raise ValueError("hash_count must be positive")
        self.bits = bytearray(self.size_bytes)

    @property
    def bit_size(self) -> int:
        return self.size_bytes * 8

    def _hash_indices(self, item: bytes) -> list[int]:
        if not isinstance(item, (bytes, bytearray)):
            raise TypeError("Bloom filter item must be bytes-like")
        item = bytes(item)

        indices: list[int] = []
        for i in range(self.hash_count):
            digest = sha256(i.to_bytes(1, "big") + item).digest()
            index = int.from_bytes(digest[:8], "big") % self.bit_size
            indices.append(index)
        return indices

    def add(self, item: bytes) -> None:
        for index in self._hash_indices(item):
            byte_index = index // 8
            bit_offset = index % 8
            self.bits[byte_index] |= 1 << bit_offset

    def contains(self, item: bytes) -> bool:
        for index in self._hash_indices(item):
            byte_index = index // 8
            bit_offset = index % 8
            if (self.bits[byte_index] & (1 << bit_offset)) == 0:
                return False
        return True

    def union_inplace(self, other: "BloomFilter") -> None:
        if self.size_bytes != other.size_bytes or self.hash_count != other.hash_count:
            raise ValueError("Bloom filters must have the same size and hash_count")
        for i in range(self.size_bytes):
            self.bits[i] |= other.bits[i]

    def copy(self) -> "BloomFilter":
        cloned = BloomFilter(size_bytes=self.size_bytes, hash_count=self.hash_count)
        cloned.bits[:] = self.bits
        return cloned

    def to_bytes(self) -> bytes:
        return bytes(self.bits)

    def set_bit_count(self) -> int:
        return sum(byte.bit_count() for byte in self.bits)


@dataclass
class DBFState:
    window_id: int
    created_at: float
    bloom: BloomFilter
    encounter_count: int = 0


@dataclass
class QBFState:
    period_id: int
    created_at: float
    bloom: BloomFilter
    source_window_ids: list[int]
    dbf_count: int
    set_bits: int


class DBFManager:
    """
    Task 6-8 scheduler and storage manager.

    Timing:
    - DBF rotation period = t * 6 seconds
    - QBF generation period = t * 6 * 6 seconds
    - Retention window = same as QBF period
    """

    def __init__(
        self,
        t: int,
        *,
        max_dbfs: int = 6,
        filter_size_bytes: int = 100 * 1024,
        hash_count: int = 3,
        time_fn: Callable[[], float] = time.time,
        debug_hook: DebugHook = None,
    ) -> None:
        if t <= 0:
            raise ValueError("t must be positive")
        if max_dbfs <= 0:
            raise ValueError("max_dbfs must be positive")

        self.t = t
        self.max_dbfs = max_dbfs
        self.filter_size_bytes = filter_size_bytes
        self.hash_count = hash_count
        self.time_fn = time_fn
        self.debug_hook = debug_hook

        self.dbf_period_seconds = t * 6
        self.qbf_period_seconds = t * 6 * 6
        self.retention_seconds = self.qbf_period_seconds

        self._lock = threading.RLock()
        self._dbfs: dict[int, DBFState] = {}
        self._last_qbf: Optional[QBFState] = None
        self._qbf_enabled = True

    def _debug(self, message: str) -> None:
        if self.debug_hook is not None:
            self.debug_hook(message)

    def current_dbf_window_id(self, now: Optional[float] = None) -> int:
        now = self.time_fn() if now is None else now
        return int(now // self.dbf_period_seconds)

    def current_qbf_period_id(self, now: Optional[float] = None) -> int:
        now = self.time_fn() if now is None else now
        return int(now // self.qbf_period_seconds)

    def ensure_current_dbf(self, now: Optional[float] = None) -> DBFState:
        now = self.time_fn() if now is None else now
        window_id = self.current_dbf_window_id(now)

        with self._lock:
            existing = self._dbfs.get(window_id)
            if existing is not None:
                return existing

            dbf = DBFState(
                window_id=window_id,
                created_at=now,
                bloom=BloomFilter(
                    size_bytes=self.filter_size_bytes,
                    hash_count=self.hash_count,
                ),
            )
            self._dbfs[window_id] = dbf
            self._prune_locked(now)

        self._debug(f"new DBF created window={window_id}")
        return dbf

    def rotate_if_needed(self, now: Optional[float] = None) -> DBFState:
        now = self.time_fn() if now is None else now
        dbf = self.ensure_current_dbf(now)

        with self._lock:
            self._prune_locked(now)

        return dbf

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.retention_seconds

        stale_by_time = [
            window_id
            for window_id, dbf in self._dbfs.items()
            if dbf.created_at < cutoff
        ]
        for window_id in stale_by_time:
            self._dbfs.pop(window_id, None)

        ordered_ids = sorted(self._dbfs.keys())
        while len(ordered_ids) > self.max_dbfs:
            oldest = ordered_ids.pop(0)
            self._dbfs.pop(oldest, None)

    def add_encounter(self, encid: bytes, now: Optional[float] = None) -> DBFState:
        if not isinstance(encid, (bytes, bytearray)):
            raise TypeError("encid must be bytes-like")
        encid = bytes(encid)

        now = self.time_fn() if now is None else now
        with self._lock:
            dbf = self.ensure_current_dbf(now)
            dbf.bloom.add(encid)
            dbf.encounter_count += 1
            set_bits = dbf.bloom.set_bit_count()

        self._debug(
            f"DBF add window={dbf.window_id} "
            f"encounters={dbf.encounter_count} set_bits={set_bits}"
        )
        return dbf

    def get_dbfs(self) -> list[DBFState]:
        with self._lock:
            return [self._dbfs[key] for key in sorted(self._dbfs.keys())]

    def get_last_qbf(self) -> Optional[QBFState]:
        with self._lock:
            return self._last_qbf

    def set_qbf_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._qbf_enabled = enabled

    def build_qbf(self, now: Optional[float] = None, *, force: bool = False) -> Optional[QBFState]:
        now = self.time_fn() if now is None else now
        period_id = self.current_qbf_period_id(now)

        with self._lock:
            if not self._qbf_enabled:
                return None

            if not force and self._last_qbf is not None and self._last_qbf.period_id == period_id:
                return self._last_qbf

            self.rotate_if_needed(now)

            qbf = BloomFilter(
                size_bytes=self.filter_size_bytes,
                hash_count=self.hash_count,
            )
            source_ids: list[int] = []

            for dbf in self.get_dbfs():
                qbf.union_inplace(dbf.bloom)
                source_ids.append(dbf.window_id)

            state = QBFState(
                period_id=period_id,
                created_at=now,
                bloom=qbf,
                source_window_ids=source_ids,
                dbf_count=len(source_ids),
                set_bits=qbf.set_bit_count(),
            )
            self._last_qbf = state

        self._debug(
            f"QBF built period={state.period_id} "
            f"dbfs={state.dbf_count} set_bits={state.set_bits}"
        )
        return state

    def build_cbf(self, now: Optional[float] = None) -> BloomFilter:
        now = self.time_fn() if now is None else now
        self.rotate_if_needed(now)

        cbf = BloomFilter(
            size_bytes=self.filter_size_bytes,
            hash_count=self.hash_count,
        )
        for dbf in self.get_dbfs():
            cbf.union_inplace(dbf.bloom)
        return cbf

