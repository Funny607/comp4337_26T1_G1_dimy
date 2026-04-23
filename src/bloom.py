from __future__ import annotations

import base64

from src.dbf_manager import BloomFilter


DEFAULT_SIZE_BYTES = 100 * 1024
DEFAULT_HASH_COUNT = 3


def to_bytes(bloom: BloomFilter) -> bytes:
    """Serialize a Bloom filter to raw bytes."""
    if not isinstance(bloom, BloomFilter):
        raise TypeError("bloom must be a BloomFilter")
    return bloom.to_bytes()


def from_bytes(
    data: bytes,
    size_bytes: int = DEFAULT_SIZE_BYTES,
    hash_count: int = DEFAULT_HASH_COUNT,
) -> BloomFilter:
    """Deserialize a Bloom filter from raw bytes with shape validation."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)
    if len(data) != size_bytes:
        raise ValueError(
            f"Bloom bytes length mismatch: expected {size_bytes}, got {len(data)}"
        )

    bloom = BloomFilter(size_bytes=size_bytes, hash_count=hash_count)
    bloom.bits[:] = data
    return bloom


def to_base64(bloom: BloomFilter) -> str:
    """Serialize a Bloom filter into ASCII base64 for network transport."""
    return base64.b64encode(to_bytes(bloom)).decode("ascii")


def from_base64(
    encoded: str,
    size_bytes: int = DEFAULT_SIZE_BYTES,
    hash_count: int = DEFAULT_HASH_COUNT,
) -> BloomFilter:
    """Deserialize a Bloom filter from ASCII base64."""
    if not isinstance(encoded, str):
        raise TypeError("encoded must be a string")
    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 bloom payload") from exc
    return from_bytes(data, size_bytes=size_bytes, hash_count=hash_count)
