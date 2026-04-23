from __future__ import annotations

import pytest

from src.bloom import from_base64, from_bytes, to_base64, to_bytes
from src.dbf_manager import BloomFilter


def test_bloom_round_trip_bytes_preserves_bits() -> None:
    bloom = BloomFilter(size_bytes=64, hash_count=3)
    bloom.add(b"alpha")
    bloom.add(b"beta")

    raw = to_bytes(bloom)
    restored = from_bytes(raw, size_bytes=64, hash_count=3)

    assert restored.to_bytes() == raw
    assert restored.contains(b"alpha") is True
    assert restored.contains(b"beta") is True


def test_bloom_round_trip_base64_preserves_bits() -> None:
    bloom = BloomFilter(size_bytes=64, hash_count=3)
    bloom.add(b"gamma")

    encoded = to_base64(bloom)
    restored = from_base64(encoded, size_bytes=64, hash_count=3)

    assert restored.to_bytes() == bloom.to_bytes()
    assert restored.contains(b"gamma") is True


def test_from_bytes_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="length mismatch"):
        from_bytes(b"abc", size_bytes=64, hash_count=3)


def test_from_base64_rejects_invalid_payload() -> None:
    with pytest.raises(ValueError, match="Invalid base64"):
        from_base64("%%%not-base64%%%", size_bytes=64, hash_count=3)
