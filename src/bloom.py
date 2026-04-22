from src.dbf_manager import BloomFilter

def to_bytes(bloom: BloomFilter) -> bytes:
    """Serialize to raw bytes."""
    return bloom.to_bytes()

def from_bytes(data: bytes, size_bytes: int = 100*1024, hash_count: int = 3) -> BloomFilter:
    """Deserialize from raw bytes."""
    bloom = BloomFilter(size_bytes=size_bytes, hash_count=hash_count)
    bloom.bits[:] = bytearray(data)
    return bloom

def to_base64(bloom: BloomFilter) -> str:
    """For network transport."""
    from src.network_tcp import encode_bloom_bytes
    return encode_bloom_bytes(bloom.to_bytes())

def from_base64(encoded: str) -> BloomFilter:
    """From network transport."""
    from src.network_tcp import decode_bloom_bytes
    data = decode_bloom_bytes(encoded)
    return from_bytes(data)