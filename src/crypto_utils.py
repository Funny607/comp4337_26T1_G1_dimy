from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HashToken = Union[str, bytes]


@dataclass(frozen=True)
class LocalEphID:
    """
    Represents one local DIMY EphID epoch.

    Design choice:
    - EphID == X25519 public key bytes (32 bytes)
    - private_key is kept locally and never broadcast
    - ephid_hash is used to verify reconstructed EphIDs
    """
    private_key: x25519.X25519PrivateKey
    public_key_bytes: bytes
    ephid_hash: str


def short_hex(data: bytes, n: int = 6) -> str:
    """
    Return a short hex prefix for readable debug output.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    if n <= 0:
        raise ValueError("n must be positive")
    return bytes(data).hex()[:n]


def hash_ephid(ephid: bytes) -> str:
    """
    Hash a 32-byte EphID using SHA-256 and return a hex digest.
    """
    if not isinstance(ephid, (bytes, bytearray)):
        raise TypeError("ephid must be bytes-like")
    ephid = bytes(ephid)
    if len(ephid) != 32:
        raise ValueError(f"EphID must be exactly 32 bytes, got {len(ephid)}")
    return sha256(ephid).hexdigest()


def verify_ephid_hash(ephid: bytes, expected_hash: str) -> bool:
    """
    Verify that the given EphID matches the advertised hash.
    """
    if not isinstance(expected_hash, str):
        raise TypeError("expected_hash must be a hex string")
    return hash_ephid(ephid) == expected_hash.lower()


def generate_ephid_keypair() -> LocalEphID:
    """
    Generate a fresh local EphID keypair.

    Returns:
        LocalEphID where:
        - private_key is local-only
        - public_key_bytes is the 32-byte EphID to be split/broadcast
        - ephid_hash is the advertised verification hash
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return LocalEphID(
        private_key=private_key,
        public_key_bytes=public_key_bytes,
        ephid_hash=hash_ephid(public_key_bytes),
    )


def load_peer_public_key(ephid_bytes: bytes) -> x25519.X25519PublicKey:
    """
    Convert reconstructed 32-byte EphID bytes into an X25519 public key object.
    """
    if not isinstance(ephid_bytes, (bytes, bytearray)):
        raise TypeError("ephid_bytes must be bytes-like")
    ephid_bytes = bytes(ephid_bytes)
    if len(ephid_bytes) != 32:
        raise ValueError(
            f"Peer EphID/public key must be exactly 32 bytes, got {len(ephid_bytes)}"
        )
    try:
        return x25519.X25519PublicKey.from_public_bytes(ephid_bytes)
    except Exception as exc:
        raise ValueError("Invalid X25519 public key bytes") from exc


def public_key_bytes(public_key: x25519.X25519PublicKey) -> bytes:
    """
    Serialize an X25519 public key into raw 32-byte form.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _normalize_hash_token(token: HashToken) -> bytes:
    """
    Normalize either:
    - a hex digest string, or
    - raw bytes

    into bytes suitable for symmetric KDF context binding.
    """
    if isinstance(token, bytes):
        return token
    if isinstance(token, str):
        token = token.strip().lower()
        try:
            return bytes.fromhex(token)
        except ValueError as exc:
            raise ValueError("Hash string must be valid hex") from exc
    raise TypeError("hash token must be bytes or hex string")


def derive_encounter_id(
    my_private_key: x25519.X25519PrivateKey,
    peer_ephid_bytes: bytes,
    my_ephid_hash: HashToken,
    peer_ephid_hash: HashToken,
) -> bytes:
    """
    Derive a symmetric Encounter ID (EncID).

    Steps:
    1. Reconstruct peer X25519 public key from EphID bytes
    2. Compute DH shared secret
    3. Bind both EphID hashes symmetrically into the KDF context
    4. Produce a stable 32-byte EncID

    The ordering of the two hash tokens is normalized so both peers derive
    the same EncID regardless of caller perspective.
    """
    if not isinstance(my_private_key, x25519.X25519PrivateKey):
        raise TypeError("my_private_key must be an X25519PrivateKey")

    peer_public_key = load_peer_public_key(peer_ephid_bytes)
    shared_secret = my_private_key.exchange(peer_public_key)

    my_hash_bytes = _normalize_hash_token(my_ephid_hash)
    peer_hash_bytes = _normalize_hash_token(peer_ephid_hash)
    ordered_hashes = sorted([my_hash_bytes, peer_hash_bytes])

    info = b"DIMY-EncID-v1|" + ordered_hashes[0] + b"|" + ordered_hashes[1]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)
