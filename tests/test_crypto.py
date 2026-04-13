from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from src.crypto_utils import (
    derive_encounter_id,
    generate_ephid_keypair,
    hash_ephid,
    load_peer_public_key,
    public_key_bytes,
    short_hex,
    verify_ephid_hash,
)


def test_generate_ephid_keypair_returns_expected_shapes() -> None:
    local = generate_ephid_keypair()

    assert isinstance(local.private_key, x25519.X25519PrivateKey)
    assert isinstance(local.public_key_bytes, bytes)
    assert len(local.public_key_bytes) == 32

    assert isinstance(local.ephid_hash, str)
    assert len(local.ephid_hash) == 64
    assert local.ephid_hash == hash_ephid(local.public_key_bytes)


def test_verify_ephid_hash_accepts_correct_value() -> None:
    local = generate_ephid_keypair()

    assert verify_ephid_hash(local.public_key_bytes, local.ephid_hash) is True


def test_verify_ephid_hash_rejects_modified_ephid() -> None:
    local = generate_ephid_keypair()
    tampered = bytearray(local.public_key_bytes)
    tampered[0] ^= 0x01

    assert verify_ephid_hash(bytes(tampered), local.ephid_hash) is False


def test_load_peer_public_key_round_trip_serialization() -> None:
    local = generate_ephid_keypair()

    peer_public_key = load_peer_public_key(local.public_key_bytes)
    round_tripped = public_key_bytes(peer_public_key)

    assert round_tripped == local.public_key_bytes


def test_load_peer_public_key_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        load_peer_public_key(b"too-short")


def test_hash_ephid_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        hash_ephid(b"abc")


def test_short_hex_returns_prefix() -> None:
    data = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert short_hex(data, n=6) == "001122"


def test_short_hex_rejects_invalid_n() -> None:
    with pytest.raises(ValueError, match="positive"):
        short_hex(b"\x00\x01", n=0)


def test_derive_encounter_id_is_symmetric() -> None:
    alice = generate_ephid_keypair()
    bob = generate_ephid_keypair()

    encid_from_alice = derive_encounter_id(
        my_private_key=alice.private_key,
        peer_ephid_bytes=bob.public_key_bytes,
        my_ephid_hash=alice.ephid_hash,
        peer_ephid_hash=bob.ephid_hash,
    )

    encid_from_bob = derive_encounter_id(
        my_private_key=bob.private_key,
        peer_ephid_bytes=alice.public_key_bytes,
        my_ephid_hash=bob.ephid_hash,
        peer_ephid_hash=alice.ephid_hash,
    )

    assert isinstance(encid_from_alice, bytes)
    assert len(encid_from_alice) == 32
    assert encid_from_alice == encid_from_bob


def test_derive_encounter_id_changes_for_different_peer() -> None:
    alice = generate_ephid_keypair()
    bob = generate_ephid_keypair()
    charlie = generate_ephid_keypair()

    encid_ab = derive_encounter_id(
        my_private_key=alice.private_key,
        peer_ephid_bytes=bob.public_key_bytes,
        my_ephid_hash=alice.ephid_hash,
        peer_ephid_hash=bob.ephid_hash,
    )

    encid_ac = derive_encounter_id(
        my_private_key=alice.private_key,
        peer_ephid_bytes=charlie.public_key_bytes,
        my_ephid_hash=alice.ephid_hash,
        peer_ephid_hash=charlie.ephid_hash,
    )

    assert encid_ab != encid_ac


def test_derive_encounter_id_accepts_hash_bytes_or_hex_string() -> None:
    alice = generate_ephid_keypair()
    bob = generate_ephid_keypair()

    encid_hex = derive_encounter_id(
        my_private_key=alice.private_key,
        peer_ephid_bytes=bob.public_key_bytes,
        my_ephid_hash=alice.ephid_hash,
        peer_ephid_hash=bob.ephid_hash,
    )

    encid_bytes = derive_encounter_id(
        my_private_key=alice.private_key,
        peer_ephid_bytes=bob.public_key_bytes,
        my_ephid_hash=bytes.fromhex(alice.ephid_hash),
        peer_ephid_hash=bytes.fromhex(bob.ephid_hash),
    )

    assert encid_hex == encid_bytes


def test_derive_encounter_id_rejects_bad_hash_string() -> None:
    alice = generate_ephid_keypair()
    bob = generate_ephid_keypair()

    with pytest.raises(ValueError, match="valid hex"):
        derive_encounter_id(
            my_private_key=alice.private_key,
            peer_ephid_bytes=bob.public_key_bytes,
            my_ephid_hash="not-a-hex-hash",
            peer_ephid_hash=bob.ephid_hash,
        )
