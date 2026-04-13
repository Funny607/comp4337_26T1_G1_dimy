from __future__ import annotations

import itertools

import pytest

from src.shamir_utils import (
    PRIME,
    ShamirShare,
    combine_shares,
    deserialize_share,
    serialize_share,
    split_secret,
)


def test_split_secret_returns_n_shares() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    shares = split_secret(secret, k=3, n=5)

    assert len(shares) == 5
    assert all(isinstance(share, ShamirShare) for share in shares)
    assert [share.index for share in shares] == [1, 2, 3, 4, 5]


def test_each_share_has_expected_encoded_length() -> None:
    secret = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    shares = split_secret(secret, k=3, n=5)

    for share in shares:
        assert len(share.value) == len(secret) * 2


def test_any_k_shares_can_reconstruct_secret() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    k = 3
    n = 5
    shares = split_secret(secret, k=k, n=n)

    for subset in itertools.combinations(shares, k):
        recovered = combine_shares(list(subset), k=k)
        assert recovered == secret


def test_more_than_k_shares_still_reconstructs() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    shares = split_secret(secret, k=3, n=5)

    recovered = combine_shares(shares[:4], k=3)
    assert recovered == secret


def test_combine_shares_rejects_too_few_shares() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    shares = split_secret(secret, k=3, n=5)

    with pytest.raises(ValueError, match="at least 3 shares"):
        combine_shares(shares[:2], k=3)


def test_combine_shares_rejects_duplicate_indices() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    shares = split_secret(secret, k=3, n=5)

    duplicated = [shares[0], shares[0], shares[1]]
    with pytest.raises(ValueError, match="Duplicate share indices"):
        combine_shares(duplicated, k=3)


def test_split_secret_rejects_empty_secret() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        split_secret(b"", k=3, n=5)


def test_split_secret_rejects_invalid_thresholds() -> None:
    secret = b"abc"

    with pytest.raises(ValueError, match="at least 2"):
        split_secret(secret, k=1, n=5)

    with pytest.raises(ValueError, match="k must be <= n"):
        split_secret(secret, k=6, n=5)

    with pytest.raises(ValueError, match=f"n must be < {PRIME}"):
        split_secret(secret, k=3, n=PRIME)


def test_serialize_and_deserialize_share_round_trip() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    share = split_secret(secret, k=3, n=5)[0]

    text = serialize_share(share)
    parsed = deserialize_share(text)

    assert parsed == share


def test_deserialize_share_rejects_bad_format() -> None:
    with pytest.raises(ValueError, match="format"):
        deserialize_share("not-a-valid-share-string")


def test_deserialize_share_rejects_bad_base64() -> None:
    with pytest.raises(ValueError, match="Invalid base64"):
        deserialize_share("1:%%%notbase64%%%")


def test_deserialize_share_rejects_empty_payload() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        deserialize_share("1:")


def test_combine_shares_rejects_mismatched_share_lengths() -> None:
    share1 = ShamirShare(index=1, value=(1).to_bytes(2, "big") * 4)
    share2 = ShamirShare(index=2, value=(2).to_bytes(2, "big") * 3)
    share3 = ShamirShare(index=3, value=(3).to_bytes(2, "big") * 4)

    with pytest.raises(ValueError, match="same number of field elements"):
        combine_shares([share1, share2, share3], k=3)


def test_reconstructed_secret_matches_original_random_like_input() -> None:
    secret = bytes(range(32))
    shares = split_secret(secret, k=4, n=6)

    recovered = combine_shares([shares[1], shares[3], shares[4], shares[5]], k=4)
    assert recovered == secret
