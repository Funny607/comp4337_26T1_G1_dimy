from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass


PRIME = 257


@dataclass(frozen=True)
class ShamirShare:
    """
    One Shamir share.

    index:
        The x-coordinate of the share, in range [1, n].
    value:
        Packed bytes of all y-values. Each field element is stored as
        2 bytes big-endian because values are in GF(257), i.e. 0..256.
    """
    index: int
    value: bytes


def _validate_k_n(k: int, n: int) -> None:
    if not isinstance(k, int) or not isinstance(n, int):
        raise TypeError("k and n must be integers")
    if k < 2:
        raise ValueError("k must be at least 2")
    if n < 2:
        raise ValueError("n must be at least 2")
    if k > n:
        raise ValueError("k must be <= n")
    if n >= PRIME:
        raise ValueError(f"n must be < {PRIME} for GF({PRIME})")


def _pack_field_elements(elements: list[int]) -> bytes:
    """
    Pack a list of GF(257) elements into bytes, 2 bytes per element.
    """
    out = bytearray()
    for elem in elements:
        if not (0 <= elem < PRIME):
            raise ValueError(f"Field element out of range: {elem}")
        out.extend(elem.to_bytes(2, byteorder="big"))
    return bytes(out)


def _unpack_field_elements(data: bytes) -> list[int]:
    """
    Unpack bytes into a list of GF(257) elements, assuming 2 bytes per element.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)
    if len(data) % 2 != 0:
        raise ValueError("Packed share value length must be even")

    elems = []
    for i in range(0, len(data), 2):
        elem = int.from_bytes(data[i:i + 2], byteorder="big")
        if not (0 <= elem < PRIME):
            raise ValueError(f"Decoded field element out of range: {elem}")
        elems.append(elem)
    return elems


def _eval_polynomial(coeffs: list[int], x: int) -> int:
    """
    Evaluate polynomial at x over GF(257) using Horner's method.

    coeffs[0] is the constant term.
    """
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % PRIME
    return result


def _mod_inverse(value: int) -> int:
    """
    Multiplicative inverse in GF(257).
    """
    value %= PRIME
    if value == 0:
        raise ZeroDivisionError("No inverse for 0 in finite field")
    return pow(value, PRIME - 2, PRIME)


def _lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    """
    Reconstruct f(0) from given (x, y) points over GF(257).
    """
    if len(points) == 0:
        raise ValueError("At least one point is required")

    xs = [x for x, _ in points]
    if len(xs) != len(set(xs)):
        raise ValueError("Duplicate share indices are not allowed")

    total = 0
    for i, (x_i, y_i) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (x_j, _) in enumerate(points):
            if i == j:
                continue
            numerator = (numerator * (-x_j)) % PRIME
            denominator = (denominator * (x_i - x_j)) % PRIME

        basis_at_zero = (numerator * _mod_inverse(denominator)) % PRIME
        total = (total + y_i * basis_at_zero) % PRIME

    return total


def split_secret(secret: bytes, k: int, n: int) -> list[ShamirShare]:
    """
    Split a secret into n shares such that any k shares can reconstruct it.

    Implementation detail:
    - Each input byte becomes the constant term of one polynomial.
    - Random coefficients are sampled independently for each byte position.
    - Shares are returned with x-coordinates 1..n.

    Args:
        secret: arbitrary bytes, typically the 32-byte EphID
        k: threshold
        n: total number of shares

    Returns:
        list[ShamirShare] of length n
    """
    _validate_k_n(k, n)

    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes-like")
    secret = bytes(secret)
    if len(secret) == 0:
        raise ValueError("secret must not be empty")

    share_columns: dict[int, list[int]] = {x: [] for x in range(1, n + 1)}

    for secret_byte in secret:
        coeffs = [secret_byte] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
        for x in range(1, n + 1):
            y = _eval_polynomial(coeffs, x)
            share_columns[x].append(y)

    shares = []
    for x in range(1, n + 1):
        shares.append(
            ShamirShare(
                index=x,
                value=_pack_field_elements(share_columns[x]),
            )
        )
    return shares


def combine_shares(shares: list[ShamirShare], k: int) -> bytes:
    """
    Reconstruct the original secret from at least k shares.

    Args:
        shares: list of shares; may contain more than k shares
        k: threshold

    Returns:
        original secret bytes
    """
    if not isinstance(shares, list):
        raise TypeError("shares must be a list")
    if len(shares) < k:
        raise ValueError(f"Need at least {k} shares to reconstruct, got {len(shares)}")
    if k < 2:
        raise ValueError("k must be at least 2")

    selected = shares[:k]

    indices = [share.index for share in selected]
    if len(indices) != len(set(indices)):
        raise ValueError("Duplicate share indices are not allowed")

    unpacked = []
    expected_len = None
    for share in selected:
        if not isinstance(share, ShamirShare):
            raise TypeError("All items in shares must be ShamirShare instances")
        if not isinstance(share.index, int):
            raise TypeError("Share index must be an integer")
        if share.index <= 0 or share.index >= PRIME:
            raise ValueError(f"Share index must be in range 1..{PRIME - 1}")

        elems = _unpack_field_elements(share.value)
        if expected_len is None:
            expected_len = len(elems)
        elif len(elems) != expected_len:
            raise ValueError("All shares must encode the same number of field elements")
        unpacked.append((share.index, elems))

    if expected_len is None or expected_len == 0:
        raise ValueError("Share payload must not be empty")

    recovered = bytearray()
    for byte_pos in range(expected_len):
        points = [(share_index, elems[byte_pos]) for share_index, elems in unpacked]
        secret_elem = _lagrange_interpolate_at_zero(points)

        if not (0 <= secret_elem <= 255):
            raise ValueError(
                f"Reconstructed byte out of byte range at position {byte_pos}: {secret_elem}"
            )
        recovered.append(secret_elem)

    return bytes(recovered)


def serialize_share(share: ShamirShare) -> str:
    """
    Convert a share into a compact transport-safe string.

    Format:
        "<index>:<base64url(value)>"
    """
    if not isinstance(share, ShamirShare):
        raise TypeError("share must be a ShamirShare")
    encoded_value = base64.urlsafe_b64encode(share.value).decode("ascii")
    return f"{share.index}:{encoded_value}"


def deserialize_share(text: str) -> ShamirShare:
    """
    Parse a serialized share string produced by serialize_share().
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    try:
        index_text, encoded_value = text.split(":", 1)
    except ValueError as exc:
        raise ValueError("Serialized share must have format '<index>:<base64>'") from exc

    try:
        index = int(index_text)
    except ValueError as exc:
        raise ValueError("Share index must be an integer") from exc

    try:
        value = base64.urlsafe_b64decode(encoded_value.encode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid base64 share payload") from exc

    if len(value) == 0:
        raise ValueError("Share payload must not be empty")

    _ = _unpack_field_elements(value)

    return ShamirShare(index=index, value=value)

