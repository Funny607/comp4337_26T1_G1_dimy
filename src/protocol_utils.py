from __future__ import annotations

from typing import Any


PROTOCOL_VERSION = 1

SHARE_PACKET_TYPE = "share"
UPLOAD_CBF_REQUEST_TYPE = "upload_cbf"
QUERY_QBF_REQUEST_TYPE = "query_qbf"


def make_share_packet(
    *,
    sender_id: str,
    epoch_id: int,
    ephid_hash: str,
    k: int,
    n: int,
    serialized_share: str,
    timestamp: float,
) -> dict[str, Any]:
    return {
        "type": SHARE_PACKET_TYPE,
        "version": PROTOCOL_VERSION,
        "sender_id": sender_id,
        "epoch_id": epoch_id,
        "ephid_hash": ephid_hash,
        "k": k,
        "n": n,
        "share": serialized_share,
        "timestamp": timestamp,
    }