from __future__ import annotations

import socket

from src.Dimy import DimyNode, DimyNodeConfig
from src.DimyServer import DimyServer, DimyServerConfig
from src.dbf_manager import BloomFilter, DBFManager
from src.network_tcp import (
    TCPBackendClient,
    decode_bloom_bytes,
    encode_bloom_bytes,
    make_query_qbf_request,
    make_upload_cbf_request,
)


def _free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_encode_and_decode_bloom_bytes_round_trip() -> None:
    payload = b"abc123" * 10
    encoded = encode_bloom_bytes(payload)
    decoded = decode_bloom_bytes(encoded)
    assert decoded == payload


def test_make_requests_include_required_fields() -> None:
    bloom = bytes(32)
    upload = make_upload_cbf_request(
        node_id="node1",
        bloom_bytes=bloom,
        size_bytes=32,
        hash_count=3,
        timestamp=1.0,
    )
    query = make_query_qbf_request(
        node_id="node2",
        bloom_bytes=bloom,
        size_bytes=32,
        hash_count=3,
        timestamp=2.0,
    )

    assert upload["type"] == "upload_cbf"
    assert query["type"] == "query_qbf"
    assert upload["size_bytes"] == 32
    assert query["hash_count"] == 3
    assert upload["node_id"] == "node1"
    assert query["node_id"] == "node2"


def test_tcp_server_upload_and_query_match_flow() -> None:
    port = _free_tcp_port()
    server = DimyServer(
        DimyServerConfig(
            bind_ip="127.0.0.1",
            bind_port=port,
            filter_size_bytes=64,
            hash_count=3,
            min_intersection_bits=3,
            debug=False,
        )
    )
    server.start()
    try:
        client = TCPBackendClient("127.0.0.1", port, debug=False)

        cbf = BloomFilter(size_bytes=64, hash_count=3)
        cbf.add(b"encounter-a")
        upload_result = client.upload_cbf(
            node_id="positive-node",
            cbf_bytes=cbf.to_bytes(),
            size_bytes=64,
            hash_count=3,
        )
        assert upload_result["ok"] is True
        assert upload_result["result"] == "uploaded"

        qbf = BloomFilter(size_bytes=64, hash_count=3)
        qbf.add(b"encounter-a")
        query_result = client.query_qbf(
            node_id="query-node",
            qbf_bytes=qbf.to_bytes(),
            size_bytes=64,
            hash_count=3,
        )
        assert query_result["ok"] is True
        assert query_result["result"] == "matched"
        assert query_result["matched_node_id"] == "positive-node"
    finally:
        server.stop()


def test_tcp_server_query_not_matched_for_empty_qbf() -> None:
    port = _free_tcp_port()
    server = DimyServer(
        DimyServerConfig(
            bind_ip="127.0.0.1",
            bind_port=port,
            filter_size_bytes=64,
            hash_count=3,
            min_intersection_bits=3,
            debug=False,
        )
    )
    server.start()
    try:
        client = TCPBackendClient("127.0.0.1", port, debug=False)

        cbf = BloomFilter(size_bytes=64, hash_count=3)
        cbf.add(b"encounter-a")
        client.upload_cbf(
            node_id="positive-node",
            cbf_bytes=cbf.to_bytes(),
            size_bytes=64,
            hash_count=3,
        )

        empty_qbf = BloomFilter(size_bytes=64, hash_count=3)
        query_result = client.query_qbf(
            node_id="query-node",
            qbf_bytes=empty_qbf.to_bytes(),
            size_bytes=64,
            hash_count=3,
        )
        assert query_result["ok"] is True
        assert query_result["result"] == "not_matched"
    finally:
        server.stop()


def test_tcp_server_rejects_size_mismatch_from_client_request() -> None:
    port = _free_tcp_port()
    server = DimyServer(
        DimyServerConfig(
            bind_ip="127.0.0.1",
            bind_port=port,
            filter_size_bytes=64,
            hash_count=3,
            debug=False,
        )
    )
    server.start()
    try:
        client = TCPBackendClient("127.0.0.1", port, debug=False)
        bad_request = make_upload_cbf_request(
            node_id="node1",
            bloom_bytes=bytes(16),
            size_bytes=16,
            hash_count=3,
        )
        response = client.send_request(bad_request)
        assert response["ok"] is False
        assert response["result"] == "error"
        assert "size_bytes" in response["message"]
    finally:
        server.stop()


def test_dimy_node_can_upload_cbf_and_query_backend() -> None:
    port = _free_tcp_port()
    server = DimyServer(
        DimyServerConfig(
            bind_ip="127.0.0.1",
            bind_port=port,
            filter_size_bytes=64,
            hash_count=3,
            min_intersection_bits=3,
            debug=False,
        )
    )
    server.start()
    try:
        positive_dbf = DBFManager(t=15, filter_size_bytes=64, hash_count=3)
        positive = DimyNode(
            DimyNodeConfig(
                node_id="positive",
                t=15,
                k=3,
                n=5,
                p=0,
                debug=False,
                enable_udp=False,
                enable_qbf_scheduler=False,
                enable_tcp_backend=True,
                server_ip="127.0.0.1",
                server_port=port,
                filter_size_bytes=64,
                hash_count=3,
            ),
            dbf_manager=positive_dbf,
        )
        positive._store_encounter_in_dbf(b"\x01" * 32)
        upload_result = positive.upload_current_cbf()
        assert upload_result["result"] == "uploaded"
        assert positive.dbf_manager.build_qbf(force=True) is None

        query_dbf = DBFManager(t=15, filter_size_bytes=64, hash_count=3)
        query_node = DimyNode(
            DimyNodeConfig(
                node_id="query",
                t=15,
                k=3,
                n=5,
                p=0,
                debug=False,
                enable_udp=False,
                enable_qbf_scheduler=False,
                enable_tcp_backend=True,
                server_ip="127.0.0.1",
                server_port=port,
                filter_size_bytes=64,
                hash_count=3,
            ),
            dbf_manager=query_dbf,
        )
        query_node._store_encounter_in_dbf(b"\x01" * 32)
        qbf = query_node.dbf_manager.build_qbf(force=True)
        assert qbf is not None
        query_result = query_node.query_backend_for_qbf(qbf)
        assert query_result["result"] == "matched"
    finally:
        server.stop()
