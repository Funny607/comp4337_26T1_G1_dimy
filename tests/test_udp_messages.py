from __future__ import annotations

import socket
import threading
import time

import pytest

from src.network_udp import UDPShareTransport


def _free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_encode_and_decode_packet_round_trip() -> None:
    received = []

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=_free_udp_port(),
        target_ip="127.0.0.1",
        target_port=_free_udp_port(),
        drop_prob=0.0,
        on_packet=lambda packet, addr: received.append((packet, addr)),
    )

    packet = {
        "type": "share",
        "sender_id": "node1",
        "epoch_id": 123,
        "share": "2:AAEAAw==",
    }

    encoded = transport.encode_packet(packet)
    decoded = transport.decode_packet(encoded)

    assert isinstance(encoded, bytes)
    assert decoded == packet


def test_decode_packet_rejects_invalid_json() -> None:
    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=_free_udp_port(),
        target_ip="127.0.0.1",
        target_port=_free_udp_port(),
        drop_prob=0.0,
        on_packet=lambda packet, addr: None,
    )

    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        transport.decode_packet(b"{not valid json")


def test_send_and_receive_packet_locally() -> None:
    recv_port = _free_udp_port()
    received_packets: list[dict] = []
    event = threading.Event()

    def on_packet(packet: dict, addr: tuple[str, int]) -> None:
        received_packets.append(packet)
        event.set()

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=recv_port,
        target_ip="127.0.0.1",
        target_port=recv_port,
        drop_prob=0.0,
        on_packet=on_packet,
        node_id="receiver",
        ignore_self=False,
    )

    transport.start()
    try:
        packet = {
            "type": "share",
            "sender_id": "node1",
            "epoch_id": 456,
            "ephid_hash": "abc123",
            "share": "1:AAEAAw==",
        }
        transport.send_packet(packet)

        assert event.wait(timeout=1.5), "Timed out waiting for local UDP packet"
        assert len(received_packets) == 1
        assert received_packets[0] == packet
    finally:
        transport.stop()


def test_drop_probability_one_drops_everything() -> None:
    recv_port = _free_udp_port()
    event = threading.Event()

    def on_packet(packet: dict, addr: tuple[str, int]) -> None:
        event.set()

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=recv_port,
        target_ip="127.0.0.1",
        target_port=recv_port,
        drop_prob=1.0,
        on_packet=on_packet,
        node_id="receiver",
        ignore_self=False,
    )

    transport.start()
    try:
        transport.send_packet(
            {
                "type": "share",
                "sender_id": "node1",
                "epoch_id": 1,
                "share": "1:AAEAAw==",
            }
        )

        assert event.wait(timeout=0.5) is False
    finally:
        transport.stop()


def test_ignore_self_packet_by_sender_id() -> None:
    recv_port = _free_udp_port()
    event = threading.Event()

    def on_packet(packet: dict, addr: tuple[str, int]) -> None:
        event.set()

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=recv_port,
        target_ip="127.0.0.1",
        target_port=recv_port,
        drop_prob=0.0,
        on_packet=on_packet,
        node_id="node1",
        ignore_self=True,
    )

    transport.start()
    try:
        transport.send_packet(
            {
                "type": "share",
                "sender_id": "node1",
                "epoch_id": 99,
                "share": "2:AAEAAw==",
            }
        )

        assert event.wait(timeout=0.5) is False
    finally:
        transport.stop()


def test_non_dict_packet_rejected() -> None:
    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=_free_udp_port(),
        target_ip="127.0.0.1",
        target_port=_free_udp_port(),
        drop_prob=0.0,
        on_packet=lambda packet, addr: None,
    )

    with pytest.raises(TypeError, match="packet must be a dict"):
        transport.send_packet(["not", "a", "dict"])  # type: ignore[arg-type]


def test_send_before_start_rejected() -> None:
    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=_free_udp_port(),
        target_ip="127.0.0.1",
        target_port=_free_udp_port(),
        drop_prob=0.0,
        on_packet=lambda packet, addr: None,
    )

    with pytest.raises(RuntimeError, match="not running"):
        transport.send_packet({"type": "share"})


def test_start_twice_rejected() -> None:
    recv_port = _free_udp_port()

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=recv_port,
        target_ip="127.0.0.1",
        target_port=recv_port,
        drop_prob=0.0,
        on_packet=lambda packet, addr: None,
    )

    transport.start()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            transport.start()
    finally:
        transport.stop()


def test_stop_is_idempotent() -> None:
    recv_port = _free_udp_port()

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=recv_port,
        target_ip="127.0.0.1",
        target_port=recv_port,
        drop_prob=0.0,
        on_packet=lambda packet, addr: None,
    )

    transport.start()
    transport.stop()
    transport.stop()


def test_invalid_payload_received_is_ignored() -> None:
    recv_port = _free_udp_port()
    event = threading.Event()

    def on_packet(packet: dict, addr: tuple[str, int]) -> None:
        event.set()

    transport = UDPShareTransport(
        bind_ip="127.0.0.1",
        bind_port=recv_port,
        target_ip="127.0.0.1",
        target_port=recv_port,
        drop_prob=0.0,
        on_packet=on_packet,
        ignore_self=False,
    )

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    transport.start()
    try:
        raw_sock.sendto(b"not-json", ("127.0.0.1", recv_port))
        time.sleep(0.2)
        assert event.is_set() is False
    finally:
        raw_sock.close()
        transport.stop()
