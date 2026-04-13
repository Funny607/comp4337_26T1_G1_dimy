from __future__ import annotations

from src.Dimy import DimyNode, DimyNodeConfig


def _make_node(node_id: str, encounter_store: list[tuple[bytes, dict]]) -> DimyNode:
    config = DimyNodeConfig(
        node_id=node_id,
        t=15,
        k=3,
        n=5,
        p=0,
        debug=False,
        enable_udp=False,
    )
    return DimyNode(
        config=config,
        encounter_handler=lambda encid, meta: encounter_store.append((encid, meta)),
    )


def test_two_nodes_derive_same_encid_from_exchanged_shares() -> None:
    alice_hits: list[tuple[bytes, dict]] = []
    bob_hits: list[tuple[bytes, dict]] = []

    alice = _make_node("alice", alice_hits)
    bob = _make_node("bob", bob_hits)

    epoch_id = 123456
    alice_state = alice.ensure_epoch(epoch_id)
    bob_state = bob.ensure_epoch(epoch_id)

    # Bob receives 3 distinct shares from Alice
    for share in alice_state.shares[:3]:
        packet = alice.build_share_packet(alice_state, share)
        bob.handle_udp_packet(packet, ("127.0.0.1", 40001))

    # Alice receives 3 distinct shares from Bob
    for share in bob_state.shares[:3]:
        packet = bob.build_share_packet(bob_state, share)
        alice.handle_udp_packet(packet, ("127.0.0.1", 40002))

    assert len(alice_hits) == 1
    assert len(bob_hits) == 1

    alice_encid, alice_meta = alice_hits[0]
    bob_encid, bob_meta = bob_hits[0]

    assert alice_encid == bob_encid
    assert alice_meta["sender_id"] == "bob"
    assert bob_meta["sender_id"] == "alice"


def test_duplicate_share_does_not_count_twice() -> None:
    bob_hits: list[tuple[bytes, dict]] = []

    alice = _make_node("alice", [])
    bob = _make_node("bob", bob_hits)

    epoch_id = 777777
    alice_state = alice.ensure_epoch(epoch_id)
    bob.ensure_epoch(epoch_id)

    first = alice.build_share_packet(alice_state, alice_state.shares[0])
    second = alice.build_share_packet(alice_state, alice_state.shares[1])
    third = alice.build_share_packet(alice_state, alice_state.shares[2])

    # Send the first share twice; Bob should still only have 2 distinct shares after first+first+second
    bob.handle_udp_packet(first, ("127.0.0.1", 50001))
    bob.handle_udp_packet(first, ("127.0.0.1", 50001))
    bob.handle_udp_packet(second, ("127.0.0.1", 50001))

    assert len(bob_hits) == 0

    # Third distinct share should finally trigger reconstruction
    bob.handle_udp_packet(third, ("127.0.0.1", 50001))
    assert len(bob_hits) == 1


def test_hash_mismatch_prevents_encounter_derivation() -> None:
    bob_hits: list[tuple[bytes, dict]] = []

    alice = _make_node("alice", [])
    bob = _make_node("bob", bob_hits)

    epoch_id = 888888
    alice_state = alice.ensure_epoch(epoch_id)
    bob.ensure_epoch(epoch_id)

    for share in alice_state.shares[:3]:
        packet = alice.build_share_packet(alice_state, share)
        packet["ephid_hash"] = "0" * 64  # tampered advertised hash
        bob.handle_udp_packet(packet, ("127.0.0.1", 50002))

    assert len(bob_hits) == 0


def test_one_node_records_only_one_encounter_for_same_peer_epoch() -> None:
    bob_hits: list[tuple[bytes, dict]] = []

    alice = _make_node("alice", [])
    bob = _make_node("bob", bob_hits)

    epoch_id = 999999
    alice_state = alice.ensure_epoch(epoch_id)
    bob.ensure_epoch(epoch_id)

    # First successful reconstruction
    for share in alice_state.shares[:3]:
        packet = alice.build_share_packet(alice_state, share)
        bob.handle_udp_packet(packet, ("127.0.0.1", 50003))

    assert len(bob_hits) == 1

    # Even if more shares arrive later for the same sender/epoch/hash,
    # the same encounter should not be recorded again.
    for share in alice_state.shares[3:]:
        packet = alice.build_share_packet(alice_state, share)
        bob.handle_udp_packet(packet, ("127.0.0.1", 50003))

    assert len(bob_hits) == 1
