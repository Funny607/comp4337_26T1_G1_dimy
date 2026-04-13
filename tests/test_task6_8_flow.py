from __future__ import annotations

from src.Dimy import DimyNode, DimyNodeConfig
from src.dbf_manager import DBFManager


def _make_node(node_id: str, dbf_manager: DBFManager, encounter_store: list[tuple[bytes, dict]]) -> DimyNode:
    config = DimyNodeConfig(
        node_id=node_id,
        t=15,
        k=3,
        n=5,
        p=0,
        debug=False,
        enable_udp=False,
        enable_qbf_scheduler=False,
    )
    return DimyNode(
        config=config,
        dbf_manager=dbf_manager,
        encounter_handler=lambda encid, meta: encounter_store.append((encid, meta)),
    )


def test_encounter_is_inserted_into_dbf_after_reconstruction() -> None:
    now = [1000.0]
    alice_store: list[tuple[bytes, dict]] = []
    bob_store: list[tuple[bytes, dict]] = []

    alice_dbf = DBFManager(t=15, time_fn=lambda: now[0])
    bob_dbf = DBFManager(t=15, time_fn=lambda: now[0])

    alice = _make_node("alice", alice_dbf, alice_store)
    bob = _make_node("bob", bob_dbf, bob_store)

    epoch_id = 12345
    alice_state = alice.ensure_epoch(epoch_id)
    bob_state = bob.ensure_epoch(epoch_id)

    for share in alice_state.shares[:3]:
        bob.handle_udp_packet(alice.build_share_packet(alice_state, share), ("127.0.0.1", 40001))

    for share in bob_state.shares[:3]:
        alice.handle_udp_packet(bob.build_share_packet(bob_state, share), ("127.0.0.1", 40002))

    assert len(alice_store) == 1
    assert len(bob_store) == 1

    alice_encid, _ = alice_store[0]
    bob_encid, _ = bob_store[0]

    assert alice_dbf.get_dbfs()[0].encounter_count == 1
    assert bob_dbf.get_dbfs()[0].encounter_count == 1
    assert alice_dbf.get_dbfs()[0].bloom.contains(alice_encid) is True
    assert bob_dbf.get_dbfs()[0].bloom.contains(bob_encid) is True


def test_qbf_contains_encounters_from_multiple_dbfs() -> None:
    now = [0.0]
    encounter_store: list[tuple[bytes, dict]] = []

    manager = DBFManager(t=15, time_fn=lambda: now[0])
    node = _make_node("alice", manager, encounter_store)

    first_encid = b"\x01" * 32
    second_encid = b"\x02" * 32

    node._store_encounter_in_dbf(first_encid)
    now[0] += 90.0
    node._store_encounter_in_dbf(second_encid)

    qbf = manager.build_qbf(force=True)
    assert qbf is not None
    assert qbf.dbf_count == 2
    assert qbf.bloom.contains(first_encid) is True
    assert qbf.bloom.contains(second_encid) is True
