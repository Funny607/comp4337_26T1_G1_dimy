from __future__ import annotations

from src.dbf_manager import DBFManager


def test_add_encounter_goes_into_current_dbf() -> None:
    now = [1000.0]
    manager = DBFManager(t=15, time_fn=lambda: now[0])

    encid = b"encounter-a"
    dbf = manager.add_encounter(encid)

    assert dbf.encounter_count == 1
    assert dbf.bloom.contains(encid) is True
    assert len(manager.get_dbfs()) == 1


def test_multiple_encounters_same_window_stay_in_same_dbf() -> None:
    now = [1000.0]
    manager = DBFManager(t=15, time_fn=lambda: now[0])

    first = manager.add_encounter(b"enc-a")
    second = manager.add_encounter(b"enc-b")

    assert first.window_id == second.window_id
    assert second.encounter_count == 2
    assert len(manager.get_dbfs()) == 1


def test_new_dbf_created_every_t_times_6_seconds() -> None:
    now = [1000.0]
    manager = DBFManager(t=15, time_fn=lambda: now[0])  # DBF period = 90s

    first = manager.add_encounter(b"enc-a")
    now[0] += 90.0
    second = manager.add_encounter(b"enc-b")

    assert first.window_id != second.window_id
    assert len(manager.get_dbfs()) == 2


def test_at_most_six_dbfs_are_kept() -> None:
    now = [0.0]
    manager = DBFManager(t=15, time_fn=lambda: now[0], max_dbfs=6)

    for i in range(8):
        manager.add_encounter(f"enc-{i}".encode())
        now[0] += 90.0

    dbfs = manager.get_dbfs()
    assert len(dbfs) == 6
    assert [dbf.window_id for dbf in dbfs] == [2, 3, 4, 5, 6, 7]


def test_qbf_combines_all_available_dbfs() -> None:
    now = [0.0]
    manager = DBFManager(t=15, time_fn=lambda: now[0])

    a = b"enc-a"
    b = b"enc-b"

    manager.add_encounter(a)
    now[0] += 90.0
    manager.add_encounter(b)

    qbf = manager.build_qbf(force=True)
    assert qbf is not None
    assert qbf.dbf_count == 2
    assert qbf.bloom.contains(a) is True
    assert qbf.bloom.contains(b) is True


def test_qbf_is_cached_within_same_period() -> None:
    now = [0.0]
    manager = DBFManager(t=15, time_fn=lambda: now[0])  # QBF period = 540s

    manager.add_encounter(b"enc-a")
    qbf1 = manager.build_qbf()
    qbf2 = manager.build_qbf()

    assert qbf1 is qbf2

    now[0] += 540.0
    qbf3 = manager.build_qbf()
    assert qbf3 is not qbf1

