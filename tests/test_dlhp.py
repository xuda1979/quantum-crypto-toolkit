import pytest

from qcrypto_toolkit.dlhp import (
    DLHPSession,
    ReplayWindow,
    generate_schedule,
    generate_chaff_units,
    protect_payload,
    recover_payload,
    schedule_statistics,
)


MASTER = b"0123456789abcdef0123456789abcdef"


def test_schedule_enforces_adjacent_class_orthogonality():
    schedule = generate_schedule(MASTER, 100)
    stats = schedule_statistics(schedule)

    assert stats["orthogonality_violations"] == 0


def test_schedule_rejects_negative_count():
    with pytest.raises(ValueError, match="count must be non-negative"):
        generate_schedule(MASTER, -1)


def test_payload_roundtrip_with_threshold_shares():
    payload = "抗量子协议工具集".encode("utf-8")
    shares = protect_payload(payload, MASTER, k=3, n=5)

    recovered = recover_payload([shares[4], shares[1], shares[2]], MASTER, k=3)

    assert recovered == payload


def test_payload_recovery_requires_threshold():
    shares = protect_payload(b"secret", MASTER, k=3, n=5)

    with pytest.raises(ValueError):
        recover_payload(shares[:2], MASTER, k=3)


def test_dlhp_session_protects_units_statelessly_and_rejects_tampering():
    sender = DLHPSession(MASTER, session_id=b"session-1")
    receiver = DLHPSession(MASTER, session_id=b"session-1")

    unit = sender.protect_unit(7, b"packet payload")

    assert receiver.open_unit(unit) == b"packet payload"
    assert unit.header.algorithm_hint is None
    assert unit.header.is_decoy is False

    tampered = unit.with_ciphertext(unit.ciphertext[:-1] + bytes([unit.ciphertext[-1] ^ 1]))
    with pytest.raises(ValueError, match="authentication"):
        receiver.open_unit(tampered)


def test_replay_window_rejects_duplicate_sequences():
    sender = DLHPSession(MASTER, session_id=b"session-2")
    receiver = DLHPSession(MASTER, session_id=b"session-2", replay_window=ReplayWindow(size=8))
    unit = sender.protect_unit(1, b"one")

    assert receiver.open_unit(unit) == b"one"
    with pytest.raises(ValueError, match="replay"):
        receiver.open_unit(unit)


def test_chaff_units_are_valid_shape_and_discarded_by_receiver():
    sender = DLHPSession(MASTER, session_id=b"session-3")
    receiver = DLHPSession(MASTER, session_id=b"session-3")
    chaff = generate_chaff_units(sender, start_seq_id=50, count=3, payload_size=24)

    assert len(chaff) == 3
    assert all(unit.header.is_decoy for unit in chaff)
    assert [receiver.open_unit(unit) for unit in chaff] == [None, None, None]
