import pytest

from qcrypto_toolkit.qch_kem import QCHKEM, QCHState, QKDKeyBuffer, QRNGHealth


def test_qch_handshake_uses_qkd_when_available():
    trace = QCHKEM().establish(QKDKeyBuffer.seeded(64), qkd_rate_bps=10000, qber=0.01)

    assert trace.server_confirmed
    assert trace.client_confirmed
    assert trace.qkd_key_bytes > 0
    assert len(trace.session_key) == 32
    assert trace.state in {QCHState.NORMAL, QCHState.RECOVERY}


def test_qch_falls_back_to_strongest_profile_without_qkd():
    trace = QCHKEM().establish(QKDKeyBuffer(), qkd_rate_bps=0, qber=0.0)

    assert trace.server_confirmed
    assert trace.client_confirmed
    assert trace.qkd_key_bytes == 0
    assert trace.state == QCHState.FALLBACK
    assert trace.pqc_profile == "ML-KEM-1024"


def test_qch_trace_contains_audit_and_safe_json_by_default():
    trace = QCHKEM().establish(QKDKeyBuffer.seeded(64), qkd_rate_bps=10000, qber=0.01)
    output = trace.to_jsonable()

    assert "session_key_hex" not in output
    assert output["qkd"]["protocol"] == "BB84"
    assert output["qrng"]["healthy"] is True
    assert output["security_margin_bits"] >= 128
    assert any(event["code"] == "hybrid_key" for event in output["audit_events"])


def test_qch_qrng_failure_forces_fallback_audit():
    trace = QCHKEM().establish(
        QKDKeyBuffer.seeded(64),
        qkd_rate_bps=10000,
        qber=0.01,
        qrng_health=QRNGHealth(min_entropy_per_bit=0.8),
    )

    assert trace.state == QCHState.FALLBACK
    assert trace.pqc_profile == "ML-KEM-1024"
    assert any(event.code == "qrng_health" for event in trace.audit_events)


def test_qch_rejects_invalid_qber():
    with pytest.raises(ValueError, match="qber must be between 0 and 1"):
        QCHKEM().establish(QKDKeyBuffer.seeded(32), qkd_rate_bps=1000, qber=1.5)
