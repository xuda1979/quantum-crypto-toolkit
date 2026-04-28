from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field

from .crypto import constant_time_equal, hkdf, mac, random_bytes, shake256
from .validation import require_non_negative_float, require_probability


@dataclass(frozen=True)
class MLKEMProfile:
    name: str
    security_bits: int
    public_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int = 32


ML_KEM_PROFILES: dict[str, MLKEMProfile] = {
    "ML-KEM-512": MLKEMProfile("ML-KEM-512", 118, 800, 768),
    "ML-KEM-768": MLKEMProfile("ML-KEM-768", 180, 1184, 1088),
    "ML-KEM-1024": MLKEMProfile("ML-KEM-1024", 256, 1568, 1568),
}


class QCHState(str, enum.Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    FALLBACK = "FALLBACK"
    RECOVERY = "RECOVERY"


@dataclass(frozen=True)
class QKDMetrics:
    rate_bps: float
    qber: float
    available_key_bytes: int
    healthy: bool = True
    protocol: str = "BB84"
    channel_loss_db: float | None = None


@dataclass(frozen=True)
class QRNGHealth:
    source: str = "system-csprng"
    min_entropy_per_bit: float = 1.0
    repetition_count_passed: bool = True
    adaptive_proportion_passed: bool = True
    certification: str = "demo"

    @property
    def healthy(self) -> bool:
        return (
            self.min_entropy_per_bit >= 0.95
            and self.repetition_count_passed
            and self.adaptive_proportion_passed
        )


@dataclass(frozen=True)
class QCHAuditEvent:
    code: str
    message: str
    severity: str = "info"


@dataclass
class QKDKeyBuffer:
    material: bytearray = field(default_factory=bytearray)
    generation_rate_bps: float = 0.0
    consumption_rate_bps: float = 0.0

    @classmethod
    def seeded(cls, size: int = 4096) -> "QKDKeyBuffer":
        return cls(bytearray(random_bytes(size)))

    def add(self, data: bytes) -> None:
        self.material.extend(data)

    def take(self, length: int) -> bytes | None:
        if length < 0:
            raise ValueError("length must be non-negative")
        if len(self.material) < length:
            return None
        out = bytes(self.material[:length])
        del self.material[:length]
        return out

    def depletion_time_s(self) -> float:
        net = self.consumption_rate_bps - self.generation_rate_bps
        if net <= 0:
            return float("inf")
        return (len(self.material) * 8) / net


@dataclass
class SyncController:
    target_security_bits: int = 256
    smoothing_factor: float = 0.3
    qber_threshold: float = 0.11
    min_qkd_bytes: int = 16
    qkd_contribution_cap_bits: int = 128
    smoothed_rate_bps: float = 0.0
    current_profile: MLKEMProfile = field(default_factory=lambda: ML_KEM_PROFILES["ML-KEM-768"])
    state: QCHState = QCHState.NORMAL

    def update(self, metrics: QKDMetrics) -> MLKEMProfile:
        self.smoothed_rate_bps = (
            self.smoothing_factor * metrics.rate_bps
            + (1.0 - self.smoothing_factor) * self.smoothed_rate_bps
        )
        if not metrics.healthy or metrics.qber > self.qber_threshold or metrics.available_key_bytes == 0:
            self.state = QCHState.FALLBACK
        elif metrics.available_key_bytes < self.min_qkd_bytes:
            self.state = QCHState.DEGRADED
        elif self.state == QCHState.FALLBACK:
            self.state = QCHState.RECOVERY
        else:
            self.state = QCHState.NORMAL
        self.current_profile = self.select_profile(metrics.available_key_bytes)
        return self.current_profile

    def qkd_security_bits(self, available_key_bytes: int) -> int:
        if self.state == QCHState.FALLBACK:
            return 0
        return min(available_key_bytes * 8, self.qkd_contribution_cap_bits)

    def select_profile(self, available_key_bytes: int) -> MLKEMProfile:
        required = self.target_security_bits - self.qkd_security_bits(available_key_bytes)
        if self.state == QCHState.FALLBACK:
            return ML_KEM_PROFILES["ML-KEM-1024"]
        if required <= ML_KEM_PROFILES["ML-KEM-512"].security_bits:
            return ML_KEM_PROFILES["ML-KEM-512"]
        if required <= ML_KEM_PROFILES["ML-KEM-768"].security_bits:
            return ML_KEM_PROFILES["ML-KEM-768"]
        return ML_KEM_PROFILES["ML-KEM-1024"]


@dataclass(frozen=True)
class DemoPrivateKey:
    profile: MLKEMProfile
    seed: bytes


@dataclass(frozen=True)
class DemoPublicKey:
    profile: MLKEMProfile
    encoded: bytes


class DemoMLKEMAdapter:
    """Deterministic ML-KEM-shaped adapter for protocol testing.

    The object preserves the KeyGen/Encaps/Decaps contract and profile sizes,
    but it does not implement ML-KEM. Use a real FIPS 203 implementation for
    production deployments.
    """

    def keygen(self, profile: MLKEMProfile) -> tuple[DemoPublicKey, DemoPrivateKey]:
        seed = random_bytes(32)
        pk = shake256([b"DEMO-MLKEM-PK", profile.name.encode(), seed], profile.public_key_bytes)
        return DemoPublicKey(profile, pk), DemoPrivateKey(profile, seed)

    def encaps(self, public_key: DemoPublicKey) -> tuple[bytes, bytes]:
        nonce = random_bytes(32)
        ciphertext = shake256(
            [b"DEMO-MLKEM-CT", public_key.profile.name.encode(), public_key.encoded, nonce],
            public_key.profile.ciphertext_bytes,
        )
        shared = shake256(
            [b"DEMO-MLKEM-SS", public_key.profile.name.encode(), public_key.encoded, ciphertext],
            public_key.profile.shared_secret_bytes,
        )
        return ciphertext, shared

    def decaps(self, private_key: DemoPrivateKey, public_key: DemoPublicKey, ciphertext: bytes) -> bytes:
        if private_key.profile != public_key.profile:
            raise ValueError("profile mismatch")
        return shake256(
            [b"DEMO-MLKEM-SS", public_key.profile.name.encode(), public_key.encoded, ciphertext],
            public_key.profile.shared_secret_bytes,
        )


@dataclass(frozen=True)
class QCHHandshakeTrace:
    state: QCHState
    pqc_profile: str
    qkd_key_bytes: int
    session_key: bytes
    ciphertext: bytes
    server_confirmed: bool
    client_confirmed: bool
    qkd_metrics: QKDMetrics | None = None
    qrng_health: QRNGHealth | None = None
    security_margin_bits: int = 0
    bandwidth_bytes: int = 0
    audit_events: tuple[QCHAuditEvent, ...] = ()

    def to_jsonable(self, include_session_key: bool = False) -> dict:
        output = {
            "state": self.state.value,
            "pqc_profile": self.pqc_profile,
            "qkd_key_bytes": self.qkd_key_bytes,
            "ciphertext_bytes": len(self.ciphertext),
            "security_margin_bits": self.security_margin_bits,
            "bandwidth_bytes": self.bandwidth_bytes,
            "server_confirmed": self.server_confirmed,
            "client_confirmed": self.client_confirmed,
            "audit_events": [event.__dict__ for event in self.audit_events],
        }
        if include_session_key:
            output["session_key_hex"] = self.session_key.hex()
        if self.qkd_metrics is not None:
            output["qkd"] = {
                "protocol": self.qkd_metrics.protocol,
                "rate_bps": self.qkd_metrics.rate_bps,
                "qber": self.qkd_metrics.qber,
                "available_key_bytes": self.qkd_metrics.available_key_bytes,
                "healthy": self.qkd_metrics.healthy,
                "channel_loss_db": self.qkd_metrics.channel_loss_db,
            }
        if self.qrng_health is not None:
            output["qrng"] = {
                "source": self.qrng_health.source,
                "min_entropy_per_bit": self.qrng_health.min_entropy_per_bit,
                "healthy": self.qrng_health.healthy,
                "certification": self.qrng_health.certification,
            }
        return output


class QCHKEM:
    def __init__(
        self,
        controller: SyncController | None = None,
        kem: DemoMLKEMAdapter | None = None,
        output_key_bytes: int = 32,
    ) -> None:
        self.controller = controller or SyncController()
        self.kem = kem or DemoMLKEMAdapter()
        self.output_key_bytes = output_key_bytes

    def establish(
        self,
        qkd_buffer: QKDKeyBuffer,
        qkd_rate_bps: float = 0.0,
        qber: float = 0.0,
        *,
        qkd_protocol: str = "BB84",
        channel_loss_db: float | None = None,
        qrng_health: QRNGHealth | None = None,
    ) -> QCHHandshakeTrace:
        require_non_negative_float("qkd_rate_bps", qkd_rate_bps)
        require_probability("qber", qber)
        qrng_health = qrng_health or QRNGHealth()
        metrics = QKDMetrics(
            qkd_rate_bps,
            qber,
            len(qkd_buffer.material),
            healthy=qrng_health.healthy,
            protocol=qkd_protocol,
            channel_loss_db=channel_loss_db,
        )
        profile = self.controller.update(metrics)
        qkd_bytes_needed = 0 if self.controller.state == QCHState.FALLBACK else min(32, len(qkd_buffer.material))
        audit_events = self._audit(metrics, qrng_health, profile, qkd_bytes_needed)

        public_key, private_key = self.kem.keygen(profile)
        ciphertext, server_pqc_secret = self.kem.encaps(public_key)
        client_pqc_secret = self.kem.decaps(private_key, public_key, ciphertext)
        if not constant_time_equal(server_pqc_secret, client_pqc_secret):
            raise RuntimeError("PQC shared secret mismatch")

        qkd_material = qkd_buffer.take(qkd_bytes_needed) or b""
        context = b"QCH-KEM-v1|" + profile.name.encode() + b"|" + str(int(time.time())).encode()
        server_key = hkdf(ciphertext[:32], server_pqc_secret + qkd_material, context, self.output_key_bytes)
        client_key = hkdf(ciphertext[:32], client_pqc_secret + qkd_material, context, self.output_key_bytes)

        server_tag = mac(server_key, b"server_confirm", ciphertext)
        client_seen = constant_time_equal(server_tag, mac(client_key, b"server_confirm", ciphertext))
        client_tag = mac(client_key, b"client_confirm", ciphertext)
        server_seen = constant_time_equal(client_tag, mac(server_key, b"client_confirm", ciphertext))

        return QCHHandshakeTrace(
            state=self.controller.state,
            pqc_profile=profile.name,
            qkd_key_bytes=qkd_bytes_needed,
            session_key=client_key,
            ciphertext=ciphertext,
            server_confirmed=client_seen,
            client_confirmed=server_seen,
            qkd_metrics=metrics,
            qrng_health=qrng_health,
            security_margin_bits=profile.security_bits + self.controller.qkd_security_bits(qkd_bytes_needed),
            bandwidth_bytes=profile.public_key_bytes + len(ciphertext),
            audit_events=tuple(audit_events),
        )

    def _audit(
        self,
        metrics: QKDMetrics,
        qrng_health: QRNGHealth,
        profile: MLKEMProfile,
        qkd_bytes_needed: int,
    ) -> list[QCHAuditEvent]:
        events: list[QCHAuditEvent] = []
        if not qrng_health.healthy:
            events.append(QCHAuditEvent("qrng_health", "QRNG health checks failed; forcing conservative PQC selection.", "warning"))
        if metrics.qber > self.controller.qber_threshold:
            events.append(QCHAuditEvent("qkd_qber", "QKD QBER exceeds configured threshold; QKD material excluded.", "warning"))
        if self.controller.state == QCHState.FALLBACK:
            events.append(QCHAuditEvent("qkd_fallback", "QKD unavailable; using strongest configured PQC profile.", "warning"))
        elif self.controller.state == QCHState.DEGRADED:
            events.append(QCHAuditEvent("qkd_degraded", "QKD buffer below target; PQC profile escalated as needed.", "info"))
        if qkd_bytes_needed > 0:
            events.append(QCHAuditEvent("hybrid_key", f"Mixed {qkd_bytes_needed} QKD bytes into HKDF input."))
        events.append(QCHAuditEvent("pqc_profile", f"Selected {profile.name} for target {self.controller.target_security_bits}-bit policy."))
        return events
