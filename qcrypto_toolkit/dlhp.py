from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from dataclasses import dataclass

from .crypto import constant_time_equal, hkdf_expand, mac, random_bytes, xor_bytes
from .validation import require_non_negative_int

PRIME = 257


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    algorithm_id: int
    hard_problem_class: str
    security_bits: int
    preferred_path: str


DEFAULT_LIBRARY = [
    AlgorithmProfile("ML-KEM-768", 1, "StructuredLattice", 128, "5G"),
    AlgorithmProfile("NTRU-HPS-677", 2, "NTRULattice", 128, "WiFi"),
    AlgorithmProfile("Classic-McEliece", 3, "GoppaCode", 128, "Satellite"),
    AlgorithmProfile("BIKE-L3", 4, "QCMDPC", 128, "WiFi"),
    AlgorithmProfile("FrodoKEM-976", 5, "UnstructuredLattice", 128, "5G"),
]


@dataclass(frozen=True)
class HopSelection:
    seq_id: int
    selection_counter: int
    algorithm: AlgorithmProfile
    packet_key: bytes
    retries: int


@dataclass(frozen=True)
class ProtectedShare:
    seq_id: int
    share_x: int
    algorithm_name: str
    hard_problem_class: str
    preferred_path: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_jsonable(self) -> dict:
        return {
            "seq_id": self.seq_id,
            "share_x": self.share_x,
            "algorithm_name": self.algorithm_name,
            "hard_problem_class": self.hard_problem_class,
            "preferred_path": self.preferred_path,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "tag": base64.b64encode(self.tag).decode("ascii"),
        }


@dataclass(frozen=True)
class ProtectedUnitHeader:
    session_id: bytes
    seq_id: int
    mode: str = "nano"
    algorithm_hint: str | None = None
    is_decoy: bool = False

    def associated_data(self) -> bytes:
        if self.seq_id < 0:
            raise ValueError("seq_id must be non-negative")
        return b"|".join(
            [
                b"DLHP-UNIT-v1",
                self.session_id,
                self.seq_id.to_bytes(8, "big"),
                self.mode.encode("ascii"),
                b"1" if self.is_decoy else b"0",
            ]
        )

    def to_jsonable(self) -> dict:
        return {
            "session_id": base64.b64encode(self.session_id).decode("ascii"),
            "seq_id": self.seq_id,
            "mode": self.mode,
            "algorithm_hint": self.algorithm_hint,
            "is_decoy": self.is_decoy,
        }


@dataclass(frozen=True)
class ProtectedUnit:
    header: ProtectedUnitHeader
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    hard_problem_class: str
    preferred_path: str

    def with_ciphertext(self, ciphertext: bytes) -> "ProtectedUnit":
        return ProtectedUnit(
            header=self.header,
            nonce=self.nonce,
            ciphertext=ciphertext,
            tag=self.tag,
            hard_problem_class=self.hard_problem_class,
            preferred_path=self.preferred_path,
        )

    def to_jsonable(self) -> dict:
        return {
            "header": self.header.to_jsonable(),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "tag": base64.b64encode(self.tag).decode("ascii"),
            "hard_problem_class": self.hard_problem_class,
            "preferred_path": self.preferred_path,
        }


class ReplayWindow:
    def __init__(self, size: int = 4096) -> None:
        if size <= 0:
            raise ValueError("replay window size must be positive")
        self.size = size
        self.highest = -1
        self.seen: set[int] = set()

    def check_and_commit(self, seq_id: int) -> None:
        if seq_id < 0:
            raise ValueError("seq_id must be non-negative")
        floor = self.highest - self.size + 1
        if seq_id < floor or seq_id in self.seen:
            raise ValueError("replay detected")
        self.seen.add(seq_id)
        if seq_id > self.highest:
            self.highest = seq_id
        self.seen = {item for item in self.seen if item >= self.highest - self.size + 1}


def derive_hop(
    master_secret: bytes,
    seq_id: int,
    library: list[AlgorithmProfile] | None = None,
    mode_salt: bytes = b"DLHP-HOLOGRAPHIC",
    previous_class: str | None = None,
    max_retries: int = 16,
) -> HopSelection:
    algorithms = library or DEFAULT_LIBRARY
    if not algorithms:
        raise ValueError("algorithm library is empty")
    selection_counter = seq_id
    retries = 0
    while True:
        material = b"HOP|" + selection_counter.to_bytes(8, "big") + b"|" + mode_salt
        seed = hmac.new(master_secret, material, hashlib.sha256).digest()
        algorithm = algorithms[int.from_bytes(seed[:4], "big") % len(algorithms)]
        if previous_class is None or algorithm.hard_problem_class != previous_class or retries >= max_retries:
            key = hkdf_expand(seed, b"DLHP-PACKET-KEY|" + algorithm.name.encode("ascii"), 32)
            return HopSelection(seq_id, selection_counter, algorithm, key, retries)
        selection_counter += 1
        retries += 1


def generate_schedule(
    master_secret: bytes,
    count: int,
    library: list[AlgorithmProfile] | None = None,
    mode_salt: bytes = b"DLHP-HOLOGRAPHIC",
    enforce_orthogonality: bool = True,
) -> list[HopSelection]:
    require_non_negative_int("count", count)
    previous_class = None
    schedule = []
    for seq_id in range(count):
        hop = derive_hop(
            master_secret,
            seq_id,
            library=library,
            mode_salt=mode_salt,
            previous_class=previous_class if enforce_orthogonality else None,
        )
        schedule.append(hop)
        previous_class = hop.algorithm.hard_problem_class if enforce_orthogonality else None
    return schedule


def _mod_inverse(value: int, prime: int = PRIME) -> int:
    return pow(value % prime, prime - 2, prime)


def shamir_split(secret: bytes, k: int, n: int, prime: int = PRIME) -> list[tuple[int, list[int]]]:
    if not 1 <= k <= n:
        raise ValueError("threshold must satisfy 1 <= k <= n")
    shares = [(x, []) for x in range(1, n + 1)]
    for byte in secret:
        coefficients = [byte] + [int.from_bytes(random_bytes(2), "big") % prime for _ in range(k - 1)]
        for x, values in shares:
            y = 0
            power = 1
            for coefficient in coefficients:
                y = (y + coefficient * power) % prime
                power = (power * x) % prime
            values.append(y)
    return shares


def shamir_reconstruct(shares: list[tuple[int, list[int]]], prime: int = PRIME) -> bytes:
    if not shares:
        return b""
    length = len(shares[0][1])
    if any(len(values) != length for _, values in shares):
        raise ValueError("share lengths differ")
    recovered = bytearray()
    for position in range(length):
        secret_value = 0
        for idx, (xj, y_values) in enumerate(shares):
            numerator = 1
            denominator = 1
            for inner_idx, (xm, _) in enumerate(shares):
                if idx == inner_idx:
                    continue
                numerator = (numerator * (-xm)) % prime
                denominator = (denominator * (xj - xm)) % prime
            secret_value = (secret_value + y_values[position] * numerator * _mod_inverse(denominator, prime)) % prime
        if secret_value > 255:
            raise ValueError("invalid reconstructed byte")
        recovered.append(secret_value)
    return bytes(recovered)


def encode_share_values(values: list[int]) -> bytes:
    return b"".join(value.to_bytes(2, "big") for value in values)


def decode_share_values(data: bytes) -> list[int]:
    if len(data) % 2:
        raise ValueError("encoded share has odd length")
    values = [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]
    if any(value >= PRIME for value in values):
        raise ValueError("share value outside field")
    return values


def _stream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = bytearray()
    counter = 0
    while len(blocks) < length:
        blocks.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(blocks[:length])


class DLHPSession:
    def __init__(
        self,
        master_secret: bytes,
        *,
        session_id: bytes,
        library: list[AlgorithmProfile] | None = None,
        mode_salt: bytes = b"DLHP-HOLOGRAPHIC",
        replay_window: ReplayWindow | None = None,
    ) -> None:
        if not master_secret:
            raise ValueError("master_secret is required")
        if not session_id:
            raise ValueError("session_id is required")
        self.master_secret = master_secret
        self.session_id = session_id
        self.library = library or DEFAULT_LIBRARY
        self.mode_salt = mode_salt
        self.replay_window = replay_window

    def derive(self, seq_id: int) -> HopSelection:
        return derive_hop(
            self.master_secret,
            seq_id,
            library=self.library,
            mode_salt=self.mode_salt + b"|" + self.session_id,
            previous_class=None,
        )

    def protect_unit(
        self,
        seq_id: int,
        plaintext: bytes,
        *,
        mode: str = "nano",
        is_decoy: bool = False,
        expose_algorithm_hint: bool = False,
    ) -> ProtectedUnit:
        hop = self.derive(seq_id)
        nonce = random_bytes(16)
        header = ProtectedUnitHeader(
            session_id=self.session_id,
            seq_id=seq_id,
            mode=mode,
            algorithm_hint=hop.algorithm.name if expose_algorithm_hint else None,
            is_decoy=is_decoy,
        )
        ciphertext = xor_bytes(plaintext, _stream(hop.packet_key, nonce, len(plaintext)))
        tag = mac(hop.packet_key, header.associated_data(), nonce, ciphertext)
        return ProtectedUnit(
            header=header,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            hard_problem_class=hop.algorithm.hard_problem_class,
            preferred_path=hop.algorithm.preferred_path,
        )

    def open_unit(self, unit: ProtectedUnit) -> bytes | None:
        if unit.header.session_id != self.session_id:
            raise ValueError("session mismatch")
        if self.replay_window is not None:
            self.replay_window.check_and_commit(unit.header.seq_id)
        hop = self.derive(unit.header.seq_id)
        expected_tag = mac(hop.packet_key, unit.header.associated_data(), unit.nonce, unit.ciphertext)
        if not constant_time_equal(expected_tag, unit.tag):
            raise ValueError("authentication failed")
        plaintext = xor_bytes(unit.ciphertext, _stream(hop.packet_key, unit.nonce, len(unit.ciphertext)))
        if unit.header.is_decoy:
            return None
        return plaintext


def generate_chaff_units(
    session: DLHPSession,
    *,
    start_seq_id: int,
    count: int,
    payload_size: int,
) -> list[ProtectedUnit]:
    require_non_negative_int("count", count)
    require_non_negative_int("payload_size", payload_size)
    return [
        session.protect_unit(start_seq_id + offset, random_bytes(payload_size), is_decoy=True)
        for offset in range(count)
    ]


def protect_payload(
    payload: bytes,
    master_secret: bytes,
    k: int = 3,
    n: int = 5,
    library: list[AlgorithmProfile] | None = None,
) -> list[ProtectedShare]:
    shares = shamir_split(payload, k, n)
    schedule = generate_schedule(master_secret, n, library=library, enforce_orthogonality=True)
    protected = []
    for hop, (share_x, share_values) in zip(schedule, shares):
        plaintext = encode_share_values(share_values)
        nonce = random_bytes(16)
        ciphertext = xor_bytes(plaintext, _stream(hop.packet_key, nonce, len(plaintext)))
        associated = (
            hop.seq_id.to_bytes(8, "big")
            + share_x.to_bytes(2, "big")
            + hop.algorithm.algorithm_id.to_bytes(2, "big")
        )
        tag = mac(hop.packet_key, associated, nonce, ciphertext)
        protected.append(
            ProtectedShare(
                seq_id=hop.seq_id,
                share_x=share_x,
                algorithm_name=hop.algorithm.name,
                hard_problem_class=hop.algorithm.hard_problem_class,
                preferred_path=hop.algorithm.preferred_path,
                nonce=nonce,
                ciphertext=ciphertext,
                tag=tag,
            )
        )
    return protected


def recover_payload(
    protected_shares: list[ProtectedShare],
    master_secret: bytes,
    k: int = 3,
    library: list[AlgorithmProfile] | None = None,
) -> bytes:
    if len(protected_shares) < k:
        raise ValueError(f"need at least {k} shares")
    max_seq_id = max(share.seq_id for share in protected_shares)
    schedule = {
        hop.seq_id: hop
        for hop in generate_schedule(
            master_secret,
            max_seq_id + 1,
            library=library,
            enforce_orthogonality=True,
        )
    }
    recovered_shares = []
    for protected in sorted(protected_shares, key=lambda item: item.seq_id)[:k]:
        hop = schedule[protected.seq_id]
        if hop.algorithm.name != protected.algorithm_name:
            raise ValueError("algorithm schedule mismatch")
        associated = (
            protected.seq_id.to_bytes(8, "big")
            + protected.share_x.to_bytes(2, "big")
            + hop.algorithm.algorithm_id.to_bytes(2, "big")
        )
        expected_tag = mac(hop.packet_key, associated, protected.nonce, protected.ciphertext)
        if not constant_time_equal(expected_tag, protected.tag):
            raise ValueError("share authentication failed")
        encoded = xor_bytes(protected.ciphertext, _stream(hop.packet_key, protected.nonce, len(protected.ciphertext)))
        recovered_shares.append((protected.share_x, decode_share_values(encoded)))
    return shamir_reconstruct(recovered_shares)


def schedule_statistics(schedule: list[HopSelection]) -> dict:
    if not schedule:
        return {"count": 0}
    counts: dict[str, int] = {}
    violations = 0
    previous = None
    for hop in schedule:
        counts[hop.algorithm.name] = counts.get(hop.algorithm.name, 0) + 1
        if previous == hop.algorithm.hard_problem_class:
            violations += 1
        previous = hop.algorithm.hard_problem_class
    entropy = 0.0
    for count in counts.values():
        probability = count / len(schedule)
        entropy -= probability * math.log2(probability)
    return {
        "count": len(schedule),
        "algorithm_counts": counts,
        "entropy_bits": round(entropy, 6),
        "orthogonality_violations": violations,
        "average_retries": round(sum(hop.retries for hop in schedule) / len(schedule), 6),
    }


def protected_shares_to_json(shares: list[ProtectedShare]) -> str:
    return json.dumps([share.to_jsonable() for share in shares], ensure_ascii=False, indent=2)
