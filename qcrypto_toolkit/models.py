from __future__ import annotations

import enum
from dataclasses import dataclass, field


class AlgorithmKind(str, enum.Enum):
    KEM = "kem"
    SIGNATURE = "signature"
    HASH_SIGNATURE = "hash_signature"
    HYBRID = "hybrid"
    HOPPING = "hopping"
    EXPERIMENTAL = "experimental"


class Maturity(str, enum.Enum):
    STANDARDIZED = "standardized"
    SELECTED_FOR_STANDARDIZATION = "selected_for_standardization"
    CANDIDATE = "candidate"
    LEGACY_PQC = "legacy_pqc"
    PATENT_EXPERIMENTAL = "patent_experimental"
    RESEARCH = "research"
    DEMONSTRATION = "demonstration"
    RETIRED = "retired"


@dataclass(frozen=True)
class AlgorithmDescriptor:
    name: str
    kind: AlgorithmKind
    hard_problem_class: str
    security_bits: int
    maturity: Maturity
    public_key_bytes: int | None = None
    secret_key_bytes: int | None = None
    ciphertext_bytes: int | None = None
    signature_bytes: int | None = None
    shared_secret_bytes: int = 32
    preferred_path: str = "default"
    aliases: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    notes: str = ""

    @property
    def normalized_names(self) -> tuple[str, ...]:
        return (self.name.lower(),) + tuple(alias.lower() for alias in self.aliases)


@dataclass(frozen=True)
class KeyPair:
    algorithm: AlgorithmDescriptor
    public_key: bytes
    secret_key: bytes
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EncapsulationResult:
    algorithm: AlgorithmDescriptor
    ciphertext: bytes
    shared_secret: bytes
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SignatureResult:
    algorithm: AlgorithmDescriptor
    signature: bytes
    metadata: dict[str, str] = field(default_factory=dict)
