from __future__ import annotations

from collections.abc import Iterable

from .models import AlgorithmDescriptor, AlgorithmKind, Maturity


class AlgorithmRegistry:
    def __init__(self, descriptors: Iterable[AlgorithmDescriptor] = ()) -> None:
        self._by_name: dict[str, AlgorithmDescriptor] = {}
        for descriptor in descriptors:
            self.register(descriptor)

    def register(self, descriptor: AlgorithmDescriptor) -> None:
        for name in descriptor.normalized_names:
            self._by_name[name] = descriptor

    def get(self, name: str) -> AlgorithmDescriptor:
        try:
            return self._by_name[name.lower()]
        except KeyError as exc:
            raise KeyError(f"unknown algorithm: {name}") from exc

    def list(
        self,
        *,
        kind: AlgorithmKind | None = None,
        maturity: Maturity | None = None,
        min_security_bits: int | None = None,
    ) -> list[AlgorithmDescriptor]:
        seen: set[str] = set()
        result = []
        for descriptor in self._by_name.values():
            if descriptor.name in seen:
                continue
            seen.add(descriptor.name)
            if kind is not None and descriptor.kind != kind:
                continue
            if maturity is not None and descriptor.maturity != maturity:
                continue
            if min_security_bits is not None and descriptor.security_bits < min_security_bits:
                continue
            result.append(descriptor)
        return sorted(result, key=lambda item: (item.kind.value, item.name))

    def by_hard_problem(self, hard_problem_class: str) -> list[AlgorithmDescriptor]:
        return [
            descriptor
            for descriptor in self.list()
            if descriptor.hard_problem_class.lower() == hard_problem_class.lower()
        ]


DEFAULT_DESCRIPTORS = [
    AlgorithmDescriptor(
        name="ML-KEM-512",
        aliases=("Kyber512",),
        kind=AlgorithmKind.KEM,
        hard_problem_class="Module-LWE",
        security_bits=118,
        maturity=Maturity.STANDARDIZED,
        public_key_bytes=800,
        secret_key_bytes=1632,
        ciphertext_bytes=768,
        tags=("nist", "fips-203", "lattice"),
    ),
    AlgorithmDescriptor(
        name="ML-KEM-768",
        aliases=("Kyber768",),
        kind=AlgorithmKind.KEM,
        hard_problem_class="Module-LWE",
        security_bits=180,
        maturity=Maturity.STANDARDIZED,
        public_key_bytes=1184,
        secret_key_bytes=2400,
        ciphertext_bytes=1088,
        preferred_path="5G",
        tags=("nist", "fips-203", "lattice"),
    ),
    AlgorithmDescriptor(
        name="ML-KEM-1024",
        aliases=("Kyber1024",),
        kind=AlgorithmKind.KEM,
        hard_problem_class="Module-LWE",
        security_bits=256,
        maturity=Maturity.STANDARDIZED,
        public_key_bytes=1568,
        secret_key_bytes=3168,
        ciphertext_bytes=1568,
        tags=("nist", "fips-203", "lattice"),
    ),
    AlgorithmDescriptor(
        name="NTRU-HPS-677",
        kind=AlgorithmKind.KEM,
        hard_problem_class="NTRU-Lattice",
        security_bits=128,
        maturity=Maturity.CANDIDATE,
        public_key_bytes=930,
        secret_key_bytes=1234,
        ciphertext_bytes=930,
        preferred_path="WiFi",
        tags=("ntru", "lattice"),
    ),
    AlgorithmDescriptor(
        name="Classic-McEliece-348864",
        aliases=("Classic-McEliece", "McEliece"),
        kind=AlgorithmKind.KEM,
        hard_problem_class="Goppa-Code",
        security_bits=128,
        maturity=Maturity.CANDIDATE,
        public_key_bytes=261120,
        secret_key_bytes=6492,
        ciphertext_bytes=128,
        preferred_path="Satellite",
        tags=("code-based",),
    ),
    AlgorithmDescriptor(
        name="BIKE-L3",
        kind=AlgorithmKind.KEM,
        hard_problem_class="QC-MDPC-Code",
        security_bits=192,
        maturity=Maturity.CANDIDATE,
        public_key_bytes=1541,
        secret_key_bytes=3082,
        ciphertext_bytes=1573,
        preferred_path="WiFi",
        tags=("code-based", "nist-round-4-alternate"),
    ),
    AlgorithmDescriptor(
        name="HQC-256",
        kind=AlgorithmKind.KEM,
        hard_problem_class="QC-Code",
        security_bits=256,
        maturity=Maturity.SELECTED_FOR_STANDARDIZATION,
        public_key_bytes=7245,
        secret_key_bytes=7317,
        ciphertext_bytes=14421,
        preferred_path="Satellite",
        tags=("code-based", "nist-selected-2025"),
        notes="Selected by NIST as an additional post-quantum encryption/KEM standard; final standard is pending.",
    ),
    AlgorithmDescriptor(
        name="FrodoKEM-976",
        kind=AlgorithmKind.KEM,
        hard_problem_class="Plain-LWE",
        security_bits=192,
        maturity=Maturity.LEGACY_PQC,
        public_key_bytes=15632,
        secret_key_bytes=31296,
        ciphertext_bytes=15744,
        preferred_path="5G",
        tags=("lattice", "conservative"),
    ),
    AlgorithmDescriptor(
        name="ML-DSA-65",
        aliases=("Dilithium3",),
        kind=AlgorithmKind.SIGNATURE,
        hard_problem_class="Module-LWE/SIS",
        security_bits=192,
        maturity=Maturity.STANDARDIZED,
        public_key_bytes=1952,
        secret_key_bytes=4032,
        signature_bytes=3309,
        tags=("nist", "fips-204", "signature"),
    ),
    AlgorithmDescriptor(
        name="Falcon-512",
        kind=AlgorithmKind.SIGNATURE,
        hard_problem_class="NTRU-Lattice",
        security_bits=128,
        maturity=Maturity.CANDIDATE,
        public_key_bytes=897,
        secret_key_bytes=1281,
        signature_bytes=666,
        tags=("signature", "compact"),
        notes="NIST plans Falcon standardization as FN-DSA; use standardized ML-DSA/SLH-DSA first where available.",
    ),
    AlgorithmDescriptor(
        name="SLH-DSA-SHAKE-128s",
        aliases=("SPHINCS+-128s",),
        kind=AlgorithmKind.HASH_SIGNATURE,
        hard_problem_class="Hash-Based",
        security_bits=128,
        maturity=Maturity.STANDARDIZED,
        public_key_bytes=32,
        secret_key_bytes=64,
        signature_bytes=7856,
        tags=("nist", "fips-205", "stateless"),
    ),
    AlgorithmDescriptor(
        name="XMSS-SHA2_10_256",
        kind=AlgorithmKind.HASH_SIGNATURE,
        hard_problem_class="Hash-Based",
        security_bits=128,
        maturity=Maturity.STANDARDIZED,
        public_key_bytes=64,
        secret_key_bytes=132,
        signature_bytes=2500,
        tags=("stateful", "rfc-8391"),
    ),
    AlgorithmDescriptor(
        name="QCH-KEM",
        kind=AlgorithmKind.HYBRID,
        hard_problem_class="Hybrid-PQC-QKD",
        security_bits=256,
        maturity=Maturity.PATENT_EXPERIMENTAL,
        ciphertext_bytes=1568,
        tags=("patent", "hybrid", "qkd"),
    ),
    AlgorithmDescriptor(
        name="DLHP",
        kind=AlgorithmKind.HOPPING,
        hard_problem_class="Multi-Primitive-Orthogonal",
        security_bits=256,
        maturity=Maturity.PATENT_EXPERIMENTAL,
        tags=("patent", "hopping", "threshold"),
    ),
]


DEFAULT_REGISTRY = AlgorithmRegistry(DEFAULT_DESCRIPTORS)
