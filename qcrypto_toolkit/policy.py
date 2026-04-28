from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .models import AlgorithmDescriptor, AlgorithmKind, Maturity
from .registry import DEFAULT_REGISTRY, AlgorithmRegistry


class DeploymentProfile(str, enum.Enum):
    BALANCED = "balanced"
    HIGH_ASSURANCE = "high_assurance"
    BANDWIDTH_CONSTRAINED = "bandwidth_constrained"
    LONG_TERM_ARCHIVE = "long_term_archive"
    EXPERIMENTAL_DIVERSITY = "experimental_diversity"


@dataclass(frozen=True)
class PolicyFinding:
    severity: str
    code: str
    message: str


@dataclass(frozen=True)
class AlgorithmAssessment:
    algorithm: AlgorithmDescriptor
    recommended: bool
    score: int
    findings: tuple[PolicyFinding, ...] = ()


@dataclass(frozen=True)
class PolicyRecommendation:
    profile: DeploymentProfile
    kem_primary: str
    kem_backup: str | None
    signature_primary: str
    signature_backup: str
    dlhp_allowed: tuple[str, ...]
    findings: tuple[PolicyFinding, ...] = field(default_factory=tuple)


_MATURE_SCORE = {
    Maturity.STANDARDIZED: 40,
    Maturity.SELECTED_FOR_STANDARDIZATION: 25,
    Maturity.CANDIDATE: 15,
    Maturity.LEGACY_PQC: 10,
    Maturity.PATENT_EXPERIMENTAL: 5,
    Maturity.RESEARCH: 0,
    Maturity.DEMONSTRATION: 0,
    Maturity.RETIRED: -100,
}


def assess_algorithm(descriptor: AlgorithmDescriptor, profile: DeploymentProfile = DeploymentProfile.BALANCED) -> AlgorithmAssessment:
    score = descriptor.security_bits + _MATURE_SCORE.get(descriptor.maturity, 0)
    findings: list[PolicyFinding] = []

    if descriptor.maturity == Maturity.RETIRED:
        findings.append(PolicyFinding("critical", "retired", "Do not deploy retired or broken algorithms."))
    elif descriptor.maturity in {Maturity.RESEARCH, Maturity.DEMONSTRATION, Maturity.PATENT_EXPERIMENTAL}:
        findings.append(PolicyFinding("warning", "experimental", "Use for prototyping or defense-in-depth only, not as sole production protection."))
    elif descriptor.maturity == Maturity.SELECTED_FOR_STANDARDIZATION:
        findings.append(PolicyFinding("info", "pending_standard", "Selected for standardization but the final standard is pending."))

    if profile == DeploymentProfile.LONG_TERM_ARCHIVE and descriptor.security_bits < 192:
        findings.append(PolicyFinding("warning", "archive_strength", "Long-term archive protection should prefer at least 192-bit security."))
        score -= 30
    if profile == DeploymentProfile.BANDWIDTH_CONSTRAINED and (descriptor.public_key_bytes or 0) > 8192:
        findings.append(PolicyFinding("info", "large_keys", "Large keys may be unsuitable for constrained links."))
        score -= 20
    if "nist" in descriptor.tags and descriptor.maturity == Maturity.STANDARDIZED:
        score += 20

    recommended = not any(finding.severity == "critical" for finding in findings)
    return AlgorithmAssessment(descriptor, recommended, score, tuple(findings))


def recommend_suite(
    profile: DeploymentProfile = DeploymentProfile.BALANCED,
    registry: AlgorithmRegistry = DEFAULT_REGISTRY,
) -> PolicyRecommendation:
    kems = [
        assess_algorithm(item, profile)
        for item in registry.list(kind=AlgorithmKind.KEM)
        if item.maturity != Maturity.RETIRED
    ]
    signatures = [
        assess_algorithm(item, profile)
        for item in registry.list()
        if item.kind in {AlgorithmKind.SIGNATURE, AlgorithmKind.HASH_SIGNATURE}
        and item.maturity != Maturity.RETIRED
    ]

    if profile == DeploymentProfile.BANDWIDTH_CONSTRAINED:
        kems.sort(key=lambda item: ((item.algorithm.public_key_bytes or 0) + (item.algorithm.ciphertext_bytes or 0), -item.score))
    else:
        kems.sort(key=lambda item: item.score, reverse=True)
    signatures.sort(key=lambda item: item.score, reverse=True)

    primary_kem = _select_primary_kem(profile, registry)
    backup_kem = next(
        (
            item.algorithm
            for item in kems
            if item.algorithm.name != primary_kem.name
            and item.algorithm.hard_problem_class != primary_kem.hard_problem_class
            and item.algorithm.security_bits >= 192
        ),
        None,
    )
    primary_sig = next(item.algorithm for item in signatures if item.algorithm.name.startswith("ML-DSA"))
    backup_sig = next(
        item.algorithm
        for item in signatures
        if item.algorithm.hard_problem_class != primary_sig.hard_problem_class
    )

    allowed = _select_dlhp_rotation(profile, registry)
    findings = [
        PolicyFinding(
            "info",
            "nist_status_2026",
            "NIST FIPS 203/204/205 are finalized; HQC was selected in 2025 as an additional KEM and is not yet a final FIPS standard.",
        )
    ]
    findings.append(
        PolicyFinding(
            "info",
            "primary_kem_policy",
            f"Primary KEM aligned to the {profile.value} deployment profile: {primary_kem.name}.",
        )
    )
    if backup_kem and backup_kem.maturity == Maturity.SELECTED_FOR_STANDARDIZATION:
        findings.append(
            PolicyFinding(
                "info",
                "hqc_backup",
                "HQC is useful as a different-math backup to ML-KEM, but final HQC standardization is expected later.",
            )
        )

    return PolicyRecommendation(
        profile=profile,
        kem_primary=primary_kem.name,
        kem_backup=backup_kem.name if backup_kem else None,
        signature_primary=primary_sig.name,
        signature_backup=backup_sig.name,
        dlhp_allowed=tuple(item.name for item in allowed),
        findings=tuple(findings),
    )


def _select_primary_kem(profile: DeploymentProfile, registry: AlgorithmRegistry) -> AlgorithmDescriptor:
    if profile == DeploymentProfile.BANDWIDTH_CONSTRAINED:
        return registry.get("ML-KEM-512")
    if profile in {DeploymentProfile.HIGH_ASSURANCE, DeploymentProfile.LONG_TERM_ARCHIVE}:
        return registry.get("ML-KEM-1024")
    return registry.get("ML-KEM-768")


def _select_dlhp_rotation(profile: DeploymentProfile, registry: AlgorithmRegistry) -> list[AlgorithmDescriptor]:
    candidates = [
        registry.get("ML-KEM-768"),
        registry.get("HQC-256"),
        registry.get("Classic-McEliece"),
        registry.get("FrodoKEM-976"),
        registry.get("NTRU-HPS-677"),
        registry.get("BIKE-L3"),
    ]
    if profile == DeploymentProfile.BANDWIDTH_CONSTRAINED:
        return [registry.get("ML-KEM-768"), registry.get("NTRU-HPS-677"), registry.get("BIKE-L3")]
    if profile == DeploymentProfile.HIGH_ASSURANCE:
        return [item for item in candidates if item.security_bits >= 128]
    if profile == DeploymentProfile.LONG_TERM_ARCHIVE:
        return [registry.get("ML-KEM-1024"), registry.get("HQC-256"), registry.get("FrodoKEM-976")]
    return candidates[:5]


def recommendation_to_jsonable(recommendation: PolicyRecommendation) -> dict:
    return {
        "profile": recommendation.profile.value,
        "kem": {
            "primary": recommendation.kem_primary,
            "backup": recommendation.kem_backup,
        },
        "signature": {
            "primary": recommendation.signature_primary,
            "backup": recommendation.signature_backup,
        },
        "dlhp_allowed": list(recommendation.dlhp_allowed),
        "findings": [finding.__dict__ for finding in recommendation.findings],
    }
