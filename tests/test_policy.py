from qcrypto_toolkit.models import Maturity
from qcrypto_toolkit.policy import DeploymentProfile, assess_algorithm, recommend_suite
from qcrypto_toolkit.registry import DEFAULT_REGISTRY


def test_policy_recommends_standardized_primary_and_diverse_backup():
    recommendation = recommend_suite(DeploymentProfile.LONG_TERM_ARCHIVE)

    assert recommendation.kem_primary == "ML-KEM-1024"
    assert recommendation.kem_backup == "HQC-256"
    assert recommendation.signature_primary == "ML-DSA-65"
    assert recommendation.signature_backup == "SLH-DSA-SHAKE-128s"
    assert "HQC-256" in recommendation.dlhp_allowed


def test_policy_primary_kem_tracks_profile_intent():
    balanced = recommend_suite(DeploymentProfile.BALANCED)
    constrained = recommend_suite(DeploymentProfile.BANDWIDTH_CONSTRAINED)
    archive = recommend_suite(DeploymentProfile.LONG_TERM_ARCHIVE)

    assert balanced.kem_primary == "ML-KEM-768"
    assert constrained.kem_primary == "ML-KEM-512"
    assert archive.kem_primary == "ML-KEM-1024"


def test_hqc_is_marked_selected_but_not_final_standard():
    hqc = DEFAULT_REGISTRY.get("HQC-256")
    assessment = assess_algorithm(hqc)

    assert hqc.maturity == Maturity.SELECTED_FOR_STANDARDIZATION
    assert assessment.recommended
    assert any(finding.code == "pending_standard" for finding in assessment.findings)
