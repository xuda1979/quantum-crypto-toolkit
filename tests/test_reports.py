from qcrypto_toolkit.reports import (
    build_campaign_report,
    build_profile_matrix,
    build_profile_sweep,
    build_security_report,
    catalog_to_jsonable,
)


def test_security_report_combines_policy_qch_and_dlhp_findings():
    report = build_security_report(
        profile="long_term_archive",
        qkd_bytes=64,
        qkd_rate=10000,
        qber=0.01,
        schedule_count=12,
    )

    assert report["profile"] == "long_term_archive"
    assert report["policy"]["kem"]["primary"] == "ML-KEM-1024"
    assert report["qch"]["server_confirmed"] is True
    assert report["dlhp"]["schedule"]["count"] == 12
    assert report["summary"]["production_ready"] is False
    assert any(item["code"] == "demo_crypto" for item in report["summary"]["findings"])


def test_security_report_applies_profile_tuning_to_qch_and_dlhp_rotation():
    archive = build_security_report(
        profile="long_term_archive",
        qkd_bytes=64,
        qkd_rate=10000,
        qber=0.01,
        schedule_count=8,
    )
    constrained = build_security_report(
        profile="bandwidth_constrained",
        qkd_bytes=64,
        qkd_rate=10000,
        qber=0.01,
        schedule_count=8,
    )

    assert archive["policy"]["kem"]["primary"] == "ML-KEM-1024"
    assert archive["qch"]["pqc_profile"] == "ML-KEM-1024"
    assert constrained["policy"]["kem"]["primary"] == "ML-KEM-512"
    assert constrained["qch"]["pqc_profile"] == "ML-KEM-512"
    assert archive["dlhp"]["rotation"]["allowed_algorithms"] == ["ML-KEM-1024", "HQC-256", "FrodoKEM-976"]
    assert constrained["dlhp"]["rotation"]["allowed_algorithms"] == ["ML-KEM-768", "NTRU-HPS-677", "BIKE-L3"]


def test_profile_matrix_compares_multiple_profiles_under_same_inputs():
    matrix = build_profile_matrix(
        profiles=["balanced", "long_term_archive", "bandwidth_constrained"],
        qkd_bytes=64,
        qkd_rate=10000,
        qber=0.01,
        schedule_count=6,
    )

    assert matrix["profiles"] == ["balanced", "long_term_archive", "bandwidth_constrained"]
    assert {row["profile"] for row in matrix["rows"]} == {"balanced", "long_term_archive", "bandwidth_constrained"}
    assert matrix["rows"][0]["profile"] == "long_term_archive"
    assert matrix["rows"][0]["qch_profile"] == "ML-KEM-1024"
    assert matrix["rows"][1]["profile"] == "balanced"
    assert matrix["rows"][1]["qch_profile"] == "ML-KEM-768"
    assert matrix["rows"][2]["profile"] == "bandwidth_constrained"
    assert matrix["rows"][2]["qch_profile"] == "ML-KEM-512"
    assert matrix["rows"][0]["score"] >= matrix["rows"][1]["score"] >= matrix["rows"][2]["score"]
    assert matrix["rows"][0]["recommended"] is True
    assert set(matrix["rows"][0]["score_breakdown"]) == {
        "security",
        "diversity",
        "rotation",
        "orthogonality",
        "bandwidth",
        "findings",
        "state",
    }
    assert matrix["summary"]["best_security_profile"] == "long_term_archive"
    assert matrix["summary"]["best_bandwidth_profile"] == "bandwidth_constrained"
    assert matrix["summary"]["best_diversity_profile"] == "balanced"
    assert matrix["summary"]["recommended_profile"] == "long_term_archive"
    assert matrix["summary"]["sorting"]["mode"] == "score_desc"
    assert any(item["profile"] == "balanced" for item in matrix["summary"]["tradeoffs"])
    assert all(row["orthogonality_violations"] == 0 for row in matrix["rows"])


def test_profile_matrix_accepts_custom_scoring_weights():
    matrix = build_profile_matrix(
        profiles=["balanced", "long_term_archive", "bandwidth_constrained"],
        qkd_bytes=64,
        qkd_rate=10000,
        qber=0.01,
        schedule_count=6,
        scoring={
            "security_weight": 5,
            "diversity_weight": 5,
            "rotation_weight": 4,
            "bandwidth_penalty": 20,
            "findings_penalty": 3,
            "state_penalty": 15,
            "orthogonality_penalty": 50,
        },
    )

    assert matrix["scoring"]["bandwidth_penalty"] == 20
    assert matrix["summary"]["recommended_profile"] == "bandwidth_constrained"


def test_campaign_report_aggregates_multiple_scenarios():
    campaign = build_campaign_report(
        scenarios=[
            {"name": "healthy", "qkd_bytes": 64, "qkd_rate": 10000, "qber": 0.01, "schedule_count": 6},
            {"name": "stressed", "qkd_bytes": 8, "qkd_rate": 2000, "qber": 0.08, "schedule_count": 6},
            {"name": "fallback", "qkd_bytes": 0, "qkd_rate": 0, "qber": 0.0, "schedule_count": 6},
        ],
        profiles=["balanced", "long_term_archive", "bandwidth_constrained"],
    )

    assert campaign["scenario_count"] == 3
    assert [item["name"] for item in campaign["scenarios"]] == ["healthy", "stressed", "fallback"]
    assert len(campaign["aggregate"]["profiles"]) == 3
    assert campaign["aggregate"]["leader"] == campaign["aggregate"]["profiles"][0]["profile"]
    assert campaign["aggregate"]["leader_headline"]
    assert campaign["aggregate"]["profiles"][0]["profile"] in {"long_term_archive", "bandwidth_constrained", "balanced"}
    assert campaign["aggregate"]["profiles"][0]["scenario_wins"] >= campaign["aggregate"]["profiles"][-1]["scenario_wins"]
    assert "average_rank" in campaign["aggregate"]["profiles"][0]
    assert "score_breakdown_average" in campaign["aggregate"]["profiles"][0]
    assert "resilience" in campaign["aggregate"]["profiles"][0]
    assert isinstance(campaign["aggregate"]["profiles"][0]["why_it_wins"], list)
    assert isinstance(campaign["aggregate"]["profiles"][0]["why_it_loses"], list)
    assert campaign["aggregate"]["profiles"][0]["campaign_headline"]
    assert campaign["aggregate"]["profiles"][0]["best_scenario"]["name"]
    assert campaign["aggregate"]["profiles"][0]["worst_scenario"]["name"]
    assert campaign["scenarios"][0]["summary"]["ranked_profiles"]
    assert all("recommended_profile" in item["summary"] for item in campaign["scenarios"])


def test_profile_sweep_maps_recommendation_boundaries():
    sweep = build_profile_sweep(
        profiles=["balanced", "long_term_archive", "bandwidth_constrained"],
        qkd_bytes_values=[0, 64],
        qkd_rate_values=[0.0, 10000.0],
        qber_values=[0.0, 0.08],
        schedule_count=6,
    )

    assert sweep["summary"]["point_count"] == 8
    assert sweep["summary"]["primary_leader"] in {"balanced", "long_term_archive", "bandwidth_constrained"}
    assert len(sweep["points"]) == 8
    assert len(sweep["summary"]["profiles"]) == 3
    assert sweep["summary"]["profiles"][0]["headline"]
    assert "leader_count" in sweep["summary"]["profiles"][0]
    assert "coverage_ratio" in sweep["summary"]["profiles"][0]
    assert "fallback_ratio" in sweep["summary"]["profiles"][0]
    assert all("matrix" in point for point in sweep["points"])


def test_catalog_jsonable_filters_by_kind_and_contains_status():
    catalog = catalog_to_jsonable(kind="kem", min_security_bits=192)

    names = {item["name"] for item in catalog["algorithms"]}
    assert "ML-KEM-1024" in names
    assert "HQC-256" in names
    assert "ML-KEM-512" not in names
    assert catalog["count"] == len(catalog["algorithms"])
    assert all(item["kind"] == "kem" for item in catalog["algorithms"])
