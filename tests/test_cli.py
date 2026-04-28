import json
from pathlib import Path

from qcrypto_toolkit.cli import main


def test_cli_recommend_outputs_policy_json(capsys):
    assert main(["recommend", "--profile", "long_term_archive"]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["kem"]["primary"] == "ML-KEM-1024"
    assert output["kem"]["backup"] == "HQC-256"
    assert output["signature"]["primary"] == "ML-DSA-65"


def test_cli_dlhp_unit_roundtrip(capsys):
    assert main(["dlhp-unit", "hello", "--seq-id", "9"]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["opened"] == "hello"
    assert output["unit"]["header"]["seq_id"] == 9
    assert output["unit"]["header"]["algorithm_hint"] is None


def test_cli_catalog_and_report(capsys):
    assert main(["catalog", "--kind", "kem", "--min-security-bits", "192"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["count"] >= 2
    assert all(item["kind"] == "kem" for item in catalog["algorithms"])

    assert main(["report", "--profile", "long_term_archive", "--schedule-count", "5"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["profile"] == "long_term_archive"
    assert report["dlhp"]["schedule"]["count"] == 5


def test_cli_matrix_outputs_profile_rows(capsys):
    assert main(["matrix", "balanced", "long_term_archive", "--schedule-count", "4"]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["profiles"] == ["balanced", "long_term_archive"]
    assert [row["profile"] for row in output["rows"]] == ["long_term_archive", "balanced"]
    assert output["rows"][0]["recommended"] is True
    assert output["summary"]["best_security_profile"] == "long_term_archive"
    assert output["summary"]["recommended_profile"] == "long_term_archive"


def test_cli_matrix_accepts_scoring_overrides(capsys):
    assert main(
        [
            "matrix",
            "balanced",
            "long_term_archive",
            "bandwidth_constrained",
            "--schedule-count",
            "6",
            "--bandwidth-penalty",
            "20",
            "--security-weight",
            "5",
            "--diversity-weight",
            "5",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["scoring"]["bandwidth_penalty"] == 20
    assert output["summary"]["recommended_profile"] == "bandwidth_constrained"


def test_cli_campaign_outputs_aggregate_results(capsys):
    assert main(
        [
            "campaign",
            "--scenario",
            "healthy:64:10000:0.01:6",
            "--scenario",
            "fallback:0:0:0:6",
            "--profiles",
            "balanced,long_term_archive,bandwidth_constrained",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["scenario_count"] == 2
    assert output["scenarios"][0]["name"] == "healthy"
    assert len(output["aggregate"]["profiles"]) == 3
    assert output["aggregate"]["profiles"][0]["campaign_headline"]


def test_cli_campaign_accepts_scenario_file(tmp_path: Path, capsys):
    scenario_file = tmp_path / "campaign.json"
    scenario_file.write_text(
        json.dumps(
            {
                "scenarios": [
                    {"name": "healthy", "qkd_bytes": 64, "qkd_rate": 10000, "qber": 0.01, "schedule_count": 6},
                    {"name": "fallback", "qkd_bytes": 0, "qkd_rate": 0, "qber": 0.0, "schedule_count": 6},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "campaign",
            "--scenario-file",
            str(scenario_file),
            "--profiles",
            "balanced,long_term_archive",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["scenario_count"] == 2
    assert output["aggregate"]["leader"] in {"balanced", "long_term_archive"}


def test_cli_sweep_outputs_grid_summary(capsys):
    assert main(
        [
            "sweep",
            "balanced",
            "long_term_archive",
            "--qkd-bytes-values",
            "0,64",
            "--qkd-rate-values",
            "0,10000",
            "--qber-values",
            "0,0.08",
            "--schedule-count",
            "6",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["summary"]["point_count"] == 8
    assert output["summary"]["primary_leader"] in {"balanced", "long_term_archive"}
    assert len(output["summary"]["profiles"]) == 2


def test_cli_invalid_qber_returns_error_code(capsys):
    assert main(["report", "--qber", "1.5"]) == 2
    captured = capsys.readouterr()

    assert captured.out == ""
    assert "qber must be between 0 and 1" in captured.err
