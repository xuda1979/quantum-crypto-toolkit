import json
from urllib.parse import urlencode

from qcrypto_toolkit.gui import build_dashboard_html, handle_api_request


def test_dashboard_html_contains_core_tools():
    html = build_dashboard_html()

    assert "QCH-KEM" in html
    assert "DLHP" in html
    assert "Policy" in html
    assert "/api/qch-demo" in html
    assert "/api/matrix" in html
    assert "/api/campaign" in html
    assert "/api/sweep" in html
    assert 'class="app-shell"' in html
    assert 'data-panel="overview"' in html
    assert 'data-action="copy-json"' in html
    assert 'data-action="download-json"' in html
    assert "Security posture" in html
    assert "Schedule diversity" in html
    assert "version 0.8" in html
    assert "Compare Profiles" in html
    assert 'id="matrix-table"' in html
    assert "security-weight" in html
    assert 'id="matrix-sort"' in html
    assert 'id="matrix-filter"' in html
    assert "Run Campaign" in html
    assert "Run Sweep" in html
    assert 'data-panel="campaign"' in html
    assert 'data-panel="sweep"' in html
    assert 'name="scenario"' in html
    assert 'id="campaign-aggregate-table"' in html
    assert 'id="campaign-scenario-table"' in html
    assert 'id="campaign-scenario-select"' in html
    assert 'id="sweep-table"' in html


def test_gui_api_qch_demo_returns_audit_json():
    status, headers, body = handle_api_request(
        "/api/qch-demo?" + urlencode({"qkd_bytes": "32", "qkd_rate": "10000", "qber": "0.01"})
    )
    output = json.loads(body.decode("utf-8"))

    assert status == 200
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert output["server_confirmed"] is True
    assert "session_key_hex" not in output
    assert any(event["code"] == "hybrid_key" for event in output["audit_events"])


def test_gui_api_recommend_and_dlhp_unit():
    status, _, recommendation_body = handle_api_request("/api/recommend?profile=long_term_archive")
    recommendation = json.loads(recommendation_body.decode("utf-8"))
    assert status == 200
    assert recommendation["kem"]["primary"] == "ML-KEM-1024"

    status, _, unit_body = handle_api_request("/api/dlhp-unit?message=hello&seq_id=11")
    unit = json.loads(unit_body.decode("utf-8"))
    assert status == 200
    assert unit["opened"] == "hello"
    assert unit["unit"]["header"]["seq_id"] == 11


def test_gui_api_catalog_schedule_and_report():
    status, _, catalog_body = handle_api_request("/api/catalog?kind=kem&min_security_bits=192")
    catalog = json.loads(catalog_body.decode("utf-8"))
    assert status == 200
    assert catalog["count"] >= 2
    assert all(item["kind"] == "kem" for item in catalog["algorithms"])

    status, _, schedule_body = handle_api_request("/api/dlhp-schedule?count=8")
    schedule = json.loads(schedule_body.decode("utf-8"))
    assert status == 200
    assert schedule["statistics"]["count"] == 8
    assert len(schedule["hops"]) == 8

    status, _, report_body = handle_api_request("/api/report?profile=long_term_archive&schedule_count=6")
    report = json.loads(report_body.decode("utf-8"))
    assert status == 200
    assert report["profile"] == "long_term_archive"
    assert report["dlhp"]["schedule"]["count"] == 6

    status, _, matrix_body = handle_api_request("/api/matrix?schedule_count=6")
    matrix = json.loads(matrix_body.decode("utf-8"))
    assert status == 200
    assert len(matrix["rows"]) == len(matrix["profiles"])
    assert any(row["profile"] == "long_term_archive" for row in matrix["rows"])
    assert matrix["summary"]["best_security_profile"] in matrix["profiles"]
    assert matrix["summary"]["recommended_profile"] == matrix["rows"][0]["profile"]
    assert "score_breakdown" in matrix["rows"][0]

    status, _, tuned_matrix_body = handle_api_request("/api/matrix?schedule_count=6&bandwidth_penalty=20&security_weight=5&diversity_weight=5")
    tuned = json.loads(tuned_matrix_body.decode("utf-8"))
    assert status == 200
    assert tuned["scoring"]["bandwidth_penalty"] == 20
    assert tuned["summary"]["recommended_profile"] == "bandwidth_constrained"

    status, _, campaign_body = handle_api_request(
        "/api/campaign?scenario=healthy:64:10000:0.01:6&scenario=fallback:0:0:0:6&profiles=balanced,long_term_archive,bandwidth_constrained"
    )
    campaign = json.loads(campaign_body.decode("utf-8"))
    assert status == 200
    assert campaign["scenario_count"] == 2
    assert len(campaign["aggregate"]["profiles"]) == 3
    assert campaign["aggregate"]["leader"] == campaign["aggregate"]["profiles"][0]["profile"]
    assert campaign["aggregate"]["profiles"][0]["campaign_headline"]

    status, _, sweep_body = handle_api_request(
        "/api/sweep?profiles=balanced,long_term_archive&qkd_bytes_values=0,64&qkd_rate_values=0,10000&qber_values=0,0.08&schedule_count=6"
    )
    sweep = json.loads(sweep_body.decode("utf-8"))
    assert status == 200
    assert sweep["summary"]["point_count"] == 8
    assert len(sweep["summary"]["profiles"]) == 2
    assert sweep["summary"]["profiles"][0]["headline"]


def test_gui_health_endpoint_reports_available_tools():
    status, _, body = handle_api_request("/api/health")
    output = json.loads(body.decode("utf-8"))

    assert status == 200
    assert output["status"] == "ok"
    assert "matrix" in output["tools"]
    assert "sweep" in output["tools"]
    assert "qch-demo" in output["tools"]
    assert "report" in output["tools"]


def test_gui_api_bad_request_is_json_error():
    status, _, body = handle_api_request("/api/recommend?profile=unknown")
    output = json.loads(body.decode("utf-8"))

    assert status == 400
    assert output["error"]


def test_gui_api_rejects_invalid_qber():
    status, _, body = handle_api_request("/api/qch-demo?qber=1.5")
    output = json.loads(body.decode("utf-8"))

    assert status == 400
    assert "qber must be between 0 and 1" in output["error"]
