from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from .dlhp import DLHPSession, generate_chaff_units
from .policy import DeploymentProfile, recommendation_to_jsonable, recommend_suite
from .qch_kem import QCHKEM, QKDKeyBuffer
from .reports import (
    build_campaign_report,
    build_profile_matrix,
    build_profile_sweep,
    build_security_report,
    catalog_to_jsonable,
    schedule_to_jsonable,
)
from .validation import parse_number_series, parse_scenarios


DEMO_SECRET = b"demo-master-secret-32-bytes...."[:32]


def _json_response(payload: dict, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    return (
        status,
        {"Content-Type": "application/json; charset=utf-8"},
        json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
    )


def _html_response(html: str) -> tuple[int, dict[str, str], bytes]:
    return 200, {"Content-Type": "text/html; charset=utf-8"}, html.encode("utf-8")


def _get_int(params: dict[str, list[str]], name: str, default: int) -> int:
    return int(params.get(name, [str(default)])[0])


def _get_float(params: dict[str, list[str]], name: str, default: float) -> float:
    return float(params.get(name, [str(default)])[0])


def _secret_from_params(params: dict[str, list[str]]) -> bytes:
    if "secret" not in params or not params["secret"][0]:
        return DEMO_SECRET
    return base64.b64decode(params["secret"][0])


def _matrix_scoring_from_params(params: dict[str, list[str]]) -> dict:
    return {
        "security_weight": _get_int(params, "security_weight", 30),
        "diversity_weight": _get_int(params, "diversity_weight", 10),
        "rotation_weight": _get_int(params, "rotation_weight", 4),
        "bandwidth_penalty": _get_int(params, "bandwidth_penalty", 1),
        "findings_penalty": _get_int(params, "findings_penalty", 3),
        "state_penalty": _get_int(params, "state_penalty", 15),
        "orthogonality_penalty": _get_int(params, "orthogonality_penalty", 50),
    }


def _campaign_scenarios_from_params(params: dict[str, list[str]]) -> list[dict]:
    raw_values = params.get("scenario") or [
        "healthy:64:10000:0.01:20",
        "stressed:8:2000:0.08:20",
        "fallback:0:0:0:20",
    ]
    file_path = params.get("scenario_file", [None])[0] or None
    return parse_scenarios([] if file_path else raw_values, file_path=file_path)


def handle_api_request(path: str) -> tuple[int, dict[str, str], bytes]:
    parsed = urlparse(path)
    params = parse_qs(parsed.query)
    try:
        if parsed.path == "/api/health":
            return _json_response(
                {
                    "status": "ok",
                    "tools": [
                        "qch-demo",
                        "recommend",
                        "dlhp-unit",
                        "dlhp-chaff",
                        "dlhp-schedule",
                        "catalog",
                        "report",
                        "matrix",
                        "campaign",
                        "sweep",
                    ],
                }
            )

        if parsed.path == "/api/qch-demo":
            buffer = QKDKeyBuffer.seeded(_get_int(params, "qkd_bytes", 64))
            trace = QCHKEM().establish(
                buffer,
                qkd_rate_bps=_get_float(params, "qkd_rate", 10000.0),
                qber=_get_float(params, "qber", 0.01),
            )
            return _json_response(trace.to_jsonable(include_session_key=False))

        if parsed.path == "/api/recommend":
            profile = DeploymentProfile(params.get("profile", [DeploymentProfile.BALANCED.value])[0])
            return _json_response(recommendation_to_jsonable(recommend_suite(profile)))

        if parsed.path == "/api/dlhp-unit":
            secret = _secret_from_params(params)
            session_id = params.get("session_id", ["demo-session"])[0].encode("utf-8")
            message = params.get("message", ["hello packet"])[0].encode("utf-8")
            seq_id = _get_int(params, "seq_id", 0)
            sender = DLHPSession(secret, session_id=session_id)
            receiver = DLHPSession(secret, session_id=session_id)
            unit = sender.protect_unit(seq_id, message)
            opened = receiver.open_unit(unit)
            return _json_response(
                {
                    "opened": opened.decode("utf-8") if opened is not None else None,
                    "unit": unit.to_jsonable(),
                }
            )

        if parsed.path == "/api/dlhp-chaff":
            secret = _secret_from_params(params)
            session = DLHPSession(secret, session_id=params.get("session_id", ["demo-session"])[0].encode("utf-8"))
            units = generate_chaff_units(
                session,
                start_seq_id=_get_int(params, "start_seq_id", 1000),
                count=_get_int(params, "count", 3),
                payload_size=_get_int(params, "payload_size", 32),
            )
            return _json_response({"chaff": [unit.to_jsonable() for unit in units]})

        if parsed.path == "/api/dlhp-schedule":
            return _json_response(schedule_to_jsonable(_get_int(params, "count", 20)))

        if parsed.path == "/api/catalog":
            min_security = params.get("min_security_bits", [None])[0]
            return _json_response(
                catalog_to_jsonable(
                    kind=params.get("kind", [None])[0] or None,
                    maturity=params.get("maturity", [None])[0] or None,
                    min_security_bits=int(min_security) if min_security else None,
                )
            )

        if parsed.path == "/api/report":
            return _json_response(
                build_security_report(
                    profile=params.get("profile", [DeploymentProfile.BALANCED.value])[0],
                    qkd_bytes=_get_int(params, "qkd_bytes", 64),
                    qkd_rate=_get_float(params, "qkd_rate", 10000.0),
                    qber=_get_float(params, "qber", 0.01),
                    schedule_count=_get_int(params, "schedule_count", 20),
                )
            )

        if parsed.path == "/api/matrix":
            raw_profiles = params.get("profiles") or [",".join(profile.value for profile in DeploymentProfile)]
            return _json_response(
                build_profile_matrix(
                    profiles=raw_profiles,
                    qkd_bytes=_get_int(params, "qkd_bytes", 64),
                    qkd_rate=_get_float(params, "qkd_rate", 10000.0),
                    qber=_get_float(params, "qber", 0.01),
                    schedule_count=_get_int(params, "schedule_count", 20),
                    scoring=_matrix_scoring_from_params(params),
                )
            )

        if parsed.path == "/api/campaign":
            raw_profiles = params.get("profiles") or [",".join(profile.value for profile in DeploymentProfile)]
            return _json_response(
                build_campaign_report(
                    scenarios=_campaign_scenarios_from_params(params),
                    profiles=raw_profiles,
                    scoring=_matrix_scoring_from_params(params),
                )
            )

        if parsed.path == "/api/sweep":
            raw_profiles = params.get("profiles") or [",".join(profile.value for profile in DeploymentProfile)]
            return _json_response(
                build_profile_sweep(
                    profiles=raw_profiles,
                    qkd_bytes_values=parse_number_series("qkd_bytes", params.get("qkd_bytes_values", ["0,8,32,64"])[0], cast=int),
                    qkd_rate_values=parse_number_series("qkd_rate", params.get("qkd_rate_values", ["0,2000,10000"])[0], cast=float),
                    qber_values=parse_number_series("qber", params.get("qber_values", ["0,0.02,0.08"])[0], cast=float, probability=True),
                    schedule_count=_get_int(params, "schedule_count", 20),
                    scoring=_matrix_scoring_from_params(params),
                )
            )

        return _json_response({"error": "unknown endpoint"}, status=404)
    except Exception as exc:
        return _json_response({"error": str(exc)}, status=400)


def build_dashboard_html() -> str:
    return """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>抗量子算法工具集</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #eef2f6;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --ink: #18202c;
      --muted: #647084;
      --line: #d9e0ea;
      --teal: #0f766e;
      --blue: #2563eb;
      --purple: #7c3aed;
      --amber: #b7791f;
      --red: #b42318;
      --green-soft: #e8f5f2;
      --blue-soft: #eaf1ff;
      --purple-soft: #f2ecff;
      --amber-soft: #fff7e6;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--ink); }
    .app-shell { min-height: 100vh; display: grid; grid-template-columns: 248px minmax(0, 1fr); }
    .sidebar {
      background: #17202c;
      color: #f8fafc;
      padding: 18px 14px;
      display: grid;
      grid-template-rows: auto auto 1fr auto;
      gap: 18px;
    }
    .brand { display: grid; gap: 8px; padding: 6px 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.12); }
    .brand-mark {
      width: 38px; height: 38px; border-radius: 8px;
      display: grid; place-items: center; font-weight: 800;
      background: linear-gradient(135deg, #14b8a6, #7c3aed);
    }
    .brand h1 { font-size: 17px; line-height: 1.25; margin: 0; letter-spacing: 0; }
    .brand p { margin: 0; color: #a8b3c4; font-size: 12px; }
    .nav { display: grid; gap: 6px; }
    .nav button {
      width: 100%; border: 0; background: transparent; color: #dbe4ef;
      display: flex; align-items: center; gap: 10px; text-align: left;
      padding: 10px 11px; border-radius: 7px; cursor: pointer; font: inherit;
    }
    .nav button.active { background: #243142; color: #fff; }
    .nav .icon { width: 20px; text-align: center; color: #99f6e4; }
    .sidebar-foot { color: #a8b3c4; font-size: 12px; padding: 0 8px; }
    .workspace { display: grid; grid-template-rows: auto 1fr; min-width: 0; }
    .topbar {
      min-height: 74px; background: rgba(255,255,255,0.9); border-bottom: 1px solid var(--line);
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      padding: 14px 22px; position: sticky; top: 0; z-index: 2; backdrop-filter: blur(10px);
    }
    .topbar h2 { font-size: 18px; margin: 0; letter-spacing: 0; }
    .topbar p { margin: 3px 0 0; color: var(--muted); font-size: 12px; }
    .status-row { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    .pill {
      border: 1px solid var(--line); background: #fff; border-radius: 999px;
      padding: 6px 9px; font-size: 12px; color: var(--muted);
    }
    .content { padding: 20px; display: grid; gap: 18px; max-width: 1480px; width: 100%; margin: 0 auto; }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .metric {
      background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
      padding: 14px; display: grid; gap: 8px; min-height: 96px;
    }
    .metric strong { font-size: 22px; line-height: 1; }
    .metric span { color: var(--muted); font-size: 12px; }
    .metric.teal { background: var(--green-soft); }
    .metric.blue { background: var(--blue-soft); }
    .metric.purple { background: var(--purple-soft); }
    .metric.amber { background: var(--amber-soft); }
    .panel-grid { display: grid; grid-template-columns: 430px minmax(0, 1fr); gap: 18px; align-items: start; }
    .panel {
      background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
      box-shadow: 0 12px 32px rgba(22, 32, 44, 0.06);
    }
    .tool-panel { display: none; padding: 16px; }
    .tool-panel.active { display: grid; gap: 14px; }
    .panel-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 2px; }
    .panel-title h3 { margin: 0; font-size: 15px; letter-spacing: 0; }
    .panel-title span { color: var(--muted); font-size: 12px; }
    .field-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    label { display: grid; gap: 5px; font-size: 12px; color: var(--muted); }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      color: var(--ink);
      background: #fff;
    }
    textarea {
      min-height: 132px;
      resize: vertical;
      font-family: var(--mono);
      line-height: 1.45;
    }
    .field-span { grid-column: 1 / -1; }
    .button-row { display: flex; gap: 9px; flex-wrap: wrap; }
    button.run {
      border: 0;
      border-radius: 6px;
      padding: 10px 12px;
      font: inherit;
      font-weight: 650;
      color: #fff;
      background: var(--teal);
      cursor: pointer;
    }
    button.run.blue { background: var(--blue); }
    button.run.purple { background: var(--purple); }
    button.run.amber { background: var(--amber); }
    button.utility {
      border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--ink);
      padding: 8px 10px; font: inherit; cursor: pointer;
    }
    .output { min-height: calc(100vh - 268px); overflow: hidden; display: grid; grid-template-rows: auto auto auto auto auto 1fr; }
    .output-head { padding: 14px 16px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .output-head h3 { margin: 0; font-size: 15px; letter-spacing: 0; }
    .status { font-size: 12px; color: var(--muted); }
    .summary-strip { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; background: var(--line); border-bottom: 1px solid var(--line); }
    .summary-item { background: var(--panel-soft); padding: 12px 14px; display: grid; gap: 4px; min-height: 70px; }
    .summary-item span { color: var(--muted); font-size: 12px; }
    .summary-item strong { font-size: 16px; overflow-wrap: anywhere; }
    pre {
      margin: 0;
      padding: 16px;
      overflow: auto;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.55;
      white-space: pre-wrap;
      word-break: break-word;
      background: #fbfcfe;
      min-height: 360px;
      max-height: calc(100vh - 360px);
    }
    .timeline { display: flex; gap: 4px; align-items: stretch; padding: 12px 16px; border-bottom: 1px solid var(--line); overflow-x: auto; background: #fff; }
    .campaign-wrap, .matrix-wrap, .sweep-wrap { border-top: 1px solid var(--line); background: #fff; }
    .campaign-headline {
      padding: 14px 16px; background: #f8fafc; border-bottom: 1px solid var(--line);
      display: grid; gap: 4px;
    }
    .campaign-headline strong { font-size: 14px; }
    .campaign-headline span { color: var(--muted); font-size: 12px; }
    .campaign-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .table-card { overflow: auto; border-right: 1px solid var(--line); }
    .table-card:last-child { border-right: 0; }
    .table-card .panel-title { padding: 12px 16px; margin: 0; border-bottom: 1px solid var(--line); background: #fbfcfe; }
    .campaign-note {
      padding: 12px 16px; border-top: 1px solid var(--line); background: #f9fbfd; color: var(--muted); font-size: 12px;
    }
    .sweep-headline {
      padding: 14px 16px; background: #f8fafc; border-bottom: 1px solid var(--line);
      display: grid; gap: 4px;
    }
    .sweep-headline strong { font-size: 14px; }
    .sweep-headline span { color: var(--muted); font-size: 12px; }
    .matrix-toolbar {
      display: flex; gap: 8px; flex-wrap: wrap; align-items: center;
      padding: 12px 16px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }
    .matrix-toolbar label { min-width: 180px; }
    table.matrix-table { width: 100%; border-collapse: collapse; font-size: 12px; }
    .matrix-table th, .matrix-table td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    .matrix-table th { position: sticky; top: 0; background: #f8fafc; color: var(--muted); font-weight: 650; }
    .matrix-table td strong { display: inline-block; min-width: 20px; }
    .matrix-table .winner { color: var(--teal); font-weight: 700; }
    .matrix-table tr.is-recommended { background: #eefcf7; }
    .matrix-table tr.is-lightweight { background: #fff9eb; }
    .matrix-table tr.is-diverse { background: #f3f0ff; }
    .hop { min-width: 40px; height: 28px; border-radius: 5px; border: 1px solid var(--line); }
    .hop.StructuredLattice, .hop.Module-LWE { background: #ccfbf1; }
    .hop.UnstructuredLattice, .hop.Plain-LWE { background: #dbeafe; }
    .hop.GoppaCode, .hop.QC-Code, .hop.QCMDPC { background: #ede9fe; }
    .hop.NTRULattice { background: #fef3c7; }
    @media (max-width: 1080px) {
      .app-shell { grid-template-columns: 1fr; }
      .sidebar { position: static; grid-template-rows: auto auto; }
      .sidebar-foot { display: none; }
      .nav { grid-template-columns: repeat(4, minmax(0, 1fr)); }
      .panel-grid { grid-template-columns: 1fr; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .campaign-grid { grid-template-columns: 1fr; }
      .table-card { border-right: 0; border-bottom: 1px solid var(--line); }
      .table-card:last-child { border-bottom: 0; }
    }
    @media (max-width: 640px) {
      .topbar { align-items: flex-start; flex-direction: column; position: static; }
      .content { padding: 12px; }
      .nav { grid-template-columns: 1fr 1fr; }
      .field-grid, .metrics, .summary-strip { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">Q</div>
        <div>
          <h1>抗量子算法工具集</h1>
          <p>QCH-KEM / DLHP Console</p>
        </div>
      </div>
      <nav class="nav" aria-label="tools">
        <button class="active" data-panel="overview"><span class="icon">◈</span>Overview</button>
        <button data-panel="campaign"><span class="icon">◉</span>Campaign</button>
        <button data-panel="sweep"><span class="icon">◌</span>Sweep</button>
        <button data-panel="qch"><span class="icon">◇</span>QCH-KEM</button>
        <button data-panel="dlhp"><span class="icon">◆</span>DLHP</button>
        <button data-panel="policy"><span class="icon">◎</span>Policy</button>
        <button data-panel="catalog"><span class="icon">▦</span>Catalog</button>
        <button data-panel="report"><span class="icon">▣</span>Report</button>
      </nav>
      <div></div>
      <div class="sidebar-foot">local dashboard · demo adapters</div>
    </aside>
    <section class="workspace">
      <header class="topbar">
        <div>
          <h2 id="page-title">Security Operations Console</h2>
          <p id="page-subtitle">Protocol demos, catalog inspection, report generation, and profile comparison</p>
        </div>
        <div class="status-row">
          <span class="pill" id="health-pill">health: checking</span>
          <span class="pill">version 0.8</span>
          <span class="pill">local only</span>
        </div>
      </header>
      <main class="content">
        <section class="metrics">
          <div class="metric teal"><span>Security posture</span><strong id="metric-posture">demo</strong></div>
          <div class="metric blue"><span>QCH state</span><strong id="metric-qch">pending</strong></div>
          <div class="metric purple"><span>Schedule diversity</span><strong id="metric-diversity">pending</strong></div>
          <div class="metric amber"><span>Catalog entries</span><strong id="metric-catalog">pending</strong></div>
        </section>
        <section class="panel-grid">
          <section class="panel">
            <form class="tool-panel active" data-panel-id="overview" data-endpoint="/api/matrix">
              <div class="panel-title"><h3>Profile Matrix</h3><span>side-by-side comparison</span></div>
              <div class="field-grid">
                <label>Profiles
                  <input name="profiles" value="balanced,long_term_archive,high_assurance,bandwidth_constrained">
                </label>
                <label>Schedule count <input name="schedule_count" type="number" value="20" min="0"></label>
                <label>QKD bytes <input name="qkd_bytes" type="number" value="64" min="0"></label>
                <label>QKD rate bps <input name="qkd_rate" type="number" value="10000" min="0"></label>
                <label>QBER <input name="qber" type="number" value="0.01" min="0" step="0.001"></label>
                <label>security-weight <input name="security_weight" type="number" value="30" min="0"></label>
                <label>diversity-weight <input name="diversity_weight" type="number" value="10" min="0"></label>
                <label>rotation-weight <input name="rotation_weight" type="number" value="4" min="0"></label>
                <label>bandwidth-penalty <input name="bandwidth_penalty" type="number" value="1" min="0"></label>
                <label>state-penalty <input name="state_penalty" type="number" value="15" min="0"></label>
              </div>
              <div class="button-row">
                <button class="run" type="submit">Compare Profiles</button>
              </div>
            </form>
            <form class="tool-panel" data-panel-id="campaign" data-endpoint="/api/campaign">
              <div class="panel-title"><h3>Campaign Planner</h3><span>multi-scenario planning</span></div>
              <label class="field-span">Scenarios
                <textarea name="scenario" spellcheck="false">healthy:64:10000:0.01:20
stressed:8:2000:0.08:20
fallback:0:0:0:20</textarea>
              </label>
              <div class="field-grid">
                <label>Profiles
                  <input name="profiles" value="balanced,long_term_archive,high_assurance,bandwidth_constrained">
                </label>
                <label>Scenario file
                  <input name="scenario_file" placeholder="/abs/path/campaign.json">
                </label>
                <label>security-weight <input name="security_weight" type="number" value="30" min="0"></label>
                <label>diversity-weight <input name="diversity_weight" type="number" value="10" min="0"></label>
                <label>rotation-weight <input name="rotation_weight" type="number" value="4" min="0"></label>
                <label>bandwidth-penalty <input name="bandwidth_penalty" type="number" value="1" min="0"></label>
                <label>findings-penalty <input name="findings_penalty" type="number" value="3" min="0"></label>
                <label>state-penalty <input name="state_penalty" type="number" value="15" min="0"></label>
                <label>orthogonality-penalty <input name="orthogonality_penalty" type="number" value="50" min="0"></label>
              </div>
              <div class="button-row">
                <button class="run" type="submit">Run Campaign</button>
              </div>
            </form>
            <form class="tool-panel" data-panel-id="sweep" data-endpoint="/api/sweep">
              <div class="panel-title"><h3>Condition Sweep</h3><span>automatic boundary mapping</span></div>
              <div class="field-grid">
                <label>Profiles
                  <input name="profiles" value="balanced,long_term_archive,high_assurance,bandwidth_constrained">
                </label>
                <label>Schedule count <input name="schedule_count" type="number" value="20" min="0"></label>
                <label>QKD bytes values
                  <input name="qkd_bytes_values" value="0,8,32,64">
                </label>
                <label>QKD rate values
                  <input name="qkd_rate_values" value="0,2000,10000">
                </label>
                <label>QBER values
                  <input name="qber_values" value="0,0.02,0.08">
                </label>
                <label>security-weight <input name="security_weight" type="number" value="30" min="0"></label>
                <label>diversity-weight <input name="diversity_weight" type="number" value="10" min="0"></label>
                <label>rotation-weight <input name="rotation_weight" type="number" value="4" min="0"></label>
                <label>bandwidth-penalty <input name="bandwidth_penalty" type="number" value="1" min="0"></label>
                <label>findings-penalty <input name="findings_penalty" type="number" value="3" min="0"></label>
                <label>state-penalty <input name="state_penalty" type="number" value="15" min="0"></label>
              </div>
              <div class="button-row">
                <button class="run" type="submit">Run Sweep</button>
              </div>
            </form>
            <form class="tool-panel" data-panel-id="qch" data-endpoint="/api/qch-demo">
              <div class="panel-title"><h3>QCH-KEM Hybrid Handshake</h3><span>QKD + PQC</span></div>
              <div class="field-grid">
                <label>QKD bytes <input name="qkd_bytes" type="number" value="64" min="0"></label>
                <label>QKD rate bps <input name="qkd_rate" type="number" value="10000" min="0"></label>
                <label>QBER <input name="qber" type="number" value="0.01" min="0" step="0.001"></label>
              </div>
              <div class="button-row"><button class="run blue" type="submit">Run QCH-KEM</button></div>
            </form>
            <form class="tool-panel" data-panel-id="dlhp" data-endpoint="/api/dlhp-unit">
              <div class="panel-title"><h3>DLHP Protected Unit</h3><span>packet protection</span></div>
              <div class="field-grid">
                <label>Message <input name="message" value="hello packet"></label>
                <label>SeqID <input name="seq_id" type="number" value="9" min="0"></label>
                <label>Session ID <input name="session_id" value="demo-session"></label>
                <label>Chaff count <input name="count" type="number" value="3" min="0"></label>
              </div>
              <div class="button-row">
                <button class="run purple" type="submit">Protect + Open</button>
                <button class="utility" type="button" data-run-endpoint="/api/dlhp-schedule">Preview Schedule</button>
                <button class="utility" type="button" data-run-endpoint="/api/dlhp-chaff">Generate Chaff</button>
              </div>
            </form>
            <form class="tool-panel" data-panel-id="policy" data-endpoint="/api/recommend">
              <div class="panel-title"><h3>Policy Recommendation</h3><span>suite selection</span></div>
              <label>Profile
                <select name="profile">
                  <option value="balanced">balanced</option>
                  <option value="high_assurance">high_assurance</option>
                  <option value="bandwidth_constrained">bandwidth_constrained</option>
                  <option value="long_term_archive">long_term_archive</option>
                  <option value="experimental_diversity">experimental_diversity</option>
                </select>
              </label>
              <div class="button-row"><button class="run" type="submit">Recommend</button></div>
            </form>
            <form class="tool-panel" data-panel-id="catalog" data-endpoint="/api/catalog">
              <div class="panel-title"><h3>Algorithm Catalog</h3><span>registry</span></div>
              <div class="field-grid">
                <label>Kind
                  <select name="kind">
                    <option value="">all</option>
                    <option value="kem">kem</option>
                    <option value="signature">signature</option>
                    <option value="hash_signature">hash_signature</option>
                    <option value="hybrid">hybrid</option>
                    <option value="hopping">hopping</option>
                  </select>
                </label>
                <label>Minimum security bits <input name="min_security_bits" type="number" value="128" min="0"></label>
              </div>
              <div class="button-row"><button class="run amber" type="submit">List Algorithms</button></div>
            </form>
            <form class="tool-panel" data-panel-id="report" data-endpoint="/api/report">
              <div class="panel-title"><h3>Security Report</h3><span>exportable JSON</span></div>
              <div class="field-grid">
                <label>Profile
                  <select name="profile">
                    <option value="balanced">balanced</option>
                    <option value="long_term_archive">long_term_archive</option>
                    <option value="high_assurance">high_assurance</option>
                    <option value="bandwidth_constrained">bandwidth_constrained</option>
                  </select>
                </label>
                <label>Schedule count <input name="schedule_count" type="number" value="20" min="0"></label>
              </div>
              <div class="button-row"><button class="run" type="submit">Build Report</button></div>
            </form>
          </section>
          <section class="panel output">
            <div class="output-head">
              <div>
                <h3>Result JSON</h3>
                <span id="status" class="status">ready</span>
              </div>
              <div class="button-row">
                <button class="utility" type="button" data-action="copy-json">Copy</button>
                <button class="utility" type="button" data-action="download-json">Download</button>
              </div>
            </div>
            <div class="summary-strip">
              <div class="summary-item"><span>Primary KEM</span><strong id="summary-kem">-</strong></div>
              <div class="summary-item"><span>QKD / QCH</span><strong id="summary-qch">-</strong></div>
              <div class="summary-item"><span>DLHP entropy</span><strong id="summary-dlhp">-</strong></div>
            </div>
            <div id="timeline" class="timeline" aria-label="schedule timeline"></div>
            <div id="campaign-wrap" class="campaign-wrap" hidden>
              <div class="campaign-headline">
                <strong id="campaign-headline">campaign summary</strong>
                <span id="campaign-meta">leader / resilience / scenario</span>
              </div>
              <div class="campaign-grid">
                <section class="table-card">
                  <div class="panel-title"><h3>Aggregate Ranking</h3><span id="campaign-leader">leader</span></div>
                  <table id="campaign-aggregate-table" class="matrix-table">
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>Profile</th>
                        <th>Wins</th>
                        <th>Average</th>
                        <th>Fallback / State</th>
                        <th>Campaign View</th>
                      </tr>
                    </thead>
                    <tbody></tbody>
                  </table>
                </section>
                <section class="table-card">
                  <div class="panel-title"><h3>Scenarios</h3><span id="campaign-scenario-count">0 scenarios</span></div>
                  <table id="campaign-scenario-table" class="matrix-table">
                    <thead>
                      <tr>
                        <th>Scenario</th>
                        <th>Inputs</th>
                        <th>Winner</th>
                        <th>Highlights</th>
                        <th>Inspect</th>
                      </tr>
                    </thead>
                    <tbody></tbody>
                  </table>
                </section>
              </div>
              <div class="matrix-toolbar">
                <label>Scenario Matrix
                  <select id="campaign-scenario-select"></select>
                </label>
              </div>
            </div>
            <div id="sweep-wrap" class="sweep-wrap" hidden>
              <div class="sweep-headline">
                <strong id="sweep-headline">sweep summary</strong>
                <span id="sweep-meta">leader coverage / transition count</span>
              </div>
              <table id="sweep-table" class="matrix-table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Profile</th>
                    <th>Leader Coverage</th>
                    <th>Average</th>
                    <th>Normal / Fallback</th>
                    <th>Sweep View</th>
                  </tr>
                </thead>
                <tbody></tbody>
              </table>
            </div>
            <div id="matrix-wrap" class="matrix-wrap" hidden>
              <div class="matrix-toolbar">
                <label>Sort
                  <select id="matrix-sort">
                    <option value="score_desc">score desc</option>
                    <option value="bandwidth_asc">bandwidth asc</option>
                    <option value="diversity_desc">diversity desc</option>
                    <option value="security_desc">security desc</option>
                  </select>
                </label>
                <label>Filter
                  <input id="matrix-filter" placeholder="profile or trade-off">
                </label>
              </div>
              <table id="matrix-table" class="matrix-table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Profile</th>
                    <th>QCH</th>
                    <th>Bandwidth</th>
                    <th>Diversity</th>
                    <th>Trade-off / Score</th>
                  </tr>
                </thead>
                <tbody></tbody>
              </table>
            </div>
            <div id="campaign-note" class="campaign-note" hidden></div>
            <pre id="result">{}</pre>
          </section>
        </section>
      </main>
    </section>
  </div>
  <script>
    const result = document.querySelector("#result");
    const status = document.querySelector("#status");
    const timeline = document.querySelector("#timeline");
    const matrixWrap = document.querySelector("#matrix-wrap");
    const matrixBody = document.querySelector("#matrix-table tbody");
    const matrixSort = document.querySelector("#matrix-sort");
    const matrixFilter = document.querySelector("#matrix-filter");
    const campaignWrap = document.querySelector("#campaign-wrap");
    const campaignAggregateBody = document.querySelector("#campaign-aggregate-table tbody");
    const campaignScenarioBody = document.querySelector("#campaign-scenario-table tbody");
    const campaignScenarioSelect = document.querySelector("#campaign-scenario-select");
    const sweepWrap = document.querySelector("#sweep-wrap");
    const sweepBody = document.querySelector("#sweep-table tbody");
    const campaignNote = document.querySelector("#campaign-note");
    let latestJson = {};
    let activeCampaignScenario = "";
    const titles = {
      overview: ["Security Operations Console", "Profile comparison matrix across multiple deployment targets"],
      campaign: ["Campaign Planner", "Aggregate winners, fallback exposure, and scenario-specific profile ranking"],
      sweep: ["Condition Sweep", "Map recommendation boundaries across QKD bytes, rates, and QBER points"],
      qch: ["QCH-KEM", "Hybrid QKD and post-quantum key establishment"],
      dlhp: ["DLHP", "Packet units, schedule preview, and decoy generation"],
      policy: ["Policy", "Deployment profile based suite selection"],
      catalog: ["Catalog", "Post-quantum registry inspection"],
      report: ["Report", "Combined JSON posture output"]
    };
    async function run(form, endpointOverride = null) {
      const endpoint = endpointOverride || form.dataset.endpoint;
      const params = new URLSearchParams(new FormData(form));
      status.textContent = "running";
      const response = await fetch(`${endpoint}?${params.toString()}`);
      const text = await response.text();
      try {
        latestJson = JSON.parse(text);
        result.textContent = JSON.stringify(latestJson, null, 2);
        updateSummary(latestJson);
      } catch {
        result.textContent = text;
        latestJson = {};
        updateSummary(latestJson);
      }
      status.textContent = response.ok ? "ok" : `error ${response.status}`;
    }
    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }
    function getCampaignScenario(data) {
      if (!data?.scenarios?.length) return null;
      if (!activeCampaignScenario || !data.scenarios.some((item) => item.name === activeCampaignScenario)) {
        activeCampaignScenario = data.scenarios[0].name;
      }
      return data.scenarios.find((item) => item.name === activeCampaignScenario) || data.scenarios[0];
    }
    function getActiveMatrixPayload(data) {
      if (data?.scenarios?.length) {
        return getCampaignScenario(data)?.matrix || data.scenarios[0].matrix;
      }
      if (data?.points?.length) {
        return data.points[0].matrix;
      }
      return data?.rows ? data : null;
    }
    function updateSummary(data) {
      const policy = data.policy || data;
      const matrixPayload = getActiveMatrixPayload(data) || data;
      const matrixFirst = matrixPayload.rows?.[0];
      const leader = data.aggregate?.profiles?.[0];
      const sweepLeader = data.summary?.profiles?.[0];
      document.querySelector("#summary-kem").textContent = matrixFirst?.kem_primary || policy.kem?.primary || data.pqc_profile || "-";
      document.querySelector("#summary-qch").textContent = matrixFirst?.qch_state || data.qch?.state || data.state || data.opened || (leader ? `${leader.profile} / ${leader.resilience}` : (sweepLeader ? `${sweepLeader.profile} / sweep` : "-"));
      document.querySelector("#summary-dlhp").textContent = matrixPayload.summary?.best_diversity_profile || matrixFirst?.entropy_bits || data.dlhp?.schedule?.entropy_bits || data.statistics?.entropy_bits || (data.summary?.transition_count ?? "-");
      if (data.scenarios) {
        document.querySelector("#metric-posture").textContent = `${data.scenario_count} scenarios`;
        document.querySelector("#metric-qch").textContent = leader?.resilience || "campaign";
        document.querySelector("#metric-diversity").textContent = leader ? `rank ${leader.average_rank}` : "ready";
        document.querySelector("#metric-catalog").textContent = data.aggregate?.profiles?.length ?? data.profiles?.length ?? "ready";
      } else if (data.points) {
        document.querySelector("#metric-posture").textContent = `${data.summary?.point_count || data.points.length} points`;
        document.querySelector("#metric-qch").textContent = sweepLeader?.profile || "sweep";
        document.querySelector("#metric-diversity").textContent = `${data.summary?.transition_count || 0} transitions`;
        document.querySelector("#metric-catalog").textContent = data.summary?.profiles?.length ?? data.profiles?.length ?? "ready";
      } else {
        document.querySelector("#metric-posture").textContent = data.rows ? `${data.rows.length} views` : (data.summary?.production_ready === false ? "prototype" : "demo");
        document.querySelector("#metric-qch").textContent = matrixFirst?.qch_profile || data.qch?.state || data.state || "ready";
        document.querySelector("#metric-diversity").textContent = (matrixFirst?.orthogonality_violations === 0) || data.dlhp?.schedule?.orthogonality_violations === 0 || data.statistics?.orthogonality_violations === 0 ? "orthogonal" : "review";
        document.querySelector("#metric-catalog").textContent = data.count ?? data.rows?.length ?? data.policy?.dlhp_allowed?.length ?? "ready";
      }
      const hops = matrixFirst?.hops_preview || matrixPayload.hops || data.hops || data.dlhp?.hops_preview || [];
      timeline.innerHTML = hops.map((hop) => `<div class="hop ${escapeHtml(hop.hard_problem_class)}" title="${escapeHtml(`${hop.seq_id}: ${hop.algorithm}`)}"></div>`).join("");
      renderCampaign(data);
      renderSweep(data);
      renderMatrix(matrixPayload);
      renderCampaignNote(data);
    }
    function renderCampaign(data) {
      if (!data?.scenarios?.length) {
        campaignWrap.hidden = true;
        campaignAggregateBody.innerHTML = "";
        campaignScenarioBody.innerHTML = "";
        campaignScenarioSelect.innerHTML = "";
        return;
      }
      campaignWrap.hidden = false;
      const leader = data.aggregate?.profiles?.[0];
      const selected = getCampaignScenario(data);
      document.querySelector("#campaign-headline").textContent = data.aggregate?.leader_headline || "campaign summary";
      document.querySelector("#campaign-meta").textContent = `leader ${leader?.profile || "-"} | selected ${selected?.name || "-"} | ${data.scenario_count} scenarios`;
      document.querySelector("#campaign-leader").textContent = leader ? `${leader.profile} · ${leader.resilience}` : "leader";
      document.querySelector("#campaign-scenario-count").textContent = `${data.scenario_count} scenarios`;
      campaignScenarioSelect.innerHTML = data.scenarios.map((item) => `
        <option value="${escapeHtml(item.name)}" ${item.name === selected?.name ? "selected" : ""}>${escapeHtml(item.name)}</option>
      `).join("");
      campaignAggregateBody.innerHTML = (data.aggregate?.profiles || []).map((row, index) => `
        <tr class="${index === 0 ? "is-recommended" : ""}">
          <td><strong class="${index === 0 ? "winner" : ""}">#${index + 1}</strong></td>
          <td class="${index === 0 ? "winner" : ""}">${escapeHtml(row.profile)}</td>
          <td>${escapeHtml(`${row.scenario_wins}/${data.scenario_count}`)}</td>
          <td>${escapeHtml(row.average_score)}<br><span class="status">rank ${escapeHtml(row.average_rank)}</span></td>
          <td>${escapeHtml(row.fallback_count)}<br><span class="status">${escapeHtml(formatStateMix(row.state_mix))}</span></td>
          <td>${escapeHtml(row.campaign_headline)}<br><span class="status">${escapeHtml(formatNarrative(row.why_it_wins, row.why_it_loses))}</span></td>
        </tr>
      `).join("");
      campaignScenarioBody.innerHTML = data.scenarios.map((item) => `
        <tr class="${item.name === selected?.name ? "is-recommended" : ""}">
          <td class="${item.name === selected?.name ? "winner" : ""}">${escapeHtml(item.name)}</td>
          <td>${escapeHtml(`qkd ${item.inputs.qkd_bytes}B @ ${item.inputs.qkd_rate}bps / qber ${item.inputs.qber}`)}</td>
          <td>${escapeHtml(item.summary.recommended_profile)}</td>
          <td>${escapeHtml(`security ${item.summary.best_security_profile} · bandwidth ${item.summary.best_bandwidth_profile} · diversity ${item.summary.best_diversity_profile}`)}</td>
          <td><button class="utility" type="button" data-scenario-select="${escapeHtml(item.name)}">Inspect</button></td>
        </tr>
      `).join("");
    }
    function renderSweep(data) {
      if (!data?.points?.length) {
        sweepWrap.hidden = true;
        sweepBody.innerHTML = "";
        return;
      }
      sweepWrap.hidden = false;
      const leader = data.summary?.profiles?.[0];
      document.querySelector("#sweep-headline").textContent = `primary leader ${leader?.profile || "-"} across ${data.summary?.point_count || data.points.length} points`;
      document.querySelector("#sweep-meta").textContent = `${data.summary?.transition_count || 0} leader transitions across qber lanes`;
      sweepBody.innerHTML = (data.summary?.profiles || []).map((row, index) => `
        <tr class="${index === 0 ? "is-recommended" : ""}">
          <td><strong class="${index === 0 ? "winner" : ""}">#${index + 1}</strong></td>
          <td class="${index === 0 ? "winner" : ""}">${escapeHtml(row.profile)}</td>
          <td>${escapeHtml(`${row.leader_count}/${data.summary.point_count}`)}<br><span class="status">${escapeHtml(Math.round(row.coverage_ratio * 100))}% coverage</span></td>
          <td>${escapeHtml(row.average_score)}<br><span class="status">rank ${escapeHtml(row.average_rank)}</span></td>
          <td>${escapeHtml(`${Math.round(row.normal_ratio * 100)}% / ${Math.round(row.fallback_ratio * 100)}%`)}</td>
          <td>${escapeHtml(row.headline)}</td>
        </tr>
      `).join("");
    }
    function renderCampaignNote(data) {
      if (data?.points?.length) {
        campaignNote.hidden = false;
        campaignNote.textContent = `sweep: ${data.summary?.point_count || data.points.length} points, primary leader ${data.summary?.primary_leader || "-"}, transitions ${data.summary?.transition_count || 0}`;
        return;
      }
      if (!data?.scenarios?.length) {
        campaignNote.hidden = true;
        campaignNote.textContent = "";
        return;
      }
      const leader = data.aggregate?.profiles?.[0];
      const selected = getCampaignScenario(data);
      campaignNote.hidden = false;
      campaignNote.textContent = `campaign: ${data.scenario_count} scenarios, leader ${leader?.profile || "-"} with ${leader?.scenario_wins || 0} wins; inspecting ${selected?.name || "-"} matrix`;
    }
    function renderMatrix(data) {
      if (!data?.rows) {
        matrixWrap.hidden = true;
        matrixBody.innerHTML = "";
        return;
      }
      matrixWrap.hidden = false;
      const tradeoffs = new Map((data.summary?.tradeoffs || []).map((item) => [item.profile, item.headline]));
      const rows = sortAndFilterRows(data.rows, tradeoffs);
      matrixBody.innerHTML = rows.map((row) => `
        <tr class="${row.recommended ? "is-recommended" : ""} ${data.summary?.best_bandwidth_profile === row.profile ? "is-lightweight" : ""} ${data.summary?.best_diversity_profile === row.profile ? "is-diverse" : ""}">
          <td><strong class="${row.recommended ? "winner" : ""}">#${row.rank}</strong></td>
          <td class="${row.recommended ? "winner" : ""}">${escapeHtml(row.profile)}</td>
          <td>${escapeHtml(row.qch_profile)}</td>
          <td>${escapeHtml(row.bandwidth_bytes)} B<br><span class="status">score ${escapeHtml(row.score)}</span></td>
          <td>${escapeHtml(row.entropy_bits)} / ${escapeHtml(row.dlhp_rotation_size)}</td>
          <td>${escapeHtml(tradeoffs.get(row.profile) || "-")}<br><span class="status">${escapeHtml(formatBreakdown(row.score_breakdown))}</span></td>
        </tr>
      `).join("");
    }
    function sortAndFilterRows(rows, tradeoffs) {
      const filter = matrixFilter.value.trim().toLowerCase();
      const filtered = rows.filter((row) => {
        if (!filter) return true;
        const headline = (tradeoffs.get(row.profile) || "").toLowerCase();
        return row.profile.toLowerCase().includes(filter) || headline.includes(filter);
      });
      const sorted = [...filtered];
      switch (matrixSort.value) {
        case "bandwidth_asc":
          sorted.sort((a, b) => a.bandwidth_bytes - b.bandwidth_bytes || b.score - a.score);
          break;
        case "diversity_desc":
          sorted.sort((a, b) => b.entropy_bits - a.entropy_bits || b.dlhp_rotation_size - a.dlhp_rotation_size);
          break;
        case "security_desc":
          sorted.sort((a, b) => securityRank(b.qch_profile) - securityRank(a.qch_profile) || b.score - a.score);
          break;
        default:
          sorted.sort((a, b) => b.score - a.score || a.bandwidth_bytes - b.bandwidth_bytes);
      }
      return sorted;
    }
    function securityRank(name) {
      return { "ML-KEM-512": 1, "ML-KEM-768": 2, "ML-KEM-1024": 3 }[name] || 0;
    }
    function formatBreakdown(breakdown) {
      if (!breakdown) return "";
      return Object.entries(breakdown).map(([key, value]) => `${key}:${value}`).join(" ");
    }
    function formatStateMix(items) {
      if (!items?.length) return "no state data";
      return items.map((item) => `${item.state}:${Math.round(item.ratio * 100)}%`).join(" ");
    }
    function formatNarrative(strengths, weaknesses) {
      const parts = [...(strengths || []), ...(weaknesses || [])];
      return parts.slice(0, 3).join(" | ") || "no aggregate commentary";
    }
    function activate(panel) {
      document.querySelectorAll(".nav button").forEach((button) => button.classList.toggle("active", button.dataset.panel === panel));
      document.querySelectorAll(".tool-panel").forEach((form) => form.classList.toggle("active", form.dataset.panelId === panel));
      document.querySelector("#page-title").textContent = titles[panel][0];
      document.querySelector("#page-subtitle").textContent = titles[panel][1];
    }
    document.querySelectorAll(".nav button").forEach((button) => {
      button.addEventListener("click", () => activate(button.dataset.panel));
    });
    document.querySelectorAll("form.tool-panel").forEach((form) => {
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        run(form);
      });
    });
    document.querySelectorAll("[data-run-endpoint]").forEach((button) => {
      button.addEventListener("click", () => run(button.closest("form"), button.dataset.runEndpoint));
    });
    matrixSort.addEventListener("change", () => renderMatrix(getActiveMatrixPayload(latestJson)));
    matrixFilter.addEventListener("input", () => renderMatrix(getActiveMatrixPayload(latestJson)));
    campaignScenarioSelect.addEventListener("change", () => {
      activeCampaignScenario = campaignScenarioSelect.value;
      updateSummary(latestJson);
    });
    campaignWrap.addEventListener("click", (event) => {
      const button = event.target.closest("[data-scenario-select]");
      if (!button) return;
      activeCampaignScenario = button.dataset.scenarioSelect;
      updateSummary(latestJson);
    });
    document.querySelector('[data-action="copy-json"]').addEventListener("click", async () => {
      await navigator.clipboard.writeText(JSON.stringify(latestJson, null, 2));
      status.textContent = "copied";
    });
    document.querySelector('[data-action="download-json"]').addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(latestJson, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "qcrypto-report.json";
      link.click();
      URL.revokeObjectURL(link.href);
    });
    fetch("/api/health").then((response) => response.json()).then((data) => {
      document.querySelector("#health-pill").textContent = `health: ${data.status}`;
    });
    run(document.querySelector('[data-panel-id="overview"]'));
  </script>
</body>
</html>"""


class ToolkitRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            status, headers, body = _html_response(build_dashboard_html())
        elif self.path.startswith("/api/"):
            status, headers, body = handle_api_request(self.path)
        else:
            status, headers, body = _json_response({"error": "not found"}, status=404)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), ToolkitRequestHandler)
    print(f"qcrypto GUI listening on http://{host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return server


def dashboard_url(host: str = "127.0.0.1", port: int = 8765) -> str:
    return f"http://{host}:{quote(str(port))}"
