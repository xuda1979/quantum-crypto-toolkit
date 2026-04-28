from __future__ import annotations

import argparse
import base64
import json
import sys

from .dlhp import (
    DLHPSession,
    generate_chaff_units,
    generate_schedule,
    protect_payload,
    protected_shares_to_json,
    recover_payload,
    schedule_statistics,
)
from .policy import DeploymentProfile, recommendation_to_jsonable, recommend_suite
from .qch_kem import QCHKEM, QKDKeyBuffer
from .gui import serve
from .reports import (
    build_campaign_report,
    build_profile_matrix,
    build_profile_sweep,
    build_security_report,
    catalog_to_jsonable,
    schedule_to_jsonable,
)
from .validation import parse_number_series, parse_profiles, parse_scenarios


def _matrix_scoring_from_args(args: argparse.Namespace) -> dict:
    return {
        "security_weight": args.security_weight,
        "diversity_weight": args.diversity_weight,
        "rotation_weight": args.rotation_weight,
        "bandwidth_penalty": args.bandwidth_penalty,
        "findings_penalty": args.findings_penalty,
        "state_penalty": args.state_penalty,
        "orthogonality_penalty": args.orthogonality_penalty,
    }


def cmd_qch_demo(args: argparse.Namespace) -> int:
    buffer = QKDKeyBuffer.seeded(args.qkd_bytes)
    toolkit = QCHKEM()
    trace = toolkit.establish(buffer, qkd_rate_bps=args.qkd_rate, qber=args.qber)
    print(json.dumps(trace.to_jsonable(include_session_key=args.show_key), indent=2))
    return 0


def cmd_dlhp_schedule(args: argparse.Namespace) -> int:
    secret = base64.b64decode(args.secret) if args.secret else b"demo-master-secret-32-bytes...."[:32]
    schedule = generate_schedule(secret, args.count)
    print(json.dumps(schedule_statistics(schedule), indent=2))
    return 0


def cmd_dlhp_protect(args: argparse.Namespace) -> int:
    secret = base64.b64decode(args.secret) if args.secret else b"demo-master-secret-32-bytes...."[:32]
    payload = args.message.encode("utf-8")
    shares = protect_payload(payload, secret, k=args.k, n=args.n)
    recovered = recover_payload(shares[: args.k], secret, k=args.k)
    output = {
        "threshold": {"k": args.k, "n": args.n},
        "recovered": recovered.decode("utf-8"),
        "shares": json.loads(protected_shares_to_json(shares)),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def cmd_dlhp_unit(args: argparse.Namespace) -> int:
    secret = base64.b64decode(args.secret) if args.secret else b"demo-master-secret-32-bytes...."[:32]
    session_id = args.session_id.encode("utf-8")
    session = DLHPSession(secret, session_id=session_id)
    receiver = DLHPSession(secret, session_id=session_id)
    unit = session.protect_unit(args.seq_id, args.message.encode("utf-8"))
    opened = receiver.open_unit(unit)
    output = {
        "opened": opened.decode("utf-8") if opened is not None else None,
        "unit": unit.to_jsonable(),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def cmd_dlhp_chaff(args: argparse.Namespace) -> int:
    secret = base64.b64decode(args.secret) if args.secret else b"demo-master-secret-32-bytes...."[:32]
    session = DLHPSession(secret, session_id=args.session_id.encode("utf-8"))
    units = generate_chaff_units(session, start_seq_id=args.start_seq_id, count=args.count, payload_size=args.payload_size)
    print(json.dumps({"chaff": [unit.to_jsonable() for unit in units]}, ensure_ascii=False, indent=2))
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    recommendation = recommend_suite(DeploymentProfile(args.profile))
    print(json.dumps(recommendation_to_jsonable(recommendation), ensure_ascii=False, indent=2))
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    serve(host=args.host, port=args.port)
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    output = catalog_to_jsonable(
        kind=args.kind,
        maturity=args.maturity,
        min_security_bits=args.min_security_bits,
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    output = build_security_report(
        profile=args.profile,
        qkd_bytes=args.qkd_bytes,
        qkd_rate=args.qkd_rate,
        qber=args.qber,
        schedule_count=args.schedule_count,
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    output = build_profile_matrix(
        profiles=args.profiles,
        qkd_bytes=args.qkd_bytes,
        qkd_rate=args.qkd_rate,
        qber=args.qber,
        schedule_count=args.schedule_count,
        scoring=_matrix_scoring_from_args(args),
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def cmd_campaign(args: argparse.Namespace) -> int:
    scenarios = parse_scenarios(args.scenario, file_path=args.scenario_file)
    output = build_campaign_report(
        scenarios=scenarios,
        profiles=[profile.value for profile in parse_profiles(args.profiles)],
        scoring=_matrix_scoring_from_args(args),
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def cmd_sweep(args: argparse.Namespace) -> int:
    output = build_profile_sweep(
        profiles=args.profiles,
        qkd_bytes_values=parse_number_series("qkd_bytes", args.qkd_bytes_values, cast=int),
        qkd_rate_values=parse_number_series("qkd_rate", args.qkd_rate_values, cast=float),
        qber_values=parse_number_series("qber", args.qber_values, cast=float, probability=True),
        schedule_count=args.schedule_count,
        scoring=_matrix_scoring_from_args(args),
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qcrypto", description="QCH-KEM and DLHP demonstration toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    qch = sub.add_parser("qch-demo", help="run a QCH-KEM hybrid handshake demo")
    qch.add_argument("--qkd-bytes", type=int, default=64, help="initial QKD buffer bytes")
    qch.add_argument("--qkd-rate", type=float, default=10000.0, help="reported QKD rate in bits/s")
    qch.add_argument("--qber", type=float, default=0.01, help="QKD bit error rate")
    qch.add_argument("--show-key", action="store_true", help="include demo session key in output")
    qch.set_defaults(func=cmd_qch_demo)

    sched = sub.add_parser("dlhp-schedule", help="derive and analyze a DLHP hopping schedule")
    sched.add_argument("--count", type=int, default=20)
    sched.add_argument("--secret", help="base64 master secret")
    sched.set_defaults(func=cmd_dlhp_schedule)

    protect = sub.add_parser("dlhp-protect", help="split, protect, and recover a payload")
    protect.add_argument("message")
    protect.add_argument("--k", type=int, default=3)
    protect.add_argument("--n", type=int, default=5)
    protect.add_argument("--secret", help="base64 master secret")
    protect.set_defaults(func=cmd_dlhp_protect)

    unit = sub.add_parser("dlhp-unit", help="protect and open one DLHP protected unit")
    unit.add_argument("message")
    unit.add_argument("--seq-id", type=int, default=0)
    unit.add_argument("--session-id", default="demo-session")
    unit.add_argument("--secret", help="base64 master secret")
    unit.set_defaults(func=cmd_dlhp_unit)

    chaff = sub.add_parser("dlhp-chaff", help="generate valid-looking decoy protected units")
    chaff.add_argument("--count", type=int, default=3)
    chaff.add_argument("--start-seq-id", type=int, default=1000)
    chaff.add_argument("--payload-size", type=int, default=32)
    chaff.add_argument("--session-id", default="demo-session")
    chaff.add_argument("--secret", help="base64 master secret")
    chaff.set_defaults(func=cmd_dlhp_chaff)

    recommend = sub.add_parser("recommend", help="recommend a post-quantum deployment suite")
    recommend.add_argument(
        "--profile",
        choices=[profile.value for profile in DeploymentProfile],
        default=DeploymentProfile.BALANCED.value,
    )
    recommend.set_defaults(func=cmd_recommend)

    catalog = sub.add_parser("catalog", help="list algorithms in the toolkit catalog")
    catalog.add_argument("--kind", choices=["kem", "signature", "hash_signature", "hybrid", "hopping", "experimental"])
    catalog.add_argument(
        "--maturity",
        choices=[
            "standardized",
            "selected_for_standardization",
            "candidate",
            "legacy_pqc",
            "patent_experimental",
            "research",
            "demonstration",
            "retired",
        ],
    )
    catalog.add_argument("--min-security-bits", type=int)
    catalog.set_defaults(func=cmd_catalog)

    report = sub.add_parser("report", help="build a combined QCH/DLHP/policy JSON report")
    report.add_argument(
        "--profile",
        choices=[profile.value for profile in DeploymentProfile],
        default=DeploymentProfile.BALANCED.value,
    )
    report.add_argument("--qkd-bytes", type=int, default=64)
    report.add_argument("--qkd-rate", type=float, default=10000.0)
    report.add_argument("--qber", type=float, default=0.01)
    report.add_argument("--schedule-count", type=int, default=20)
    report.set_defaults(func=cmd_report)

    matrix = sub.add_parser("matrix", help="compare multiple deployment profiles under the same inputs")
    matrix.add_argument(
        "profiles",
        nargs="*",
        default=[profile.value for profile in DeploymentProfile],
        help="profiles to compare; accepts repeated values or comma-separated lists",
    )
    matrix.add_argument("--qkd-bytes", type=int, default=64)
    matrix.add_argument("--qkd-rate", type=float, default=10000.0)
    matrix.add_argument("--qber", type=float, default=0.01)
    matrix.add_argument("--schedule-count", type=int, default=20)
    matrix.add_argument("--security-weight", type=int, default=30)
    matrix.add_argument("--diversity-weight", type=int, default=10)
    matrix.add_argument("--rotation-weight", type=int, default=4)
    matrix.add_argument("--bandwidth-penalty", type=int, default=1)
    matrix.add_argument("--findings-penalty", type=int, default=3)
    matrix.add_argument("--state-penalty", type=int, default=15)
    matrix.add_argument("--orthogonality-penalty", type=int, default=50)
    matrix.set_defaults(func=cmd_matrix)

    campaign = sub.add_parser("campaign", help="run multiple scenario matrices and aggregate the winners")
    campaign.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="scenario in name:qkd_bytes:qkd_rate:qber:schedule_count format",
    )
    campaign.add_argument(
        "--scenario-file",
        help="path to a JSON campaign file or newline-delimited scenario text",
    )
    campaign.add_argument(
        "--profiles",
        default="balanced,long_term_archive,high_assurance,bandwidth_constrained",
        help="profiles to compare; comma-separated",
    )
    campaign.add_argument("--security-weight", type=int, default=30)
    campaign.add_argument("--diversity-weight", type=int, default=10)
    campaign.add_argument("--rotation-weight", type=int, default=4)
    campaign.add_argument("--bandwidth-penalty", type=int, default=1)
    campaign.add_argument("--findings-penalty", type=int, default=3)
    campaign.add_argument("--state-penalty", type=int, default=15)
    campaign.add_argument("--orthogonality-penalty", type=int, default=50)
    campaign.set_defaults(func=cmd_campaign)

    sweep = sub.add_parser("sweep", help="scan recommendation changes across multiple QKD and QBER conditions")
    sweep.add_argument(
        "profiles",
        nargs="*",
        default=[profile.value for profile in DeploymentProfile],
        help="profiles to compare; accepts repeated values or comma-separated lists",
    )
    sweep.add_argument("--qkd-bytes-values", default="0,8,32,64", help="comma list or start:stop:step")
    sweep.add_argument("--qkd-rate-values", default="0,2000,10000", help="comma list or start:stop:step")
    sweep.add_argument("--qber-values", default="0,0.02,0.08", help="comma list or start:stop:step")
    sweep.add_argument("--schedule-count", type=int, default=20)
    sweep.add_argument("--security-weight", type=int, default=30)
    sweep.add_argument("--diversity-weight", type=int, default=10)
    sweep.add_argument("--rotation-weight", type=int, default=4)
    sweep.add_argument("--bandwidth-penalty", type=int, default=1)
    sweep.add_argument("--findings-penalty", type=int, default=3)
    sweep.add_argument("--state-penalty", type=int, default=15)
    sweep.add_argument("--orthogonality-penalty", type=int, default=50)
    sweep.set_defaults(func=cmd_sweep)

    gui = sub.add_parser("gui", help="start the local web console")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8765)
    gui.set_defaults(func=cmd_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) in {"matrix", "sweep"}:
        args.profiles = [profile.value for profile in parse_profiles(args.profiles)]
    if getattr(args, "command", None) == "campaign":
        args.profiles = [profile.value for profile in parse_profiles([args.profiles])]
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
