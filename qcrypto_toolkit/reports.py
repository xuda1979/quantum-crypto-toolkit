from __future__ import annotations

from dataclasses import asdict, dataclass

from .dlhp import AlgorithmProfile, generate_schedule, schedule_statistics
from .models import AlgorithmKind, Maturity
from .policy import DeploymentProfile, recommendation_to_jsonable, recommend_suite
from .qch_kem import QCHKEM, QKDKeyBuffer, SyncController
from .registry import DEFAULT_REGISTRY
from .validation import parse_profiles, require_non_negative_float, require_non_negative_int, require_probability


DEMO_MASTER = b"demo-master-secret-32-bytes...."[:32]
_QCH_PROFILE_TUNING = {
    DeploymentProfile.BALANCED: {
        "target_security_bits": 256,
        "qkd_contribution_cap_bits": 128,
        "min_qkd_bytes": 16,
    },
    DeploymentProfile.HIGH_ASSURANCE: {
        "target_security_bits": 320,
        "qkd_contribution_cap_bits": 128,
        "min_qkd_bytes": 24,
    },
    DeploymentProfile.BANDWIDTH_CONSTRAINED: {
        "target_security_bits": 224,
        "qkd_contribution_cap_bits": 128,
        "min_qkd_bytes": 8,
    },
    DeploymentProfile.LONG_TERM_ARCHIVE: {
        "target_security_bits": 320,
        "qkd_contribution_cap_bits": 128,
        "min_qkd_bytes": 24,
    },
    DeploymentProfile.EXPERIMENTAL_DIVERSITY: {
        "target_security_bits": 256,
        "qkd_contribution_cap_bits": 96,
        "min_qkd_bytes": 16,
    },
}


@dataclass(frozen=True)
class MatrixScoring:
    security_weight: int = 30
    diversity_weight: int = 10
    rotation_weight: int = 4
    bandwidth_penalty: int = 1
    findings_penalty: int = 3
    state_penalty: int = 15
    orthogonality_penalty: int = 50


def normalize_matrix_scoring(scoring: dict | None = None) -> MatrixScoring:
    values = MatrixScoring()
    if scoring is None:
        return values
    payload = asdict(values)
    for key, value in scoring.items():
        if key not in payload:
            raise ValueError(f"unknown scoring parameter: {key}")
        payload[key] = require_non_negative_int(key, int(value))
    return MatrixScoring(**payload)


def _kind_from_text(value: str | None) -> AlgorithmKind | None:
    if value is None:
        return None
    return AlgorithmKind(value)


def _maturity_from_text(value: str | None) -> Maturity | None:
    if value is None:
        return None
    return Maturity(value)


def catalog_to_jsonable(
    *,
    kind: str | None = None,
    maturity: str | None = None,
    min_security_bits: int | None = None,
) -> dict:
    if min_security_bits is not None:
        require_non_negative_int("min_security_bits", min_security_bits)
    algorithms = DEFAULT_REGISTRY.list(
        kind=_kind_from_text(kind),
        maturity=_maturity_from_text(maturity),
        min_security_bits=min_security_bits,
    )
    entries = [
        {
            "name": item.name,
            "aliases": list(item.aliases),
            "kind": item.kind.value,
            "hard_problem_class": item.hard_problem_class,
            "security_bits": item.security_bits,
            "maturity": item.maturity.value,
            "public_key_bytes": item.public_key_bytes,
            "secret_key_bytes": item.secret_key_bytes,
            "ciphertext_bytes": item.ciphertext_bytes,
            "signature_bytes": item.signature_bytes,
            "preferred_path": item.preferred_path,
            "tags": list(item.tags),
            "notes": item.notes,
        }
        for item in algorithms
    ]
    return {
        "count": len(entries),
        "filters": {
            "kind": kind,
            "maturity": maturity,
            "min_security_bits": min_security_bits,
        },
        "algorithms": entries,
    }


def _controller_for_profile(profile: DeploymentProfile) -> SyncController:
    return SyncController(**_QCH_PROFILE_TUNING[profile])


def _rotation_library(profile: DeploymentProfile) -> tuple[tuple[str, ...], list[AlgorithmProfile]]:
    allowed = recommend_suite(profile).dlhp_allowed
    library = [
        AlgorithmProfile(
            name=descriptor.name,
            algorithm_id=index,
            hard_problem_class=descriptor.hard_problem_class,
            security_bits=descriptor.security_bits,
            preferred_path=descriptor.preferred_path,
        )
        for index, descriptor in enumerate((DEFAULT_REGISTRY.get(name) for name in allowed), start=1)
    ]
    return allowed, library


def schedule_to_jsonable(
    count: int,
    master_secret: bytes = DEMO_MASTER,
    library: list[AlgorithmProfile] | None = None,
) -> dict:
    require_non_negative_int("count", count)
    schedule = generate_schedule(master_secret, count, library=library)
    return {
        "statistics": schedule_statistics(schedule),
        "hops": [
            {
                "seq_id": hop.seq_id,
                "selection_counter": hop.selection_counter,
                "algorithm": hop.algorithm.name,
                "hard_problem_class": hop.algorithm.hard_problem_class,
                "preferred_path": hop.algorithm.preferred_path,
                "retries": hop.retries,
            }
            for hop in schedule
        ],
    }


def build_security_report(
    *,
    profile: str = DeploymentProfile.BALANCED.value,
    qkd_bytes: int = 64,
    qkd_rate: float = 10000.0,
    qber: float = 0.01,
    schedule_count: int = 20,
) -> dict:
    require_non_negative_int("qkd_bytes", qkd_bytes)
    require_non_negative_float("qkd_rate", qkd_rate)
    require_probability("qber", qber)
    require_non_negative_int("schedule_count", schedule_count)
    selected_profile = DeploymentProfile(profile)
    recommendation = recommend_suite(selected_profile)
    policy = recommendation_to_jsonable(recommendation)
    rotation_names, rotation_library = _rotation_library(selected_profile)
    qch = QCHKEM(controller=_controller_for_profile(selected_profile)).establish(
        QKDKeyBuffer.seeded(qkd_bytes),
        qkd_rate_bps=qkd_rate,
        qber=qber,
    ).to_jsonable(include_session_key=False)
    schedule = schedule_to_jsonable(schedule_count, library=rotation_library)
    findings = [
        {
            "severity": "warning",
            "code": "demo_crypto",
            "message": "Current adapters model protocol mechanics; replace KEM/QKD/DEM components before production deployment.",
        },
        {
            "severity": "info",
            "code": "secret_handling",
            "message": "Production deployments need key erasure, side-channel controls, secure storage, and transport binding.",
        },
    ]
    if qch["state"] == "FALLBACK":
        findings.append(
            {
                "severity": "warning",
                "code": "qkd_fallback",
                "message": "QKD was unavailable or unhealthy; validate fallback policy and alerting.",
            }
        )
    if schedule["statistics"].get("orthogonality_violations", 0) > 0:
        findings.append(
            {
                "severity": "critical",
                "code": "orthogonality",
                "message": "DLHP schedule contains adjacent hard-problem class violations.",
            }
        )

    return {
        "profile": selected_profile.value,
        "inputs": {
            "qkd_bytes": qkd_bytes,
            "qkd_rate": qkd_rate,
            "qber": qber,
            "schedule_count": schedule_count,
        },
        "summary": {
            "production_ready": False,
            "findings": findings,
        },
        "policy": policy,
        "qch": qch,
        "dlhp": {
            "rotation": {
                "allowed_algorithms": list(rotation_names),
                "hard_problem_classes": [item.hard_problem_class for item in rotation_library],
                "preferred_paths": [item.preferred_path for item in rotation_library],
            },
            "schedule": schedule["statistics"],
            "hops_preview": schedule["hops"][: min(10, len(schedule["hops"]))],
        },
    }


def build_profile_matrix(
    *,
    profiles: list[str] | tuple[str, ...] | None = None,
    qkd_bytes: int = 64,
    qkd_rate: float = 10000.0,
    qber: float = 0.01,
    schedule_count: int = 20,
    scoring: dict | None = None,
) -> dict:
    selected_profiles = parse_profiles(profiles)
    scoring_model = normalize_matrix_scoring(scoring)
    rows = []
    for profile_item in selected_profiles:
        report = build_security_report(
            profile=profile_item.value,
            qkd_bytes=qkd_bytes,
            qkd_rate=qkd_rate,
            qber=qber,
            schedule_count=schedule_count,
        )
        rows.append(
            {
                "profile": profile_item.value,
                "kem_primary": report["policy"]["kem"]["primary"],
                "qch_profile": report["qch"]["pqc_profile"],
                "qch_state": report["qch"]["state"],
                "qkd_key_bytes": report["qch"]["qkd_key_bytes"],
                "bandwidth_bytes": report["qch"]["bandwidth_bytes"],
                "allowed_algorithms": report["dlhp"]["rotation"]["allowed_algorithms"],
                "dlhp_rotation_size": len(report["dlhp"]["rotation"]["allowed_algorithms"]),
                "entropy_bits": report["dlhp"]["schedule"].get("entropy_bits", 0.0),
                "orthogonality_violations": report["dlhp"]["schedule"].get("orthogonality_violations", 0),
                "findings": [item["code"] for item in report["summary"]["findings"]],
                "hops_preview": report["dlhp"]["hops_preview"],
            }
        )
    for row in rows:
        row["score_breakdown"] = _matrix_score_breakdown(row, scoring_model)
        row["score"] = sum(row["score_breakdown"].values())
    rows.sort(key=lambda item: (-item["score"], item["bandwidth_bytes"], item["profile"]))
    for index, row in enumerate(rows, start=1):
        row["rank"] = index
        row["recommended"] = index == 1
    best_security = max(rows, key=lambda item: _security_rank(item["qch_profile"]))
    best_bandwidth = min(rows, key=lambda item: item["bandwidth_bytes"])
    best_diversity = max(rows, key=lambda item: (item["entropy_bits"], item["dlhp_rotation_size"]))
    return {
        "profiles": [item.value for item in selected_profiles],
        "inputs": {
            "qkd_bytes": qkd_bytes,
            "qkd_rate": qkd_rate,
            "qber": qber,
            "schedule_count": schedule_count,
        },
        "scoring": asdict(scoring_model),
        "rows": rows,
        "summary": {
            "best_security_profile": best_security["profile"],
            "best_bandwidth_profile": best_bandwidth["profile"],
            "best_diversity_profile": best_diversity["profile"],
            "recommended_profile": rows[0]["profile"] if rows else None,
            "sorting": {
                "mode": "score_desc",
                "tiebreakers": ["bandwidth_asc", "profile_asc"],
            },
            "tradeoffs": [
                {
                    "profile": row["profile"],
                    "headline": _matrix_tradeoff(row, best_security, best_bandwidth, best_diversity),
                }
                for row in rows
            ],
        },
    }


def build_campaign_report(
    *,
    scenarios: list[dict],
    profiles: list[str] | tuple[str, ...] | None = None,
    scoring: dict | None = None,
) -> dict:
    if not scenarios:
        raise ValueError("at least one scenario is required")

    selected_profiles = [profile.value for profile in parse_profiles(profiles)]
    scoring_model = normalize_matrix_scoring(scoring)
    results = []
    aggregate: dict[str, dict] = {
        profile: {
            "profile": profile,
            "scenario_wins": 0,
            "total_score": 0,
            "average_score": 0.0,
            "average_rank": 0.0,
            "fallback_count": 0,
            "states": {},
            "best_scenario": None,
            "worst_scenario": None,
            "score_breakdown_totals": {
                "security": 0,
                "diversity": 0,
                "rotation": 0,
                "orthogonality": 0,
                "bandwidth": 0,
                "findings": 0,
                "state": 0,
            },
            "recommended_in": [],
            "resilience": "steady",
            "why_it_wins": [],
            "why_it_loses": [],
            "campaign_headline": "",
        }
        for profile in selected_profiles
    }

    for raw in scenarios:
        name = raw.get("name")
        if not name:
            raise ValueError("scenario name is required")
        matrix = build_profile_matrix(
            profiles=selected_profiles,
            qkd_bytes=int(raw.get("qkd_bytes", 64)),
            qkd_rate=float(raw.get("qkd_rate", 10000.0)),
            qber=float(raw.get("qber", 0.01)),
            schedule_count=int(raw.get("schedule_count", 20)),
            scoring=asdict(scoring_model),
        )
        winner = matrix["summary"]["recommended_profile"]
        for row in matrix["rows"]:
            stats = aggregate[row["profile"]]
            stats["total_score"] += row["score"]
            stats["average_rank"] += row["rank"]
            stats["fallback_count"] += 1 if row["qch_state"] == "FALLBACK" else 0
            stats["states"][row["qch_state"]] = stats["states"].get(row["qch_state"], 0) + 1
            for key, value in row["score_breakdown"].items():
                stats["score_breakdown_totals"][key] += value
            _update_campaign_extremes(stats, row=row, scenario_name=name)
            if row["profile"] == winner:
                stats["scenario_wins"] += 1
                stats["recommended_in"].append(name)
        results.append(
            {
                "name": name,
                "inputs": matrix["inputs"],
                "summary": {
                    "recommended_profile": winner,
                    "best_security_profile": matrix["summary"]["best_security_profile"],
                    "best_bandwidth_profile": matrix["summary"]["best_bandwidth_profile"],
                    "best_diversity_profile": matrix["summary"]["best_diversity_profile"],
                    "ranked_profiles": [row["profile"] for row in matrix["rows"]],
                },
                "matrix": matrix,
            }
        )

    ordered_profiles = []
    for profile in selected_profiles:
        stats = aggregate[profile]
        stats["average_score"] = round(stats["total_score"] / len(results), 6)
        stats["average_rank"] = round(stats["average_rank"] / len(results), 6)
        stats["score_breakdown_average"] = {
            key: round(value / len(results), 6) for key, value in stats["score_breakdown_totals"].items()
        }
        stats["state_mix"] = _campaign_state_mix(stats["states"], len(results))
        stats["resilience"] = _campaign_resilience_label(stats, len(results))
        stats["why_it_wins"] = _campaign_strengths(stats)
        stats["why_it_loses"] = _campaign_weaknesses(stats, len(results))
        stats["campaign_headline"] = _campaign_headline(stats)
        ordered_profiles.append(stats)
    ordered_profiles.sort(key=lambda item: (-item["scenario_wins"], -item["average_score"], item["fallback_count"], item["profile"]))

    leader = ordered_profiles[0]

    return {
        "scenario_count": len(results),
        "profiles": selected_profiles,
        "scoring": asdict(scoring_model),
        "scenarios": results,
        "aggregate": {
            "leader": leader["profile"],
            "leader_headline": leader["campaign_headline"],
            "profiles": ordered_profiles,
            "scenario_names": [item["name"] for item in results],
        },
    }


def build_profile_sweep(
    *,
    profiles: list[str] | tuple[str, ...] | None = None,
    qkd_bytes_values: list[int] | tuple[int, ...] | None = None,
    qkd_rate_values: list[float] | tuple[float, ...] | None = None,
    qber_values: list[float] | tuple[float, ...] | None = None,
    schedule_count: int = 20,
    scoring: dict | None = None,
) -> dict:
    selected_profiles = [item.value for item in parse_profiles(profiles)]
    qkd_bytes_points = _normalize_sweep_series("qkd_bytes_values", qkd_bytes_values or [0, 8, 32, 64], cast=int)
    qkd_rate_points = _normalize_sweep_series("qkd_rate_values", qkd_rate_values or [0.0, 2000.0, 10000.0], cast=float)
    qber_points = _normalize_sweep_series("qber_values", qber_values or [0.0, 0.02, 0.08], cast=float, probability=True)
    require_non_negative_int("schedule_count", schedule_count)
    scoring_model = normalize_matrix_scoring(scoring)

    points = []
    profile_stats: dict[str, dict] = {
        profile: {
            "profile": profile,
            "leader_count": 0,
            "average_score": 0.0,
            "average_rank": 0.0,
            "normal_count": 0,
            "fallback_count": 0,
            "leader_points": [],
        }
        for profile in selected_profiles
    }
    transition_points = []
    last_leader_by_lane: dict[tuple[int, float], str] = {}

    point_id = 0
    for qkd_bytes in qkd_bytes_points:
        for qkd_rate in qkd_rate_points:
            lane = (qkd_bytes, qkd_rate)
            previous_leader = None
            for qber in qber_points:
                matrix = build_profile_matrix(
                    profiles=selected_profiles,
                    qkd_bytes=qkd_bytes,
                    qkd_rate=qkd_rate,
                    qber=qber,
                    schedule_count=schedule_count,
                    scoring=asdict(scoring_model),
                )
                leader = matrix["summary"]["recommended_profile"]
                point = {
                    "id": f"pt-{point_id}",
                    "inputs": matrix["inputs"],
                    "leader": leader,
                    "best_security_profile": matrix["summary"]["best_security_profile"],
                    "best_bandwidth_profile": matrix["summary"]["best_bandwidth_profile"],
                    "best_diversity_profile": matrix["summary"]["best_diversity_profile"],
                    "matrix": matrix,
                }
                point_id += 1
                points.append(point)

                if previous_leader is not None and previous_leader != leader:
                    transition_points.append(
                        {
                            "lane": {
                                "qkd_bytes": qkd_bytes,
                                "qkd_rate": qkd_rate,
                            },
                            "from_profile": previous_leader,
                            "to_profile": leader,
                            "at_qber": qber,
                        }
                    )
                previous_leader = leader
                last_leader_by_lane[lane] = leader

                for row in matrix["rows"]:
                    stats = profile_stats[row["profile"]]
                    stats["average_score"] += row["score"]
                    stats["average_rank"] += row["rank"]
                    stats["normal_count"] += 1 if row["qch_state"] == "NORMAL" else 0
                    stats["fallback_count"] += 1 if row["qch_state"] == "FALLBACK" else 0
                    if row["profile"] == leader:
                        stats["leader_count"] += 1
                        stats["leader_points"].append(
                            {
                                "qkd_bytes": qkd_bytes,
                                "qkd_rate": qkd_rate,
                                "qber": qber,
                            }
                        )

    total_points = len(points)
    ordered_profiles = []
    for profile in selected_profiles:
        stats = profile_stats[profile]
        stats["average_score"] = round(stats["average_score"] / total_points, 6)
        stats["average_rank"] = round(stats["average_rank"] / total_points, 6)
        stats["normal_ratio"] = round(stats["normal_count"] / total_points, 6)
        stats["fallback_ratio"] = round(stats["fallback_count"] / total_points, 6)
        stats["coverage_ratio"] = round(stats["leader_count"] / total_points, 6)
        stats["headline"] = _sweep_profile_headline(stats)
        ordered_profiles.append(stats)
    ordered_profiles.sort(key=lambda item: (-item["leader_count"], item["average_rank"], -item["average_score"], item["profile"]))

    leader_map = {}
    for point in points:
        leader_map.setdefault(point["leader"], 0)
        leader_map[point["leader"]] += 1

    primary_leader = ordered_profiles[0]["profile"] if ordered_profiles else None
    return {
        "profiles": selected_profiles,
        "sweep": {
            "qkd_bytes_values": qkd_bytes_points,
            "qkd_rate_values": qkd_rate_points,
            "qber_values": qber_points,
            "schedule_count": schedule_count,
        },
        "scoring": asdict(scoring_model),
        "points": points,
        "summary": {
            "point_count": total_points,
            "primary_leader": primary_leader,
            "leader_counts": leader_map,
            "transition_count": len(transition_points),
            "transitions": transition_points,
            "profiles": ordered_profiles,
        },
    }


def _security_rank(profile_name: str) -> int:
    order = {
        "ML-KEM-512": 1,
        "ML-KEM-768": 2,
        "ML-KEM-1024": 3,
    }
    return order.get(profile_name, 0)


def _matrix_tradeoff(row: dict, best_security: dict, best_bandwidth: dict, best_diversity: dict) -> str:
    labels = []
    if row["profile"] == best_security["profile"]:
        labels.append("max security margin")
    if row["profile"] == best_bandwidth["profile"]:
        labels.append("lowest bandwidth")
    if row["profile"] == best_diversity["profile"]:
        labels.append("widest DLHP diversity")
    if not labels:
        labels.append("middle-ground trade-off")
    return ", ".join(labels)


def _matrix_score_breakdown(row: dict, scoring: MatrixScoring) -> dict[str, int]:
    return {
        "security": _security_rank(row["qch_profile"]) * scoring.security_weight,
        "diversity": min(int(round(row["entropy_bits"] * scoring.diversity_weight)), 30),
        "rotation": min(row["dlhp_rotation_size"] * scoring.rotation_weight, 24),
        "orthogonality": -(row["orthogonality_violations"] * scoring.orthogonality_penalty),
        "bandwidth": -min((row["bandwidth_bytes"] // 512) * scoring.bandwidth_penalty, 24 * max(scoring.bandwidth_penalty, 1)),
        "findings": -(len(row["findings"]) * scoring.findings_penalty),
        "state": 0 if row["qch_state"] == "NORMAL" else -scoring.state_penalty,
    }


def _update_campaign_extremes(stats: dict, *, row: dict, scenario_name: str) -> None:
    snapshot = {
        "name": scenario_name,
        "score": row["score"],
        "rank": row["rank"],
        "qch_state": row["qch_state"],
        "bandwidth_bytes": row["bandwidth_bytes"],
        "qch_profile": row["qch_profile"],
    }
    best = stats["best_scenario"]
    worst = stats["worst_scenario"]
    if best is None or snapshot["score"] > best["score"] or (
        snapshot["score"] == best["score"] and snapshot["rank"] < best["rank"]
    ):
        stats["best_scenario"] = snapshot
    if worst is None or snapshot["score"] < worst["score"] or (
        snapshot["score"] == worst["score"] and snapshot["rank"] > worst["rank"]
    ):
        stats["worst_scenario"] = snapshot


def _campaign_state_mix(states: dict[str, int], scenario_count: int) -> list[dict]:
    order = ("NORMAL", "RECOVERY", "DEGRADED", "FALLBACK")
    return [
        {
            "state": name,
            "count": states.get(name, 0),
            "ratio": round(states.get(name, 0) / scenario_count, 6) if scenario_count else 0.0,
        }
        for name in order
        if states.get(name, 0)
    ]


def _campaign_resilience_label(stats: dict, scenario_count: int) -> str:
    fallback_ratio = stats["fallback_count"] / scenario_count
    normal_ratio = stats["states"].get("NORMAL", 0) / scenario_count
    if fallback_ratio == 0 and normal_ratio >= 0.8:
        return "resilient"
    if fallback_ratio <= 0.25:
        return "steady"
    if fallback_ratio < 0.5:
        return "fragile"
    return "fallback-heavy"


def _campaign_strengths(stats: dict) -> list[str]:
    strengths = []
    if stats["scenario_wins"] > 0:
        strengths.append(f"wins {stats['scenario_wins']} scenarios")
    if stats["average_rank"] <= 1.5:
        strengths.append("stays near the top across conditions")
    if stats["fallback_count"] == 0:
        strengths.append("avoids fallback entirely")
    if stats["score_breakdown_average"]["security"] > stats["score_breakdown_average"]["bandwidth"] * -1:
        strengths.append("security weighting dominates penalties")
    return strengths[:3] or ["competitive average score"]


def _campaign_weaknesses(stats: dict, scenario_count: int) -> list[str]:
    weaknesses = []
    if stats["fallback_count"] > 0:
        weaknesses.append(f"falls back in {stats['fallback_count']} of {scenario_count} scenarios")
    if stats["average_rank"] >= 2.5:
        weaknesses.append("rarely leads the matrix")
    if stats["score_breakdown_average"]["bandwidth"] < -8:
        weaknesses.append("bandwidth cost drags aggregate score")
    if stats["score_breakdown_average"]["state"] < 0:
        weaknesses.append("state penalties reduce consistency")
    return weaknesses[:3]


def _campaign_headline(stats: dict) -> str:
    best = stats["best_scenario"]["name"] if stats["best_scenario"] else "-"
    worst = stats["worst_scenario"]["name"] if stats["worst_scenario"] else "-"
    return (
        f"{stats['resilience']} profile, avg rank {stats['average_rank']}, "
        f"best in {best}, weakest in {worst}"
    )


def _normalize_sweep_series(
    name: str,
    values: list[int] | tuple[int, ...] | list[float] | tuple[float, ...],
    *,
    cast,
    probability: bool = False,
) -> list[int] | list[float]:
    if not values:
        raise ValueError(f"{name} must contain at least one value")
    normalized = []
    for item in values:
        if cast is int:
            normalized.append(require_non_negative_int(name, int(item)))
        else:
            number = float(item)
            if probability:
                normalized.append(require_probability(name, number))
            else:
                normalized.append(require_non_negative_float(name, number))
    deduped = []
    for item in normalized:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _sweep_profile_headline(stats: dict) -> str:
    return (
        f"leads {stats['leader_count']} points, avg rank {stats['average_rank']}, "
        f"fallback {round(stats['fallback_ratio'] * 100)}%"
    )
