from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .policy import DeploymentProfile


def require_non_negative_int(name: str, value: int) -> int:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def require_non_negative_float(name: str, value: float) -> float:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def require_probability(name: str, value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return value


def parse_number_series(
    name: str,
    value: str | None,
    *,
    cast=float,
    probability: bool = False,
) -> list[int] | list[float]:
    if value is None:
        raise ValueError(f"{name} is required")
    text = value.strip()
    if not text:
        raise ValueError(f"{name} is required")

    values: list[int] | list[float] = []
    if ":" in text:
        parts = [part.strip() for part in text.split(":")]
        if len(parts) != 3:
            raise ValueError(f"{name} range must use start:stop:step")
        start = cast(parts[0])
        stop = cast(parts[1])
        step = cast(parts[2])
        if step <= 0:
            raise ValueError(f"{name} step must be positive")
        current = start
        epsilon = 1e-12 if cast is float else 0
        while current <= stop + epsilon:
            values.append(cast(round(current, 6) if cast is float else current))
            current += step
    else:
        for chunk in text.split(","):
            item = chunk.strip()
            if item:
                values.append(cast(item))

    if not values:
        raise ValueError(f"{name} must contain at least one value")

    normalized: list[int] | list[float] = []
    for item in values:
        if cast is int:
            normalized.append(require_non_negative_int(name, int(item)))
        else:
            number = float(item)
            if probability:
                normalized.append(require_probability(name, number))
            else:
                normalized.append(require_non_negative_float(name, number))
    return normalized


def parse_profiles(values: Iterable[str] | None = None) -> list[DeploymentProfile]:
    if values is None:
        return list(DeploymentProfile)

    parsed: list[DeploymentProfile] = []
    seen: set[DeploymentProfile] = set()
    for raw_value in values:
        for chunk in raw_value.split(","):
            value = chunk.strip()
            if not value:
                continue
            profile = DeploymentProfile(value)
            if profile not in seen:
                parsed.append(profile)
                seen.add(profile)
    return parsed or list(DeploymentProfile)


def normalize_scenario(raw: dict) -> dict:
    name = str(raw.get("name", "")).strip()
    if not name:
        raise ValueError("scenario name is required")
    return {
        "name": name,
        "qkd_bytes": require_non_negative_int("qkd_bytes", int(raw.get("qkd_bytes", 64))),
        "qkd_rate": require_non_negative_float("qkd_rate", float(raw.get("qkd_rate", 10000.0))),
        "qber": require_probability("qber", float(raw.get("qber", 0.01))),
        "schedule_count": require_non_negative_int("schedule_count", int(raw.get("schedule_count", 20))),
    }


def parse_scenario_text(value: str) -> dict:
    parts = value.split(":")
    if len(parts) != 5:
        raise ValueError("scenario must use name:qkd_bytes:qkd_rate:qber:schedule_count")
    name, qkd_bytes, qkd_rate, qber, schedule_count = parts
    return normalize_scenario(
        {
            "name": name,
            "qkd_bytes": qkd_bytes,
            "qkd_rate": qkd_rate,
            "qber": qber,
            "schedule_count": schedule_count,
        }
    )


def parse_scenarios(values: Iterable[str] | None = None, *, file_path: str | None = None) -> list[dict]:
    scenarios: list[dict] = []

    if file_path:
        try:
            text = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"unable to read scenario file: {exc}") from exc
        try:
            stripped = text.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                payload = json.loads(text)
                items = payload.get("scenarios") if isinstance(payload, dict) else payload
                if not isinstance(items, list):
                    raise ValueError("scenario file must contain a JSON array or an object with a scenarios array")
                for item in items:
                    if not isinstance(item, dict):
                        raise ValueError("each JSON scenario must be an object")
                    scenarios.append(normalize_scenario(item))
            else:
                for line in text.splitlines():
                    raw = line.strip()
                    if raw and not raw.startswith("#"):
                        scenarios.append(parse_scenario_text(raw))
        except json.JSONDecodeError as exc:
            raise ValueError(f"scenario file contains invalid JSON: {exc.msg}") from exc

    for raw_value in values or ():
        for line in str(raw_value).splitlines():
            value = line.strip()
            if value:
                scenarios.append(parse_scenario_text(value))

    if not scenarios:
        raise ValueError("at least one scenario is required")
    return scenarios
