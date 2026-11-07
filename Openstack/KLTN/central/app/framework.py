"""Pure contracts and policies for scores, fusion, lifecycle and response gates."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from typing import Any

SCORE_SCHEMA = "score.v1"
SCORE_BRANCHES = {"host_ml", "network_dl"}
READY_STATES = {"ready_shadow", "ready_active"}
ALL_SCORE_STATES = READY_STATES | {
    "waiting_for_model", "incompatible_schema", "unsupported_domain",
    "warming_context", "error",
}
REVIEW_DECISIONS = {"confirmed", "false_positive", "needs_review", "dismissed"}
RESPONSE_ACTIONS = {"quarantine_network", "release_network", "collect_evidence"}
REGISTRY_STAGES = {"candidate", "validated", "canary", "active", "retired", "rolled_back"}


class ContractError(ValueError):
    pass


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()
    return hashlib.sha256(data).hexdigest()


def parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ContractError(f"{field} must be an ISO-8601 string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ContractError(f"{field} is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{field} must contain a timezone")
    return parsed.astimezone(timezone.utc)


def _probability(value: Any, field: str, nullable: bool = False) -> float | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise ContractError(f"{field} must be finite and within [0,1]")
    return number


def validate_score(payload: Any, authenticated_host: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ContractError("score must be an object")
    if payload.get("schema_version") != SCORE_SCHEMA:
        raise ContractError("unsupported score schema")
    host_id = payload.get("host_id")
    if not isinstance(host_id, str) or not 1 <= len(host_id) <= 256:
        raise ContractError("invalid host_id")
    if authenticated_host is not None and host_id != authenticated_host:
        raise ContractError("credential cannot submit scores for another host")
    branch = payload.get("branch")
    if branch not in SCORE_BRANCHES:
        raise ContractError("unsupported branch")
    status = payload.get("status")
    if status not in ALL_SCORE_STATES:
        raise ContractError("unsupported score status")
    bundle_id = payload.get("bundle_id")
    if not isinstance(bundle_id, str) or not 1 <= len(bundle_id) <= 256:
        raise ContractError("invalid bundle_id")
    domain = payload.get("domain")
    if not isinstance(domain, str) or not 1 <= len(domain) <= 128:
        raise ContractError("invalid domain")
    validation = payload.get("domain_validation")
    if validation not in {"validated", "shadow_unvalidated", "unsupported"}:
        raise ContractError("invalid domain_validation")
    refs = payload.get("event_refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 512 or any(
            not isinstance(ref, str) or not 1 <= len(ref) <= 128 for ref in refs):
        raise ContractError("event_refs must contain 1..512 identifiers")
    if len(refs) != len(set(refs)):
        raise ContractError("event_refs must be unique")
    processed_at = parse_time(payload.get("processed_at"), "processed_at")
    score = _probability(payload.get("score"), "score", nullable=True)
    threshold = _probability(payload.get("threshold"), "threshold", nullable=True)
    prediction = payload.get("prediction")
    if prediction is not None and (isinstance(prediction, bool) or prediction not in (0, 1)):
        raise ContractError("prediction must be 0, 1 or null")
    if status in READY_STATES:
        if score is None or threshold is None or prediction is None:
            raise ContractError("ready score requires score, threshold and prediction")
        if prediction != int(score >= threshold):
            raise ContractError("prediction does not match score >= threshold")
    elif any(value is not None for value in (score, threshold, prediction)):
        raise ContractError("unavailable branch must use null score/threshold/prediction")
    window = payload.get("window")
    if window is not None:
        if not isinstance(window, dict):
            raise ContractError("window must be an object or null")
        start = parse_time(window.get("start"), "window.start")
        end = parse_time(window.get("end"), "window.end")
        if start >= end or end - start > timedelta(hours=24):
            raise ContractError("invalid score window")
        window = {**window, "start": start.isoformat(), "end": end.isoformat()}
    evidence = payload.get("evidence", {})
    if not isinstance(evidence, dict):
        raise ContractError("evidence must be an object")
    normalized = {
        "schema_version": SCORE_SCHEMA,
        "host_id": host_id,
        "branch": branch,
        "bundle_id": bundle_id,
        "event_refs": refs,
        "window": window,
        "status": status,
        "score": score,
        "threshold": threshold,
        "prediction": prediction,
        "domain": domain,
        "domain_validation": validation,
        "processed_at": processed_at,
        "evidence": evidence,
    }
    normalized["score_id"] = canonical_hash([
        SCORE_SCHEMA, host_id, branch, bundle_id, refs, window, processed_at.isoformat()
    ])
    return normalized


FUSION_POLICY = {
    "version": "fusion-calibrated-v1",
    "algorithm": "availability-gated-weighted-risk",
    "threshold": 0.75,
    "weights": {"host_ml": 0.55, "network_dl": 0.45},
    "bucket_seconds": 900,
    "calibrated_source": "ATLASv2 paired validation grid search",
}


def fuse_scores(rows: list[dict[str, Any]], bucket_start: datetime) -> dict[str, Any]:
    """Fuse the newest usable score for each branch with explicit source masks.

    This is the safe shadow fallback until a separately validated learned
    gating/cross-attention bundle is registered.  It does not pretend that a
    missing branch emitted a benign score.
    """
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("status") not in READY_STATES or row.get("score") is None:
            continue
        previous = latest.get(row["branch"])
        if previous is None or row["processed_at"] > previous["processed_at"]:
            latest[row["branch"]] = row
    mask = {branch: branch in latest for branch in sorted(SCORE_BRANCHES)}
    if not latest:
        raise ContractError("no usable scores to fuse")
    weighted = [(FUSION_POLICY["weights"][branch], float(row["score"]))
                for branch, row in latest.items()]
    weight_sum = sum(weight for weight, _ in weighted)
    risk = sum(weight * score for weight, score in weighted) / weight_sum
    risk = min(1.0, max(0.0, risk))
    bucket_end = bucket_start + timedelta(seconds=FUSION_POLICY["bucket_seconds"])
    score_refs = sorted(row["score_id"] for row in latest.values())
    fusion_id = canonical_hash([
        "fusion.v1", rows[0]["host_id"], bucket_start.isoformat(),
        FUSION_POLICY["version"], score_refs,
    ])
    return {
        "fusion_id": fusion_id,
        "host_id": rows[0]["host_id"],
        "bucket_start": bucket_start,
        "bucket_end": bucket_end,
        "algorithm": FUSION_POLICY["algorithm"],
        "policy_version": FUSION_POLICY["version"],
        "risk_score": risk,
        "threshold": FUSION_POLICY["threshold"],
        "prediction": int(risk >= FUSION_POLICY["threshold"]),
        "source_mask": mask,
        "score_refs": score_refs,
        "evidence": {
            "branches": {branch: {
                "score": row["score"], "bundle_id": row["bundle_id"],
                "domain_validation": row["domain_validation"],
                "event_refs": row["event_refs"],
            } for branch, row in latest.items()},
            "limitation": "shadow deterministic fallback; learned fusion not yet validated",
        },
    }


def alert_severity(risk: float) -> str:
    if risk >= 0.95:
        return "critical"
    if risk >= 0.85:
        return "high"
    return "medium"


def population_stability_index(reference: dict[str, int], current: dict[str, int]) -> float | None:
    """Finite categorical PSI; returns None when either sample is empty."""
    ref_total, cur_total = sum(reference.values()), sum(current.values())
    if ref_total <= 0 or cur_total <= 0:
        return None
    keys = set(reference) | set(current)
    epsilon = 1e-6
    result = 0.0
    for key in keys:
        expected = max(epsilon, reference.get(key, 0) / ref_total)
        actual = max(epsilon, current.get(key, 0) / cur_total)
        result += (actual - expected) * math.log(actual / expected)
    return float(result)
