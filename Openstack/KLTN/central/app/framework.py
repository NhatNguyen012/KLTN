"""Pure contracts and policies: score validation, context-aware fusion, drift metrics, review/response vocabularies."""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
from typing import Any

SCORE_SCHEMA = "score.v1"
SUMMARY_SCHEMA = "summary.v1"
SCORE_BRANCHES = {"host_ml", "host_dl"}
READY_STATES = {"ready_shadow", "ready_active"}
ALL_SCORE_STATES = READY_STATES | {"waiting_for_model", "incompatible_bundle", "unsupported_domain", "warming_context",
                                   "error"}
VALIDATION = {"validated", "shadow_unvalidated", "unsupported"}
REVIEW_DECISIONS = {"confirmed", "false_positive", "needs_review", "dismissed"}
RESPONSE_ACTIONS = {"quarantine_network", "release_network", "collect_evidence"}
REGISTRY_STAGES = {"candidate", "validated", "canary", "active", "retired", "rolled_back"}


APPROVAL_POLICIES = {"two_person", "single_operator"}


class ContractError(ValueError):
    pass


def approval_allowed(policy: str, requested_by: str, approved_by: str) -> bool:
    """Response approval rule. two_person: the approver must be someone else (case/blank-insensitive). single_operator
    (closed research lab, the owner's choice): the requester may approve their own request. Either way the approval
    is an explicit, named, recorded step and network actions still need a confirmed SOC review."""
    if policy not in APPROVAL_POLICIES:
        raise ContractError(f"unknown approval policy {policy!r}")
    return policy == "single_operator" or requested_by.strip().lower() != approved_by.strip().lower()


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
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


def _bounded_str(payload, key, maximum=256):
    v = payload.get(key)
    if not isinstance(v, str) or not 1 <= len(v) <= maximum:
        raise ContractError(f"invalid {key}")
    return v


def validate_score(payload: Any, authenticated_host: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ContractError("score must be an object")
    if payload.get("schema_version") != SCORE_SCHEMA:
        raise ContractError("unsupported score schema")
    host_id = _bounded_str(payload, "host_id")
    if authenticated_host is not None and host_id != authenticated_host:
        raise ContractError("credential cannot submit scores for another host")
    branch = payload.get("branch")
    if branch not in SCORE_BRANCHES:
        raise ContractError("unsupported branch")
    status = payload.get("status")
    if status not in ALL_SCORE_STATES:
        raise ContractError("unsupported score status")
    bundle_id = _bounded_str(payload, "bundle_id")
    domain = _bounded_str(payload, "domain", 128)
    validation = payload.get("domain_validation")
    if validation not in VALIDATION:
        raise ContractError("invalid domain_validation")
    refs = payload.get("event_refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 512 or any(
            not isinstance(ref, str) or not 1 <= len(ref) <= 160 for ref in refs):
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
        start, end = parse_time(window.get("start"), "window.start"), parse_time(window.get("end"), "window.end")
        if start >= end or end - start > timedelta(hours=24):
            raise ContractError("invalid score window")
        window = {**window, "start": start.isoformat(), "end": end.isoformat()}
    evidence = payload.get("evidence", {})
    if not isinstance(evidence, dict) or len(json.dumps(evidence)) > 256 * 1024:
        raise ContractError("evidence must be an object below 256 KiB")
    event_time = parse_time(evidence["event_time"], "evidence.event_time") if "event_time" in evidence else \
        (parse_time(window["end"], "window.end") if window else processed_at)
    normalized = {"schema_version": SCORE_SCHEMA, "host_id": host_id, "branch": branch, "bundle_id": bundle_id,
                  "event_refs": refs, "window": window, "status": status, "score": score, "threshold": threshold,
                  "prediction": prediction, "domain": domain, "domain_validation": validation,
                  "processed_at": processed_at, "event_time": event_time, "evidence": evidence}
    normalized["score_id"] = canonical_hash([SCORE_SCHEMA, host_id, branch, bundle_id, refs, window, processed_at.isoformat()])
    return normalized


def validate_summary(payload: Any, authenticated_host: str | None) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != SUMMARY_SCHEMA:
        raise ContractError("unsupported summary schema")
    host_id = _bounded_str(payload, "host_id")
    if authenticated_host is not None and host_id != authenticated_host:
        raise ContractError("credential cannot submit summaries for another host")
    out = {"host_id": host_id, "bundle_id": _bounded_str(payload, "bundle_id"), "domain": _bounded_str(payload, "domain", 128),
           "period_start": parse_time(payload.get("period_start"), "period_start"),
           "period_end": parse_time(payload.get("period_end"), "period_end"), "payload": payload}
    if len(json.dumps(payload)) > 512 * 1024:
        raise ContractError("summary too large")
    out["summary_id"] = canonical_hash([SUMMARY_SCHEMA, host_id, out["period_start"].isoformat(), out["period_end"].isoformat()])
    return out


# ------------------------------------------------------------------------------------------------ fusion
FUSION_POLICY = {
    "version": "fusion-il3-v1",
    "algorithm": "threshold-normalised noisy-OR of host ML (per event) and host DL (per window) + context",
    "bucket_seconds": 300,
    "incident_gap_seconds": 900,
    "alert_threshold": 0.5,
    "calibration": "none in the lab yet: each branch is normalised by its own VALIDATION threshold "
                   "(margin 0.5 = at threshold); weights become learnable once SOC-verified lab labels exist",
}
HIGH_STAGES = {"lateral_movement", "exfiltration", "impact"}


def margin(p: float, th: float) -> float:
    """Probability rescaled so that the branch threshold maps to 0.5 (logit shift)."""
    eps = 1e-7
    p, th = min(max(p, eps), 1 - eps), min(max(th, eps), 1 - eps)
    z = math.log(p / (1 - p)) - math.log(th / (1 - th))
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))


def fuse_bucket(host_id: str, bucket_start: datetime, rows: list[dict[str, Any]], rule_hits: dict[str, int]) -> dict[str, Any]:
    """rows: ready scores of one host whose event time falls in the bucket."""
    by = {"host_ml": [], "host_dl": []}
    for r in rows:
        if r["status"] in READY_STATES and r["score"] is not None and r["branch"] in by:
            by[r["branch"]].append(r)
    if not by["host_ml"] and not by["host_dl"]:
        raise ContractError("no usable scores to fuse")
    branch_info, terms = {}, []
    for b, lst in by.items():
        if not lst:
            continue
        best = max(lst, key=lambda r: margin(r["score"], r["threshold"]))
        m = margin(best["score"], best["threshold"])
        terms.append(m)
        info = {"top_score": best["score"], "threshold": best["threshold"], "margin": m, "n_scores": len(lst),
                "n_predicted": sum(int(r["prediction"] or 0) for r in lst), "bundle_id": best["bundle_id"],
                "domain": best["domain"], "domain_validation": best["domain_validation"], "top_score_id": best["score_id"]}
        if b == "host_dl":
            ev = best.get("evidence") or {}
            info.update(stage_last=ev.get("stage_last"), window=best.get("score_window"))
        branch_info[b] = info
    risk = 1.0
    for t in terms:
        risk *= (1.0 - t)
    risk = min(1.0, max(0.0, 1.0 - risk))
    pred = int(risk >= FUSION_POLICY["alert_threshold"])
    both = all(branch_info.get(b, {}).get("n_predicted", 0) > 0 for b in by)
    stage = branch_info.get("host_dl", {}).get("stage_last")
    severity = "critical" if pred and (both or stage in HIGH_STAGES) else ("high" if pred and (risk >= 0.8 or rule_hits) else "medium")
    shadow = any(i["domain_validation"] != "validated" for i in branch_info.values())
    bucket_end = bucket_start + timedelta(seconds=FUSION_POLICY["bucket_seconds"])
    fusion_id = canonical_hash(["fusion.v2", host_id, bucket_start.isoformat(), FUSION_POLICY["version"]])
    top_ml = sorted(by["host_ml"], key=lambda r: -r["score"])[:20]
    top_dl = sorted(by["host_dl"], key=lambda r: -r["score"])[:10]
    return {"fusion_id": fusion_id, "host_id": host_id, "bucket_start": bucket_start, "bucket_end": bucket_end,
            "algorithm": FUSION_POLICY["algorithm"], "policy_version": FUSION_POLICY["version"], "risk_score": risk,
            "threshold": FUSION_POLICY["alert_threshold"], "prediction": pred,
            "source_mask": {b: bool(by[b]) for b in by}, "severity": severity, "shadow": shadow,
            "score_refs": sorted(r["score_id"] for r in top_ml + top_dl),
            "evidence": {"branches": branch_info, "rule_hits": rule_hits, "agreement": both,
                         "ml_events": [{"score_id": r["score_id"], "score": r["score"], "event_time": r["event_time"].isoformat(),
                                        "event": (r.get("evidence") or {}).get("event"),
                                        "top_features": (r.get("evidence") or {}).get("top_features"),
                                        "event_refs": r["event_refs"][:16]} for r in top_ml],
                         "dl_windows": [{"score_id": r["score_id"], "score": r["score"], "window": r.get("score_window"),
                                         "stage_last": (r.get("evidence") or {}).get("stage_last"),
                                         "top_events": ((r.get("evidence") or {}).get("top_events") or [])[:8]} for r in top_dl]}}


def alert_severity_rank(sev: str) -> int:
    return {"medium": 1, "high": 2, "critical": 3}.get(sev, 0)


def population_stability_index(reference: dict[str, float], current: dict[str, float]) -> float | None:
    """Finite categorical PSI; returns None when either sample is empty."""
    ref_total, cur_total = sum(reference.values()), sum(current.values())
    if ref_total <= 0 or cur_total <= 0:
        return None
    eps = 1e-6
    out = 0.0
    for key in set(reference) | set(current):
        e = max(eps, reference.get(key, 0) / ref_total)
        a = max(eps, current.get(key, 0) / cur_total)
        out += (a - e) * math.log(a / e)
    return float(out)
