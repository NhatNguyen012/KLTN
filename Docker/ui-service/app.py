#!/usr/bin/env python3
"""SOC Web UI & API Gateway coordinating ml-service and dl-service containers."""

from __future__ import annotations

import asyncio
from collections import Counter
import gzip
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel

ML_SERVICE_URL = os.environ.get("ML_SERVICE_URL", "http://ml-service:8001").rstrip("/")
DL_SERVICE_URL = os.environ.get("DL_SERVICE_URL", "http://dl-service:8002").rstrip("/")
SAMPLE_DIR = Path(os.environ.get("SAMPLE_LOGS_DIR", "/app/sample_logs"))
STATIC_DIR = Path(__file__).resolve().parent / "static"

MAX_EVENTS_PER_REQUEST = 5000
TRUTH_KEYS = frozenset(
    {
        "label",
        "is_malicious",
        "scenario_id",
        "stage_id",
        "true_binary",
        "true_scenario",
        "true_stage",
        "_meta_truth",
        "ground_truth",
        "eval_split",
    }
)

app = FastAPI(title="APT Multi-Model Container Gateway & UI", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class AnalyzePayload(BaseModel):
    raw_logs: str
    ml_threshold: Optional[float] = None
    dl_threshold: Optional[float] = None
    adapt_external: bool = True


def _xml_event_to_dict(xml_str: str) -> Dict[str, Any]:
    import xml.etree.ElementTree as ET

    if "<!DOCTYPE" in xml_str.upper() or "<!ENTITY" in xml_str.upper():
        raise HTTPException(status_code=400, detail="Unsupported DOCTYPE/ENTITY in XML event")
    root = ET.fromstring(xml_str)
    out: Dict[str, Any] = {}
    ed: Dict[str, Any] = {}
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag == "Provider":
            out["source_name"] = elem.attrib.get("Name", "")
        elif tag in ("EventID", "Channel", "Computer", "EventRecordID"):
            if elem.text:
                out[tag] = elem.text.strip()
        elif tag == "TimeCreated" and "SystemTime" in elem.attrib:
            out["SystemTime"] = elem.attrib["SystemTime"]
        elif tag == "Data":
            name = elem.attrib.get("Name")
            if name:
                ed[name] = (elem.text or "").strip()
    if ed:
        out["event_data"] = ed
    return out


def _parse_log_bytes(raw: bytes, filename: str = "") -> List[Dict[str, Any]]:
    if filename.endswith(".gz") or raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Input log payload is empty.")

    records: List[Dict[str, Any]] = []
    if text.startswith("["):
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            raise HTTPException(status_code=400, detail="JSON array expected.")
        records = [x for x in parsed if isinstance(x, dict)]
    elif text.startswith("<Event"):
        blocks = re.findall(r"<Event\b.*?</Event>", text, flags=re.S)
        if not blocks:
            raise HTTPException(status_code=400, detail="No complete <Event>...</Event> XML blocks found.")
        for i, block in enumerate(blocks, 1):
            try:
                records.append(_xml_event_to_dict(block))
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Invalid XML Event #{i}: {exc}") from exc
    else:
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s:
                continue
            if s.startswith("<Event"):
                try:
                    records.append(_xml_event_to_dict(s))
                except Exception as exc:
                    raise HTTPException(status_code=400, detail=f"Invalid XML Event at line {i}: {exc}") from exc
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid JSON at line {i}: {exc.msg}") from exc
            if isinstance(obj, dict):
                records.append(obj)

    if not records:
        raise HTTPException(status_code=400, detail="No valid JSON event records found.")
    if len(records) > MAX_EVENTS_PER_REQUEST:
        raise HTTPException(
            status_code=400,
            detail=f"Too many events in one request ({len(records)} > {MAX_EVENTS_PER_REQUEST}).",
        )
    return records


def _extract_truth(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    mt = rec.get("_meta_truth")
    if isinstance(mt, dict):
        return mt
    tb = rec.get("true_binary")
    if tb is None and rec.get("label") in (0, 1):
        tb = int(rec["label"])
    elif tb is None and rec.get("is_malicious") in (0, 1):
        tb = int(rec["is_malicious"])
    if tb is None:
        return None
    return {
        "true_binary": int(tb),
        "true_scenario": rec.get("true_scenario"),
        "true_stage": rec.get("true_stage"),
        "eval_split": rec.get("eval_split", "uploaded"),
    }


def _clean_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in rec.items() if k not in TRUTH_KEYS}


def _preview_event(rec: Dict[str, Any]) -> str:
    if "E_current" in rec and isinstance(rec["E_current"], list):
        return ", ".join(str(x) for x in rec["E_current"][:5])
    props = rec.get("properties")
    if isinstance(props, dict):
        for k in ("command_line", "image_path", "file_path", "dest_ip", "key"):
            v = props.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()[:140]
    return ""


def _binary_metrics(y_true: List[int], y_pred: List[int]) -> Optional[Dict[str, Any]]:
    if not y_true or len(y_true) != len(y_pred):
        return None
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    return {
        "evaluated": len(y_true),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
    }


async def _run_dual_inference(
    records: List[Dict[str, Any]],
    ml_threshold: Optional[float] = None,
    dl_threshold: Optional[float] = None,
    source_name: str = "custom_input",
    adapt_external: bool = True,
) -> Dict[str, Any]:
    truths = [_extract_truth(r) for r in records]
    clean_records = [_clean_record(r) for r in records]

    async with httpx.AsyncClient(timeout=60.0) as client:
        ml_req = {
            "records": clean_records,
            "adapt_external": adapt_external,
            **({"threshold": ml_threshold} if ml_threshold is not None else {}),
        }
        dl_req = {
            "records": clean_records,
            "adapt_external": adapt_external,
            **({"threshold": dl_threshold} if dl_threshold is not None else {}),
        }
        ml_resp, dl_resp = await asyncio.gather(
            client.post(f"{ML_SERVICE_URL}/predict", json=ml_req),
            client.post(f"{DL_SERVICE_URL}/predict", json=dl_req),
        )
    if ml_resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"ml-service error: {ml_resp.text}")
    if dl_resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"dl-service error: {dl_resp.text}")

    ml_data = ml_resp.json()
    dl_data = dl_resp.json()
    ml_preds = ml_data["predictions"]
    dl_preds = dl_data["predictions"]

    rows: List[Dict[str, Any]] = []
    dl_sc_counts = Counter()
    dl_st_counts = Counter()

    ml_yt, ml_yp = [], []
    dl_yt, dl_yp = [], []

    for idx, rec in enumerate(clean_records):
        mp = ml_preds[idx]
        dp = dl_preds[idx]
        tr = truths[idx]
        if dp["pred_binary"] == 1 or dp["scenario_id"] != 0:
            dl_sc_counts[dp["scenario_name"]] += 1
        if dp["pred_binary"] == 1 or dp["stage_id"] != 0:
            dl_st_counts[dp["stage_name"]] += 1

        # Score strictly on non-warmup records when truth split metadata is present
        count_in_eval = tr is not None and tr.get("eval_split") != "warmup"
        if count_in_eval:
            if mp["eligible"] and mp["pred_binary"] is not None:
                ml_yt.append(int(tr["true_binary"]))
                ml_yp.append(int(mp["pred_binary"]))
            if dp["eligible"] and dp["pred_binary"] is not None:
                dl_yt.append(int(tr["true_binary"]))
                dl_yp.append(int(dp["pred_binary"]))

        rows.append(
            {
                "index": idx,
                "domain_hint": dp["domain_hint"],
                "hostname": str(dp.get("hostname") or rec.get("hostname") or "linux-theia"),
                "timestamp": str(dp.get("timestamp") or rec.get("timestamp") or rec.get("timestamp_rec") or ""),
                "action": str(dp.get("action") or rec.get("action") or rec.get("op") or "PROVENANCE"),
                "object": str(dp.get("object") or rec.get("object") or "EVENT"),
                "summary": str(dp.get("summary") or _preview_event(rec)),
                "truth": tr,
                "ml": mp,
                "dl": dp,
            }
        )

    both_scored = [
        (r["ml"]["pred_binary"], r["dl"]["pred_binary"])
        for r in rows
        if r["ml"]["eligible"] and r["dl"]["eligible"] and r["ml"]["pred_binary"] is not None
    ]
    agree_rate = (
        round(sum(1 for m, d in both_scored if m == d) / float(len(both_scored)), 4)
        if both_scored
        else None
    )

    return {
        "source_name": source_name,
        "total_events": len(rows),
        "ml_summary": {
            "model_name": ml_data["model_name"],
            "threshold": ml_data["threshold"],
            "scored_events": ml_data["scored_events"],
            "malicious_detected": ml_data["malicious_detected"],
            "latency_ms": ml_data["latency_ms"],
            "vs_ground_truth": _binary_metrics(ml_yt, ml_yp),
        },
        "dl_summary": {
            "model_name": dl_data["model_name"],
            "threshold": dl_data["threshold"],
            "scored_events": dl_data["scored_events"],
            "malicious_detected": dl_data["malicious_detected"],
            "latency_ms": dl_data["latency_ms"],
            "scenario_breakdown": dict(dl_sc_counts.most_common()),
            "stage_breakdown": dict(dl_st_counts.most_common()),
            "vs_ground_truth": _binary_metrics(dl_yt, dl_yp),
        },
        "ml_dl_agreement": agree_rate,
        "events": rows,
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/status")
async def status() -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=5.0) as client:
        ml_r, dl_r = await asyncio.gather(
            client.get(f"{ML_SERVICE_URL}/health"),
            client.get(f"{DL_SERVICE_URL}/health"),
            return_exceptions=True,
        )
    ml_info = ml_r.json() if isinstance(ml_r, httpx.Response) and ml_r.status_code == 200 else {"status": "error"}
    dl_info = dl_r.json() if isinstance(dl_r, httpx.Response) and dl_r.status_code == 200 else {"status": "error"}
    return {"ui": "ok", "ml_service": ml_info, "dl_service": dl_info}


@app.get("/api/samples")
def list_samples() -> Dict[str, Any]:
    manifest_path = SAMPLE_DIR / "manifest.json"
    if not manifest_path.is_file():
        return {"samples": []}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


@app.get("/api/samples/{sample_id}/raw")
def get_sample_raw(sample_id: str) -> Dict[str, Any]:
    manifest_path = SAMPLE_DIR / "manifest.json"
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="Sample manifest missing")
    man = json.loads(manifest_path.read_text(encoding="utf-8"))
    match = next((s for s in man.get("samples", []) if s["id"] == sample_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Unknown sample id: {sample_id}")
    p = (SAMPLE_DIR / match["file"]).resolve()
    p.relative_to(SAMPLE_DIR.resolve())
    return {"meta": match, "raw_logs": p.read_text(encoding="utf-8")}


@app.post("/api/analyze-sample/{sample_id}")
async def analyze_sample(
    sample_id: str,
    ml_threshold: Optional[float] = None,
    dl_threshold: Optional[float] = None,
) -> Dict[str, Any]:
    item = get_sample_raw(sample_id)
    records = _parse_log_bytes(item["raw_logs"].encode("utf-8"), item["meta"]["file"])
    return await _run_dual_inference(records, ml_threshold, dl_threshold, source_name=item["meta"]["title"])


@app.post("/api/analyze")
async def analyze_text(payload: AnalyzePayload) -> Dict[str, Any]:
    records = _parse_log_bytes(payload.raw_logs.encode("utf-8"), "paste.jsonl")
    return await _run_dual_inference(
        records,
        payload.ml_threshold,
        payload.dl_threshold,
        source_name="Pasted Logs",
        adapt_external=payload.adapt_external,
    )


@app.post("/api/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    ml_threshold: Optional[float] = Form(default=None),
    dl_threshold: Optional[float] = Form(default=None),
    adapt_external: bool = Form(default=True),
) -> Dict[str, Any]:
    content = await file.read()
    records = _parse_log_bytes(content, file.filename or "upload.jsonl")
    return await _run_dual_inference(
        records,
        ml_threshold,
        dl_threshold,
        source_name=file.filename or "Uploaded File",
        adapt_external=adapt_external,
    )
