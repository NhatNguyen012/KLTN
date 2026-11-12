"""Doc va kiem tra network_event_schema_v1.json (nguon duy nhat cho danh sach feature, ID dac biet, bang cong).

Duoc 08b_loso_preprocess.py va 04a_dl_shards_base.py (qua 08c) import truc tiep. Khong in/ghi gi o day.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("network_event_schema_v1.json")

ALLOWED_ROLES = {"join_audit", "target", "categorical", "numeric", "binary", "time", "graph_only", "cross_check", "not_used"}
REQUIRED_TOP = ("schema_version", "roles", "fields", "categorical", "numeric", "port_class", "sample")


def load_schema(path: Path | None = None) -> dict[str, Any]:
    path = Path(path) if path else SCHEMA_PATH
    raw = path.read_bytes()
    schema = json.loads(raw.decode("utf-8"))
    schema["_sha256"] = hashlib.sha256(raw).hexdigest()
    schema["_path"] = str(path)
    validate(schema)
    return schema


def validate(schema: dict[str, Any]) -> None:
    for key in REQUIRED_TOP:
        if key not in schema:
            raise ValueError(f"schema thieu khoa {key!r}")

    by_name: dict[str, dict[str, Any]] = {}
    for f in schema["fields"]:
        name = f["name"]
        if name in by_name:
            raise ValueError(f"field trung ten: {name}")
        if f["role"] not in ALLOWED_ROLES:
            raise ValueError(f"{name}: role khong hop le {f['role']!r}")
        for req in ("source", "dtype", "meaning_vi", "example"):
            if req not in f or f[req] in ("", None):
                raise ValueError(f"{name}: thieu {req}")
        by_name[name] = f

    cat = schema["categorical"]
    for name in [*cat["base_fields"], *cat["derived_fields"]]:
        if name not in by_name or by_name[name]["role"] != "categorical":
            raise ValueError(f"{name}: khong phai field categorical trong schema")

    for name in cat["derived_fields"]:
        if "derived_from" not in by_name[name]:
            raise ValueError(f"{name}: field dan xuat can derived_from")

    for name in schema["numeric"]["fields"]:
        if name not in by_name or by_name[name]["role"] != "numeric":
            raise ValueError(f"{name}: khong phai field numeric trong schema")

    ids = cat["reserved_ids"]
    if ids != {"<UNK>": 0, "<MISSING>": 1}:
        raise ValueError(f"reserved_ids phai la <UNK>=0, <MISSING>=1, nhan duoc {ids}")

    ports = schema["port_class"]["common_ports"]
    if not ports or any(not str(p).isdigit() for p in ports):
        raise ValueError("common_ports phai co khoa la so cong")


def common_ports(schema: dict[str, Any]) -> dict[int, str]:
    return {int(p): name for p, name in schema["port_class"]["common_ports"].items()}


def fields_by_role(schema: dict[str, Any], role: str) -> list[str]:
    return [f["name"] for f in schema["fields"] if f["role"] == role]
