#!/usr/bin/env python3
"""Shared causal stream feature extraction for ML (LightGBM) and DL (ExpandableMixHeadCausalIL).

Reuses the exact workspace tokenizers and past-only HostProcessContextTracker without any
duplicated preprocessing logic or label leakage.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shlex
from typing import Any, Callable, Dict, Iterable, List, Mapping, Tuple

from ML.code.preprocess.ecar_tokenizer import flatten_tokens, tokenize_record
from ML.code.preprocess.process_context_tracker import (
    HostProcessContextTracker,
    ProcessContextConfig,
    canonical_host,
    parse_timestamp,
)
from shared.schema_adapters import adapt_records


def _load_tokenize_dl_record() -> Callable[[Mapping[str, Any]], Tuple[Dict[str, List[str]], Dict[str, Any]]] | None:
    """Load dl_ecar_tokenizer directly by path so ML containers do not trigger DL/__init__ torch imports."""
    for base in (Path("/workspace"), Path(__file__).resolve().parents[2]):
        cand = base / "DL/code/preprocess/dl_ecar_tokenizer.py"
        if cand.is_file():
            spec = importlib.util.spec_from_file_location("_dl_ecar_tokenizer_standalone", cand)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod.tokenize_dl_record
    return None


tokenize_dl_record = _load_tokenize_dl_record()

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
    }
)


def strip_truth_fields(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a clean copy with all ground-truth label fields removed prior to model featurization."""
    return {k: v for k, v in rec.items() if k not in TRUTH_KEYS}


def is_causal_triplet_record(rec: Mapping[str, Any]) -> bool:
    """Detect whether record is already structured as L=3 causal lines (e.g. THEIA Linux)."""
    return any(
        k in rec
        for k in (
            "E_incoming",
            "E_parent",
            "E_current",
            "incoming_tokens",
            "parent_tokens",
            "current_tokens",
            "incoming_ids",
            "current_ids",
        )
    )


@dataclass
class ExtractedEventFeatures:
    index: int
    domain_hint: str
    hostname: str
    timestamp: str
    action: str
    object_type: str
    event_id: str
    command_preview: str
    ml_eligible: bool
    dl_eligible: bool
    ml_tokens: List[str]
    incoming_tokens: List[str]
    parent_tokens: List[str]
    current_tokens: List[str]
    incoming_ids_raw: List[int] | None = None
    parent_ids_raw: List[int] | None = None
    current_ids_raw: List[int] | None = None


def _as_str_list(val: Any) -> List[str]:
    if not isinstance(val, (list, tuple)):
        return []
    return [str(x) for x in val if x is not None and str(x).strip()]


def _as_int_list(val: Any) -> List[int] | None:
    if not isinstance(val, (list, tuple)) or not val:
        return None
    out = [int(x) for x in val if int(x) > 0]
    return out or [2]


def _split_dl_context_tokens(ctx_tokens: Iterable[str]) -> Tuple[List[str], List[str]]:
    inc_toks = [t for t in ctx_tokens if "::incoming::" in t]
    parent_toks = [
        t
        for t in ctx_tokens
        if "::parent::" in t or "::relation::lineage" in t or "::relation::path" in t
    ]
    return inc_toks, parent_toks


def _safe_command_preview(rec: Mapping[str, Any]) -> str:
    props = rec.get("properties")
    if isinstance(props, Mapping):
        for key in ("command_line", "payload", "image_path", "file_path", "module_path", "key", "dest_ip"):
            val = props.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()[:160]
    return ""


def _linux_path_cat(path: str) -> str:
    p = (path or "").strip().lower()
    if not p:
        return "other_path"
    if p.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/libexec/")):
        return "system"
    if p.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return "temp"
    if p.startswith(("/home/", "/root/")):
        return "user_profile"
    if not p.startswith("/"):
        return "relative"
    return "other_path"


def _linux_base(path: str) -> str:
    return os.path.basename((path or "").strip().rstrip("/")).lower()


def _linux_ip_scope(ip_str: str) -> str:
    s = (ip_str or "").strip()
    if not s:
        return "unspecified"
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast or str(ip) == "255.255.255.255":
        return "multicast_broadcast"
    if ip.version == 4 and str(ip).startswith("203.0.113."):
        return "external_public"
    if ip.is_private:
        return "enterprise_internal"
    return "external_public"


def _linux_port_role(port_raw: str) -> str:
    try:
        p = int(str(port_raw or "").strip())
    except ValueError:
        return "unknown"
    roles = {20: "ftp_data", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http_web", 88: "kerberos", 135: "rpc_endpoint", 389: "ldap", 443: "https_web", 445: "smb_cifs", 636: "ldaps", 3389: "remote_desktop", 8443: "https_web", 18443: "https_web"}
    if p in roles:
        return roles[p]
    if p >= 49152:
        return "ephemeral_high"
    if p >= 1024:
        return "registered_mid"
    return "unknown"


def _linux_cmd_switches(cmd: str) -> List[str]:
    if not cmd:
        return []
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    out: List[str] = []
    for tok in toks[1:12]:
        t = tok.strip().lower()
        if t.startswith("-") or t in {"sudo", "/bin/sh"}:
            out.append(f"shell::switch={t}")
    return out


class _LinuxTheiaCausalTracker:
    """Past-only L=3 context state mapping KLTN auditd records into THEIA Domain-2 tokens."""

    def __init__(self) -> None:
        self.proc_meta: Dict[str, Tuple[str, str, int | None]] = {}
        self.incoming: Dict[str, List[Tuple[str, str]]] = {}

    def featurize(self, rec: Mapping[str, Any], event_t: int | None) -> Tuple[List[str], List[str], List[str]]:
        props = rec.get("properties") if isinstance(rec.get("properties"), Mapping) else {}
        pid = str(props.get("pid") or rec.get("actorID") or "")
        ppid = str(props.get("ppid") or "")
        img = str(props.get("image_path") or "")
        pimg = str(props.get("parent_image_path") or "")
        if not pimg and ppid and ppid in self.proc_meta:
            pimg = self.proc_meta[ppid][0]
        img_cat = _linux_path_cat(img)
        img_base = _linux_base(img)

        act = str(rec.get("action") or "open").lower()
        obj = str(rec.get("object") or "file").lower()
        theia_op = str(props.get("theia_op") or "EVENT_OPEN").lower()
        cur: List[str] = [f"action::{act}", f"object::{obj}", f"structure::action_object={act}->{obj}", f"theia::op={theia_op}"]
        if img:
            cur.append(f"image_path::category={img_cat}")
        if img_base:
            cur.append(f"image_path::basename={img_base}")

        fpath = str(props.get("file_path") or "")
        if obj == "process":
            if img:
                cur.append(f"target_image::category={img_cat}")
            if img_base:
                cur.append(f"target_image::basename={img_base}")
            if pimg and img_base:
                cur.append(f"structure::process_lineage={_linux_base(pimg)}->{img_base}")
        elif obj == "file" and fpath:
            fbase = _linux_base(fpath)
            cur.append(f"file_path::category={_linux_path_cat(fpath)}")
            if fbase:
                cur.append(f"file_path::basename={fbase}")
                ext = os.path.splitext(fbase)[1].lower() if "." in fbase and not fbase.startswith(".") else "none"
                cur.append(f"file_path::extension={ext or 'none'}")
            if fpath.startswith("/etc/"):
                cur.append("file_path::config=/etc")
        elif obj == "flow":
            direction = str(props.get("direction") or "outbound").lower()
            proto = str(props.get("proto") or "tcp").lower()
            src_s = _linux_ip_scope(str(props.get("src_ip") or ""))
            dst_s = _linux_ip_scope(str(props.get("dest_ip") or ""))
            scope = "loopback" if (src_s == "loopback" or dst_s == "loopback") else ("internal_to_external" if dst_s == "external_public" else ("internal_to_internal" if dst_s == "enterprise_internal" else "unspecified"))
            dport_r = _linux_port_role(str(props.get("dest_port") or ""))
            sport_r = _linux_port_role(str(props.get("src_port") or ""))
            cur.extend([
                f"net::direction={direction}",
                f"net::proto={proto}",
                f"net::src_scope={src_s}",
                f"net::dest_scope={dst_s}",
                f"net::scope={scope}",
                f"net::src_port_role={sport_r}",
                f"net::dest_port_role={dport_r}",
                f"net::flow_pattern={proto}:{dport_r}:{direction}",
            ])
            if img_base:
                cur.append(f"net::proc={img_base}")

        cmd = str(props.get("command_line") or "")
        if cmd:
            if "python" in cmd.lower() or "python" in img_base:
                cur.append("command_line::family=python")
            elif img_base in {"bash", "sh", "dash"}:
                cur.append("command_line::family=native")
            cur.extend(_linux_cmd_switches(cmd))

        # E_parent (past-only)
        pbase = _linux_base(pimg)
        if pbase:
            pcat = _linux_path_cat(pimg)
            par = [
                "ctx::status::has_parent",
                f"ctx::parent::exe={pbase}",
                f"ctx::parent::path_role={pcat}",
                f"parent_image_path::category={pcat}",
                f"parent_image_path::basename={pbase}",
                f"ctx::relation::path={pcat}->{img_cat}",
            ]
        else:
            par = ["ctx::status::parent_missing"]

        # E_incoming (past-only for pid)
        hist = self.incoming.get(pid, [])
        if hist:
            inc: List[str] = []
            for h_act, h_tgt in hist[-3:]:
                inc.extend([f"ctx::incoming::{h_act}::direction=incoming", f"ctx::incoming::{h_act}::present=true", h_tgt])
            inc = list(dict.fromkeys(inc))
        else:
            inc = ["ctx::incoming::target=parent:" + pbase] if pbase else ["ctx::status::actor_metadata_missing"]

        return inc, par, list(dict.fromkeys(cur))

    def observe(self, rec: Mapping[str, Any], event_t: int | None) -> None:
        props = rec.get("properties") if isinstance(rec.get("properties"), Mapping) else {}
        pid = str(props.get("pid") or rec.get("actorID") or "")
        img = str(props.get("image_path") or "")
        pimg = str(props.get("parent_image_path") or "")
        if pid and img:
            self.proc_meta[pid] = (img, pimg, event_t)
        act = str(rec.get("action") or "open").lower()
        obj = str(rec.get("object") or "file").lower()
        if pid:
            if obj == "file" and props.get("file_path"):
                tgt = f"ctx::incoming::target=file_path:{_linux_base(str(props['file_path']))}"
                self.incoming.setdefault(pid, []).append((act, tgt))
            elif obj == "flow":
                dst_s = _linux_ip_scope(str(props.get("dest_ip") or ""))
                dport_r = _linux_port_role(str(props.get("dest_port") or ""))
                self.incoming.setdefault(pid, []).append((act, f"ctx::incoming::target=flow:{dst_s}:{dport_r}"))
            elif act == "create" and obj == "process" and pimg:
                self.incoming.setdefault(pid, []).append(("open", f"ctx::incoming::target=parent:{_linux_base(pimg)}"))
            if pid in self.incoming and len(self.incoming[pid]) > 8:
                self.incoming[pid] = self.incoming[pid][-8:]


def _build_tracker() -> HostProcessContextTracker:
    return HostProcessContextTracker(ProcessContextConfig())


def extract_stream_features(
    records: List[Mapping[str, Any]],
    adapt_external: bool = True,
) -> List[ExtractedEventFeatures]:
    """Featurize raw/adapted eCAR logs or pre-structured L=3 causal triplets while preserving indices."""
    clean_inputs = [strip_truth_fields(orig) for orig in records]
    if adapt_external:
        clean_inputs, _ = adapt_records(clean_inputs)

    results: List[ExtractedEventFeatures | None] = [None] * len(clean_inputs)
    raw_items: List[Tuple[int, str, int | None, Dict[str, Any]]] = []

    for idx, rec in enumerate(clean_inputs):
        if is_causal_triplet_record(rec):
            inc = _as_str_list(rec.get("E_incoming") or rec.get("incoming_tokens"))
            par = _as_str_list(rec.get("E_parent") or rec.get("parent_tokens"))
            cur = _as_str_list(rec.get("E_current") or rec.get("current_tokens"))
            all_toks = list(dict.fromkeys(inc + par + cur))
            domain = str(rec.get("domain") or "theia_linux")
            results[idx] = ExtractedEventFeatures(
                index=idx,
                domain_hint=domain,
                hostname=str(rec.get("hostname") or "linux-theia"),
                timestamp=str(rec.get("timestamp") or rec.get("timestamp_rec") or ""),
                action=str(rec.get("action") or rec.get("op") or "PROVENANCE"),
                object_type=str(rec.get("object") or "EVENT"),
                event_id=str(rec.get("event_uuid") or rec.get("id") or f"evt-{idx}"),
                command_preview=str(rec.get("summary") or ", ".join(cur[:5]))[:160],
                ml_eligible=False,  # Host ML LightGBM is Windows OpTC eCAR domain-0 only
                dl_eligible=True,
                ml_tokens=all_toks,
                incoming_tokens=inc,
                parent_tokens=par,
                current_tokens=cur,
                incoming_ids_raw=_as_int_list(rec.get("incoming_ids")),
                parent_ids_raw=_as_int_list(rec.get("parent_ids")),
                current_ids_raw=_as_int_list(rec.get("current_ids")),
            )
        else:
            host = canonical_host(rec.get("hostname")) or "__default__"
            ts = parse_timestamp(rec.get("timestamp"))
            raw_items.append((idx, host, ts, rec))

    # Group raw eCAR items per host & flush timestamps causally (ties get pre-t context, then observe)
    by_host: Dict[str, List[Tuple[int, int | None, Dict[str, Any]]]] = {}
    for idx, host, ts, rec in raw_items:
        by_host.setdefault(host, []).append((idx, ts, rec))

    for host, items in by_host.items():
        # Preserve original relative order on equal timestamps; sort monotonically when timestamps exist
        items.sort(key=lambda item: (item[1] if item[1] is not None else -1, item[0]))
        tracker = _build_tracker()
        linux_tracker = _LinuxTheiaCausalTracker()

        def _process_batch(batch: List[Tuple[int, int | None, Dict[str, Any]]], batch_t: int | None) -> None:
            for orig_idx, _, rec in batch:
                adapted_from = rec.get("_adapted_from")
                if adapted_from == "kltn_linux_audit":
                    inc_toks, parent_toks, dl_curr = linux_tracker.featurize(rec, event_t=batch_t)
                    results[orig_idx] = ExtractedEventFeatures(
                        index=orig_idx,
                        domain_hint="kltn_linux_audit->theia_l3",
                        hostname=str(rec.get("hostname") or host),
                        timestamp=str(rec.get("timestamp") or ""),
                        action=str(rec.get("action") or ""),
                        object_type=str(rec.get("object") or ""),
                        event_id=str(rec.get("id") or f"evt-{orig_idx}"),
                        command_preview=_safe_command_preview(rec),
                        ml_eligible=False,  # Host ML LightGBM is Windows OpTC eCAR domain-0 only
                        dl_eligible=True,
                        ml_tokens=list(dict.fromkeys(inc_toks + parent_toks + dl_curr)),
                        incoming_tokens=inc_toks,
                        parent_tokens=parent_toks,
                        current_tokens=dl_curr,
                    )
                    continue

                ctx_tokens = tracker.get_context_tokens(rec, query_t=batch_t)
                ml_grouped, ml_audit = tokenize_record(rec)
                ml_eligible = bool(ml_audit.get("eligible"))
                if ml_eligible:
                    ml_grouped["structure_semantic"].extend(ctx_tokens)
                    ml_tokens = list(dict.fromkeys(flatten_tokens(ml_grouped)))
                else:
                    ml_tokens = []

                if tokenize_dl_record is not None:
                    dl_grouped, dl_audit = tokenize_dl_record(rec)
                    dl_curr = []
                    for vlist in dl_grouped.values():
                        dl_curr.extend(vlist)
                else:
                    dl_curr, dl_audit = [], ml_audit
                inc_toks, parent_toks = _split_dl_context_tokens(ctx_tokens)
                dl_eligible = bool(dl_curr) or bool(dl_audit.get("eligible"))

                dom_hint = f"{adapted_from}->ecar" if adapted_from else "optc_ecar"
                results[orig_idx] = ExtractedEventFeatures(
                    index=orig_idx,
                    domain_hint=dom_hint,
                    hostname=str(rec.get("hostname") or host),
                    timestamp=str(rec.get("timestamp") or ""),
                    action=str(rec.get("action") or ""),
                    object_type=str(rec.get("object") or ""),
                    event_id=str(rec.get("id") or f"evt-{orig_idx}"),
                    command_preview=_safe_command_preview(rec),
                    ml_eligible=ml_eligible,
                    dl_eligible=dl_eligible,
                    ml_tokens=ml_tokens,
                    incoming_tokens=inc_toks,
                    parent_tokens=parent_toks,
                    current_tokens=dl_curr,
                )
            for _, _, rec in batch:
                if rec.get("_adapted_from") == "kltn_linux_audit":
                    linux_tracker.observe(rec, event_t=batch_t)
                else:
                    tracker.observe(rec, event_t=batch_t)

        cur_batch: List[Tuple[int, int | None, Dict[str, Any]]] = []
        cur_t: int | None = None
        for item in items:
            _, ts, _ = item
            if cur_batch and ts != cur_t:
                _process_batch(cur_batch, cur_t)
                cur_batch = []
            cur_t = ts
            cur_batch.append(item)
        if cur_batch:
            _process_batch(cur_batch, cur_t)

    return [r for r in results if r is not None]
