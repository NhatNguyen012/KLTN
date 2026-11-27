"""Self-contained OpTC eCAR causal featurizer for endpoint Host ML (Seed-02 LightGBM)."""
from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np

from ._vendor.ecar_tokenizer import flatten_tokens, tokenize_record
from ._vendor.optc_process_context_tracker import (
    HostProcessContextTracker,
    ProcessContextConfig,
    parse_timestamp,
)
from ._vendor.optc_schema_adapters import adapt_records
from .host_ml import Row


def _ts_micros(ts_str: Any) -> int:
    val = parse_timestamp(str(ts_str or ""))
    return int(val) if val is not None else 0


class OptcEcarFeaturizer:
    """Adapt Windows Sysmon/Security/PowerShell/eCAR records into 10,317-dim OpTC Seed-02 sparse rows."""

    def __init__(self, domain: str, vocab: dict[str, int], host: str = ""):
        self.domain = domain
        self.vocab = vocab
        self.width = len(vocab)
        self.host = host or "localhost"
        self.tracker = HostProcessContextTracker(ProcessContextConfig())
        self.oov: Counter[str] = Counter()
        self.rows_seen = 0
        self.tokens_seen = 0
        self.tokens_oov = 0
        self.events_seen = 0

    def feed(self, raw: Any, ref: Any = None) -> list[Row]:
        """Adapt one raw record (Sysmon/Security/PowerShell XML or eCAR dict) and return [Row] if ML-eligible."""
        if not isinstance(raw, dict):
            return []
        rec_in = dict(raw)
        if not rec_in.get("hostname") and self.host:
            rec_in.setdefault("hostname", self.host)
        adapted, _ = adapt_records([rec_in])
        if not adapted:
            return []
        out: list[Row] = []
        for rec in adapted:
            ts_str = rec.get("timestamp")
            ts_us = parse_timestamp(str(ts_str)) if ts_str else None
            ctx_tokens = self.tracker.get_context_tokens(rec, query_t=ts_us)
            grouped, audit = tokenize_record(rec)
            self.tracker.observe(rec, event_t=ts_us)
            if not audit.get("eligible"):
                continue
            grouped["structure_semantic"].extend(ctx_tokens)
            tokens = list(dict.fromkeys(flatten_tokens(grouped)))
            props = rec.get("properties") or {}
            act = str(rec.get("action") or "")
            obj = str(rec.get("object") or "")
            img = str(props.get("image_path") or props.get("parent_image_path") or "")
            cmd = str(props.get("command_line") or props.get("payload") or "")
            tpath = str(props.get("file_path") or props.get("target_image_path") or props.get("key") or props.get("dest_ip") or "")
            ev_summary = {
                "kind": f"{act}_{obj}" if act and obj else (act or obj),
                "image": img[:260],
                "cmd": cmd[:512],
                "tpath": tpath[:260],
            }
            refs = [ref] if ref is not None else ([rec["id"]] if rec.get("id") else [])
            self.events_seen += 1
            out.append(Row(ts=_ts_micros(ts_str), kind=ev_summary["kind"], tokens=tokens, event=ev_summary, refs=refs))
        return out

    def feed_canonical(self, _ce: Any) -> Row | None:
        return None

    def flush(self) -> list[Row]:
        return []

    def columns(self, row: Row) -> list[int]:
        cols, oov = set(), set()
        for t in row.tokens:
            c = self.vocab.get(t)
            if c is None:
                oov.add(t)
            elif 0 <= c < self.width:
                cols.add(c)
        self.rows_seen += 1
        self.tokens_seen += len(cols) + len(oov)
        self.tokens_oov += len(oov)
        self.oov.update(oov)
        return sorted(cols)

    def matrix(self, rows: list[Row]):
        from scipy.sparse import csr_matrix
        indptr, indices = [0], []
        for r in rows:
            indices += self.columns(r)
            indptr.append(len(indices))
        return csr_matrix(
            (np.ones(len(indices), np.float32), np.asarray(indices, np.int32), np.asarray(indptr, np.int64)),
            shape=(len(rows), self.width),
        )

    def drain_stats(self, top: int = 200) -> dict:
        out = {
            "events": self.events_seen,
            "rows": self.rows_seen,
            "tokens": self.tokens_seen,
            "tokens_oov": self.tokens_oov,
            "oov_rate": self.tokens_oov / self.tokens_seen if self.tokens_seen else None,
            "oov_distinct": len(self.oov),
            "oov_top": self.oov.most_common(top),
        }
        self.oov = Counter()
        self.rows_seen = self.tokens_seen = self.tokens_oov = self.events_seen = 0
        return out
