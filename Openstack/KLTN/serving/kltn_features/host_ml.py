"""Online host-ML featurizer for the fused IL LightGBM (endpoint side).

Training contracts reproduced here (tokens come from the vendored training code, nothing is re-implemented):
  linux-audit     raw audit.log lines -> AuditStream -> Sl700Tokenizer.tokens (code/ML/build_sl700_host_ml.py):
                  Base OpTC eCAR tokens + ATLASv2 context + `lx:` Linux tokens; rows = procstart, filemod, fileread,
                  auth, privchange; every other event only updates the causal state.
  windows-sysmon  Sysmon XML -> SysmonMapper -> CBC-like CanonicalEvent -> canonical_ecar_record + tokenize_record
                  + extract_domain_shift_tokens (ATLASv2 build_host_shards.py); FLOW_START only updates the state.
  windows-cbc     CanonicalEvents from CBC-EDR (parity tests, or hosts that run a CBC sensor).
Columns: the bundle vocabulary (token -> column of the fused model). Tokens outside it are counted as OOV: they are the
candidates of the next vocabulary extension (IL step N+1) and the drift signal of the domain.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

import numpy as np

from ._vendor.atlas_host_ctx import FileSessionIndex, canonical_ecar_record, extract_domain_shift_tokens
from ._vendor.ecar_tokenizer import flatten_tokens, tokenize_record
from ._vendor.sl700_ecar import ROW_KINDS, Sl700Tokenizer
from .auditd_stream import AuditStream
from .sysmon import SysmonMapper, parse_event, to_canonical

DOMAINS = ("linux-audit", "windows-sysmon", "windows-cbc")
OPTC_BASE_WIDTH = 10317       # frozen OpTC vocabulary: columns [0, 10317)
WINDOWS_ROW_TYPES = {"PROCESS_START", "PROCESS_END", "FILE_WRITE", "FILE_CREATE", "FILE_DELETE", "REGISTRY_WRITE",
                     "MODULE_LOAD", "CROSS_PROCESS"}


@dataclass
class Row:
    ts: int                               # event time, us UTC
    kind: str                             # procstart / filemod / ... (Linux) or PROCESS_START / ... (Windows)
    tokens: list[str]
    event: dict                           # compact normalized event (evidence)
    refs: list = field(default_factory=list)


def _evidence_linux(e: dict) -> dict:
    return {k: e.get(k) for k in ("ts", "line", "kind", "pid", "ppid", "image", "tpath", "uid", "auid", "ses", "syscall",
                                  "rip", "rport", "user") if e.get(k) not in (None, "")} | {"cmd": (e.get("cmd") or "")[:1024]}


def _evidence_windows(e: dict) -> dict:
    out = {k: e.get(k) for k in ("ts", "eid", "event_type", "record_id", "path", "ppath", "tpath", "user", "rip",
                                 "rport", "domain", "pid", "guid") if e.get(k) not in (None, "", 0)}
    out["cmd"] = (e.get("tcmd") or e.get("cmd") or "")[:1024]
    return out


class HostFeaturizer:
    def __init__(self, domain: str, vocab: dict[str, int], host: str = ""):
        if domain not in DOMAINS:
            raise ValueError(f"unsupported domain {domain}")
        self.domain = domain
        self.vocab = vocab
        self.width = len(vocab)
        self.optc_tokens = {t for t, c in vocab.items() if c < OPTC_BASE_WIDTH}
        self.oov = Counter()                       # token -> rows (since last drain)
        self.rows_seen = 0
        self.tokens_seen = 0
        self.tokens_oov = 0
        self.events_seen = 0
        if domain == "linux-audit":
            self.stream = AuditStream(host)
            self.tk = Sl700Tokenizer(with_scope=False)   # scope tokens were excluded from the model (ecar_lx)
        else:
            self.mapper = SysmonMapper(host)
            self.session = FileSessionIndex()

    # ---------------------------------------------------------------- input
    def feed(self, raw, ref=None) -> list[Row]:
        """One raw record: an audit.log line (str, or {'log': line}) or a Sysmon record (dict)."""
        if self.domain == "linux-audit":
            line = raw if isinstance(raw, str) else str(raw.get("log") or raw.get("message") or "")
            return self._linux(self.stream.feed(line, ref=ref))
        if self.domain == "windows-sysmon":
            fields = parse_event(raw)
            if fields is None:
                return []
            e = self.mapper.map(fields)
            if e is None or e["event_type"] == "DNS_QUERY":
                return []
            row = self.feed_canonical(to_canonical(e), _evidence_windows(e))
            if row is not None and ref is not None:
                row.refs.append(ref)
            return [row] if row is not None else []
        raise ValueError("windows-cbc takes CanonicalEvents: use feed_canonical")

    def feed_event(self, e: dict, ref=None) -> list[Row]:
        """A normalized event as the central normalizer stores it (host_events.event): IL dataset export path."""
        if self.domain == "linux-audit":
            rows = self._linux([e])
        elif e.get("event_type") == "DNS_QUERY":
            rows = []
        else:
            row = self.feed_canonical(to_canonical(e), _evidence_windows(e))
            rows = [row] if row is not None else []
        for r in rows:
            if ref is not None:
                r.refs.append(ref)
        return rows

    def flush(self) -> list[Row]:
        return self._linux(self.stream.flush()) if self.domain == "linux-audit" else []

    def _linux(self, events) -> list[Row]:
        out = []
        for e in events:
            self.events_seen += 1
            toks = self.tk.tokens(e)               # None for non-row kinds (state still updated)
            if toks is None:
                continue
            out.append(Row(e["ts"], e["kind"], toks, _evidence_linux(e), list(e.get("refs") or [])))
        return out

    def feed_canonical(self, ce, evidence: dict | None = None) -> Row | None:
        """ATLASv2 build_host_shards.process_file_worker for one event (state updated before tokens, as there)."""
        self.events_seen += 1
        self.session.add_event(ce)
        if ce.event_type not in WINDOWS_ROW_TYPES:
            return None
        rec = canonical_ecar_record(ce, self.session)
        grouped, _audit = tokenize_record(rec)
        toks = flatten_tokens(grouped) + extract_domain_shift_tokens(ce, self.session, self.optc_tokens)
        return Row(ce.timestamp, ce.event_type, toks, evidence or {"ts": ce.timestamp, "event_type": ce.event_type,
                                                                     "path": ce.process_path, "tpath": ce.target_path})

    # ---------------------------------------------------------------- vectors
    def columns(self, row: Row) -> list[int]:
        cols, oov = set(), set()
        for t in row.tokens:
            c = self.vocab.get(t)
            if c is None:
                oov.add(t)
            else:
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
        return csr_matrix((np.ones(len(indices), np.float32), np.asarray(indices, np.int32),
                           np.asarray(indptr, np.int64)), shape=(len(rows), self.width))

    def drain_stats(self, top: int = 200) -> dict:
        """Counters since the last drain (endpoint summary -> central drift monitor / vocabulary extension)."""
        out = {"events": self.events_seen, "rows": self.rows_seen, "tokens": self.tokens_seen,
               "tokens_oov": self.tokens_oov, "oov_rate": self.tokens_oov / self.tokens_seen if self.tokens_seen else None,
               "oov_distinct": len(self.oov), "oov_top": self.oov.most_common(top)}
        self.oov = Counter()
        self.rows_seen = self.tokens_seen = self.tokens_oov = self.events_seen = 0
        return out
