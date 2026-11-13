"""Central DL input: per-host streaming windows for the IL BiLSTM and the model runtime.

Training recipes reproduced (event fields come from the vendored training code):
  linux-audit     build_sl700_windows.py (event_record: parent-centric procstart, OpTC contract tokens, cmd flags)
                  + build_sl700_events_v2.py (bag of Linux tokens per event: LinuxContextTracker groups g_ev, g_par,
                  g_ses) ; label-bearing kinds procstart, netconn, crossproc, auth, privchange; filemod input-only.
  windows-*       bilstm_v9/build_dataset.py (event_tokens + optc_tokens + cmd flags) on CBC-like records
                  (sysmon.to_dl_record, or parse_events.py records for CBC); label-bearing netconn, procstart,
                  crossproc; filemod input-only; no bag.
Windows of 180 s every 30 s with >= 2 label-bearing events, split into chunks of <= 512 label-bearing events, plus the
input-only events inside each chunk; encoded as num = 18 command-line flags + [dt, rel, is_input_only].
Live windows are emitted once `watermark` (now - allowed lateness) passed their end; the grid is aligned to absolute
time (origin 0) live, and to the first label-bearing event in the parity tests (as the training builders).
"""
from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from collections import defaultdict

import numpy as np

from ._vendor import dl_atlas_events as AT
from ._vendor import dl_sl700_events as SL
from ._vendor.dl_bag_groups import group_of
from ._vendor.dl_contract import FIELDS, optc_tokens
from ._vendor.linux_ctx import LinuxContextTracker

WINDOW_US, STRIDE_US, MAX_LEN = 180_000_000, 30_000_000, 512
STAGES = {1: "initial_compromise", 2: "execution_discovery", 3: "lateral_movement", 4: "exfiltration", 5: "impact"}


# ---------------------------------------------------------------------------------------------------- Linux events
class ProcHistory:
    """Online build_sl700_windows.ProcIndex: pid -> time-ordered (ts, exe, cmd) of its events, plus .pp (pid -> first
    ppid seen). Events must be added in (ts, serial) order; at(pid, ts) only uses entries with t <= ts, so adding a
    whole batch before computing its records equals the offline index built over the full run."""

    def __init__(self, horizon_us: int = 24 * 3600 * 1_000_000):
        self.d = defaultdict(list)
        self.t = defaultdict(list)
        self.pp = {}
        self.horizon_us = horizon_us

    def add(self, e):
        pid = e.get("pid")
        if pid is not None and e.get("image"):
            self.d[pid].append((e["ts"], e["image"], e.get("cmd") or "" if e["kind"] == "procstart" else ""))
            self.t[pid].append(e["ts"])
        if pid is not None and e.get("ppid") is not None:
            self.pp.setdefault(int(pid), int(e["ppid"]))

    def at(self, pid, ts):
        if pid is None or SL._isna(pid) or int(pid) not in self.d:
            return "", ""
        p = int(pid)
        i = bisect_right(self.t[p], ts) - 1
        if i < 0:
            return "", ""
        v = self.d[p]
        img = v[i][1]
        cmd = next((c for _, im, c in reversed(v[:i + 1]) if c), "")
        return img, cmd

    def prune(self, now_us: int):
        """Drop history older than the horizon, keeping the latest entry (and latest command) of every pid."""
        cut = now_us - self.horizon_us
        for p in list(self.d):
            v = self.d[p]
            if len(v) > 1 and v[0][0] < cut:
                keep = [x for x in v if x[0] >= cut]
                last_cmd = next(((t, im, c) for t, im, c in reversed(v) if c), None)
                if not keep:
                    keep = [v[-1]]
                if last_cmd is not None and last_cmd[0] < keep[0][0]:
                    keep = [last_cmd] + keep
                self.d[p] = keep
                self.t[p] = [x[0] for x in keep]


class LinuxDLState:
    """Per-host state for linux-audit events (dicts from auditd build_audit_event, in (ts, serial) order)."""

    bag_groups = ("g_ev", "g_par", "g_ses")

    def __init__(self):
        self.pidx = ProcHistory()
        self.tracker = LinuxContextTracker(with_scope=False)   # scope tokens (g_scope) are not a model input

    def records(self, events: list[dict]) -> list[dict]:
        bags = []
        for e in events:
            toks = self.tracker.tokens(e)
            self.tracker.observe(e)
            bags.append([t for t in toks if group_of(t) in self.bag_groups])
            self.pidx.add(e)
        out = []
        for e, bag in zip(events, bags):
            if e["kind"] not in SL.LABEL_KINDS + SL.EXTRA_KINDS:
                continue
            r = dict(e)
            r.setdefault("y", 0)
            r.setdefault("stage", 0)
            rec = SL.event_record(r, self.pidx)
            rec["is_label"] = e["kind"] in SL.LABEL_KINDS
            rec["bag"] = bag
            rec["ref"] = e.get("ref")
            out.append(rec)
        return out


# ---------------------------------------------------------------------------------------------------- Windows events
def windows_record(r: dict) -> dict:
    """parse_events-style record -> DL event (build_dataset.py token/flag recipe)."""
    rec = {"ts": int(r["ts"]), "line": int(r.get("line") or 0), "host": r.get("host", ""), "kind_raw": r["kind"],
           "is_label": r["kind"] in AT.LABEL_KINDS, "bag": [], "ref": r.get("ref")}
    t = AT.event_tokens(r)
    rec["tok"] = tuple(t[f] for f in AT.CAT_FIELDS)
    rec["optc"] = optc_tokens(r)
    rec["flags"] = AT.cmd_flags(r["cmd"]) + (AT.cmd_flags(r["tcmd"]) if r["kind"] == "procstart" else [0.0] * len(AT.CMD_FLAGS))
    rec["actor_path"] = r.get("path", "")
    return rec


# ---------------------------------------------------------------------------------------------------- windowing
class Windower:
    """Sliding windows over one host's DL records (training grid semantics)."""

    def __init__(self, origin_us: int | None = 0):
        self.lab, self.ts_lab = [], []
        self.extra, self.ts_ex = [], []
        self.origin = origin_us          # None = first label-bearing event (training builders)
        self.cur = None
        self.w = 0
        self.last_ts = -1

    def add(self, recs: list[dict]) -> int:
        """Append records in time order; returns the number of late records dropped (older than the next window)."""
        late = 0
        for r in recs:
            if self.cur is not None and r["ts"] < self.cur:
                late += 1
                continue
            if r["is_label"]:
                if self.cur is None:
                    self.cur = r["ts"] if self.origin is None else r["ts"] - (r["ts"] - self.origin) % STRIDE_US
                i = bisect_right(self.ts_lab, r["ts"])        # in-order input appends; a late record is inserted
                self.lab.insert(i, r); self.ts_lab.insert(i, r["ts"])
            else:
                i = bisect_right(self.ts_ex, r["ts"])
                self.extra.insert(i, r); self.ts_ex.insert(i, r["ts"])
            self.last_ts = max(self.last_ts, r["ts"])
        return late

    def ready(self, watermark_us: int | None, final: bool = False):
        """Yield (window_index, chunk_index, start, end, events) for windows whose end <= watermark; `final` also emits
        the trailing windows that start at or before the last label-bearing event (training behaviour at run end)."""
        while self.cur is not None and self.ts_lab:
            end = self.cur + WINDOW_US
            if final:
                if self.cur > self.ts_lab[-1]:
                    break
            elif watermark_us is None or end > watermark_us:
                break
            li, ri = bisect_left(self.ts_lab, self.cur), bisect_right(self.ts_lab, end)
            if ri - li >= 2:
                evs = self.lab[li:ri]
                for ci in range(math.ceil(len(evs) / MAX_LEN)):
                    ch = evs[ci * MAX_LEN:(ci + 1) * MAX_LEN]
                    lo, hi = ch[0]["ts"], ch[-1]["ts"]
                    allev = sorted(ch + self.extra[bisect_left(self.ts_ex, lo):bisect_right(self.ts_ex, hi)],
                                   key=lambda e: (e["ts"], e["kind_raw"] == "filemod"))
                    yield self.w, ci, self.cur, end, allev
                self.w += 1
            self.cur += STRIDE_US
            self._prune()

    def _prune(self):
        i = bisect_left(self.ts_lab, self.cur)
        j = bisect_left(self.ts_ex, self.cur)
        if i > 4096:
            del self.lab[:i], self.ts_lab[:i]
        if j > 4096:
            del self.extra[:j], self.ts_ex[:j]


def encode(events: list[dict]) -> dict:
    """build_sl700_windows.encode / build_dataset encoding: raw tokens + num = flags + [dt, rel, is_input_only]."""
    ts = np.asarray([e["ts"] for e in events], dtype=np.float64)
    dt = np.log1p(np.diff(ts, prepend=ts[0]) / 1e6).astype(np.float32)
    rel = np.log1p((ts - ts[0]) / 1e6).astype(np.float32) / math.log1p(180.0)
    isx = np.asarray([e["kind_raw"] == "filemod" for e in events], dtype=np.float32)
    flags = np.asarray([e["flags"] for e in events], dtype=np.float32)
    return {"tok_raw": [e["tok"] for e in events], "optc_raw": [e["optc"] for e in events],
            "num": np.concatenate([flags, np.stack([dt, rel, isx], 1)], 1), "bag_raw": [e["bag"] for e in events]}


# ---------------------------------------------------------------------------------------------------- model runtime
class DLVocab:
    """Bundle vocabularies: OpTC-contract ids (ext), host-context ids (ctx_vocab), Linux token bag ids."""

    def __init__(self, blob: dict):
        self.fields = blob["fields"]
        assert self.fields == FIELDS
        self.ext = blob["ext"]
        self.cat_fields = blob["cat_fields"]
        self.ctx_fields = blob["ctx_fields"]
        self.ctx_vocab = blob["ctx_vocab"]
        self.pos = [self.cat_fields.index(f) for f in self.ctx_fields]
        self.bag_vocab = blob["bag_vocab"]
        self.bag_max = int(blob["bag_max"])
        self.num_dim = int(blob["num_dim"])
        self.n_cmd = self.num_dim - 3

    def sample(self, enc: dict, with_bag: bool) -> dict:
        ids = np.array([[1 if v == "<MISSING>" else self.ext[f].get(v, 0) for f, v in zip(self.fields, ev)]
                        for ev in enc["optc_raw"]], dtype=np.int64)
        cc = np.array([[self.ctx_vocab[f].get(tok[p], 1) for f, p in zip(self.ctx_fields, self.pos)]
                       for tok in enc["tok_raw"]], dtype=np.int64)
        s = {"x_cat": ids, "delta": enc["num"][:, self.n_cmd].astype(np.float32), "ctx_cat": cc,
             "ctx_num": enc["num"].astype(np.float32)}
        if with_bag:
            rows = [sorted({self.bag_vocab.get(t, 1) for t in toks})[:self.bag_max] for toks in enc["bag_raw"]]
            b = np.zeros((len(rows), max(1, max((len(r) for r in rows), default=1))), np.int64)
            for j, r in enumerate(rows):
                b[j, :len(r)] = r
            s["bag"] = b
        return s

    def oov(self, enc: dict) -> dict:
        """Unknown values per input (drift / vocabulary-extension evidence)."""
        out = {"optc": 0, "ctx": 0, "bag": 0, "events": len(enc["optc_raw"])}
        for ev in enc["optc_raw"]:
            out["optc"] += sum(1 for f, v in zip(self.fields, ev) if v != "<MISSING>" and v not in self.ext[f])
        for tok in enc["tok_raw"]:
            out["ctx"] += sum(1 for f, p in zip(self.ctx_fields, self.pos) if tok[p] not in self.ctx_vocab[f])
        for toks in enc["bag_raw"]:
            out["bag"] += sum(1 for t in set(toks) if t not in self.bag_vocab)
        return out


def build_model(state_dict: dict, config: dict):
    """IL BiLSTM (OpTC base + host-context branch + 2nd BiLSTM + event/stage heads + Linux bag) sized from the bundle."""
    import torch.nn as nn
    from ._vendor.dl_base_model import BiLSTMBaseline
    from ._vendor.dl_il_bag_model import ILBiLSTMBag
    from ._vendor.dl_il_model import ILBiLSTM

    base = BiLSTMBaseline(categorical_cardinalities=config["base_cardinalities"], numerical_dim=0,
                          event_dim=config["event_dim"], hidden_dim=config["hidden_dim"],
                          lstm_layers=config["lstm_layers"], dropout=config["dropout"])
    sd = state_dict
    n_new = [sd[f"embeddings.{i}.new.weight"].shape[0] for i in range(len(config["base_cardinalities"]))]
    n_ctx = len(config["ctx_fields"])
    model = ILBiLSTM(base, n_new, [sd[f"ctx_embs.{j}.weight"].shape[0] for j in range(n_ctx)], config["num_dim"],
                     hidden2=config["hidden2"])
    # vocabulary growth kept the embedding widths of the step that created each table: size every grown module from
    # the checkpoint instead of re-deriving it from cardinalities
    for j in range(n_ctx):
        rows, dim = sd[f"ctx_embs.{j}.weight"].shape
        model.ctx_embs[j] = nn.Embedding(rows, dim, padding_idx=0)
    out_f, in_f = sd["ctx_proj.0.weight"].shape
    model.ctx_proj[0] = nn.Linear(in_f, out_f)
    out_f, in_f = sd["stage_head.2.weight"].shape
    model.stage_head[-1] = nn.Linear(in_f, out_f)
    if "bag_emb.weight" in sd:
        n_tok, dim = sd["bag_emb.weight"].shape
        model.__class__ = ILBiLSTMBag
        model.bag_emb = nn.EmbeddingBag(n_tok, dim, mode="mean", padding_idx=0)
    model.load_state_dict(sd, strict=True)
    return model.eval()


def collate(samples: list[dict], with_bag: bool, device="cpu"):
    """train_il_step3(_v2).collate for context-bearing domains (has_ctx = 1). with_bag: the model has the bag branch
    (samples of domains without Linux tokens get an all-padding bag, as the ATLASv2 windows had in training)."""
    import torch
    B = len(samples); L = max(len(s["delta"]) for s in samples)
    ref = next(s for s in samples if s.get("ctx_cat") is not None) if any(s.get("ctx_cat") is not None for s in samples) else None
    n_ctx = ref["ctx_cat"].shape[1] if ref else samples[0].get("n_ctx", 10)
    cnd = ref["ctx_num"].shape[1] if ref else samples[0].get("cnd", 21)
    x = np.zeros((B, L, len(FIELDS)), np.int64); d = np.zeros((B, L, 1), np.float32)
    cc = np.zeros((B, L, n_ctx), np.int64); cn = np.zeros((B, L, cnd), np.float32)
    K = max((s["bag"].shape[1] for s in samples if "bag" in s), default=1)
    bag = np.zeros((B, L, K), np.int64)
    has = np.ones(B, np.float32)
    for i, s in enumerate(samples):
        n = len(s["delta"])
        x[i, :n] = s["x_cat"]; d[i, :n, 0] = s["delta"]
        if s.get("ctx_cat") is not None:          # OpTC flows (training replay) carry no host context: has_ctx = 0
            cc[i, :n] = s["ctx_cat"]; cn[i, :n] = s["ctx_num"]
        has[i] = float(s.get("has_ctx", 1.0))
        if "bag" in s:
            bag[i, :n, :s["bag"].shape[1]] = s["bag"]
    t = lambda a: torch.from_numpy(a).to(device)
    inp = dict(x_cat=t(x), delta=t(d), ctx_cat=t(cc), ctx_num=t(cn), has_ctx=t(has),
               lengths=torch.tensor([len(s["delta"]) for s in samples], device=device))
    if with_bag:
        inp["bag"] = t(bag)
    return inp


def predict(model, samples: list[dict], device="cpu", bs: int = 64) -> list[dict]:
    """Window logit z, per-event attack logits and the stage read-out of train_il_step3.predict(with_events=True)."""
    import torch
    import torch.nn.functional as F
    with_bag = hasattr(model, "bag_emb")
    out = [None] * len(samples)
    order = np.argsort([len(s["delta"]) for s in samples])
    with torch.no_grad():
        for i in range(0, len(samples), bs):
            idx = order[i:i + bs]
            inp = collate([samples[j] for j in idx], with_bag, device)
            z, _z_old, ev, st, mask = model(**inp)
            joint = (F.logsigmoid(ev)[..., None] + F.log_softmax(st, -1)).masked_fill(~mask[..., None], -1e4)
            alert = (ev >= 0) & mask
            ar = torch.arange(ev.size(1), device=ev.device)[None].expand_as(ev)
            li = torch.where(alert, ar, torch.full_like(ar, -1)).max(1).values
            sk = joint.max(1).values
            lp = torch.where(li >= 0, st.argmax(-1).gather(1, li.clamp(min=0)[:, None]).squeeze(1), sk.argmax(-1))
            for row, j in enumerate(idx):
                n = int(inp["lengths"][row])
                out[j] = {"z": float(z[row]), "event_logits": ev[row, :n].float().cpu().numpy(),
                          "stage_presence": sk[row].float().cpu().numpy(), "stage_last": int(lp[row]) + 1}
    return out
