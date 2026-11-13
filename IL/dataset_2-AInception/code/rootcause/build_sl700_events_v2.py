#!/usr/bin/env python3
"""SL700 events with Linux (Base-OpTC-style) tokens + causal parent / incoming (login session) context, and the
exact window grid of sl700_windows_v1 (same sample ids, labels and event lists), so that models trained on either
input are compared on identical samples.

Output (new dir): <out>/events.parquet  one row per event of a window (all runs/hosts), with
                     v1 token tuple (tok_*), Linux token groups (g_ev, g_par, g_ses, g_scope) as '\x1f'-joined strings
                  <out>/windows.pkl     [{sample_id, run, host, split, y, stages, stage_last, idx (event row ids),
                                          idx_fileread (row ids of fileread events inside the chunk)}]
"""
from __future__ import annotations

import argparse
import math
import pickle
import sys
from bisect import bisect_left, bisect_right
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, "/mnt/SSD_Data/optc/IL/dataset_2-AInception/code/DL")
import build_sl700_windows as V1  # noqa: E402
from linux_ctx import LinuxContextTracker  # noqa: E402

SEP = "\x1f"
GROUPS = ("g_ev", "g_par", "g_ses", "g_scope")


def group_of(tok: str) -> str:
    if "src_scope" in tok or tok.startswith("net:scope"):
        return "g_scope"
    if tok.startswith("ctx:session"):
        return "g_ses"
    if tok.startswith("ctx:"):
        return "g_par"
    return "g_ev"


def run_tokens(run_df: pd.DataFrame) -> dict:
    """index -> {group: [tokens]} for every row of run_df, tracker run per host over ALL events in time order."""
    out = {}
    for host, h in run_df.groupby("host"):
        h = h.sort_values(["ts", "line"], kind="stable")
        tr = LinuxContextTracker(with_scope=True)
        for idx, r in zip(h.index, h.to_dict("records")):
            for c in ("pid", "ppid"):
                r[c] = None if pd.isna(r[c]) else int(r[c])
            r["syscall"] = None if pd.isna(r["syscall"]) else int(r["syscall"])
            for c in ("uid", "auid", "ses"):
                r[c] = None if pd.isna(r[c]) else r[c]
            toks = tr.tokens(r)
            tr.observe(r)
            g = {k: [] for k in GROUPS}
            for t in toks:
                g[group_of(t)].append(t)
            out[idx] = g
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/rootcause_20261113/events_v2")
    ap.add_argument("--relabel", default=str(V1.RELABEL), help="relabel output dir (relabel_v2 or relabel_v3)")
    ap.add_argument("--ref", default="/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/sl700_windows_v1/dataset.pkl",
                    help="windows dataset built from the same labels, for the identity check")
    a = ap.parse_args()
    V1.RELABEL = Path(a.relabel)
    out = Path(a.out)
    if (out / "windows.pkl").exists():
        raise SystemExit(f"{out} exists")
    out.mkdir(parents=True, exist_ok=True)
    rows, windows = [], []
    gid = 0
    for run, split in V1.SPLIT.items():
        run_df = pd.read_parquet(V1.RELABEL / f"SL700_{run}/events.parquet",
                                 columns=["ts", "line", "host", "kind", "pid", "ppid", "image", "cmd", "tpath", "rip", "rport",
                                          "outbound", "user", "uid", "auid", "ses", "syscall", "y", "stage"])
        lt = run_tokens(run_df)
        # ---- identical to V1.build_run, carrying the DataFrame index
        df = run_df[run_df.kind.isin(V1.LABEL_KINDS + V1.EXTRA_KINDS)].sort_values("ts")
        fr_all = run_df[run_df.kind == "fileread"].sort_values("ts")
        for host, h in df.groupby("host"):
            full = run_df[run_df.host == host]
            pidx = V1.ProcIndex(full)
            pidx.pp = {}
            for pid, ppid in zip(full.pid, full.ppid):
                if pid is not None and not pd.isna(pid) and ppid is not None and not pd.isna(ppid):
                    pidx.pp.setdefault(int(pid), int(ppid))
            recs = []
            for i, r in zip(h.index, h.to_dict("records")):
                e = V1.event_record(r, pidx)
                e["gid"] = gid; gid += 1
                rows.append({"gid": e["gid"], "run": run, "host": host, "ts": e["ts"], "line": e["line"], "kind": e["kind_raw"],
                             "y": e["y"], "stage": e["stage"], **{f"tok_{f}": v for f, v in zip(V1.CAT_FIELDS, e["tok"])},
                             "flags": np.asarray(e["flags"], np.float32),
                             **{g: SEP.join(lt[i][g]) for g in GROUPS}})
                recs.append(e)
            fr = fr_all[fr_all.host == host]
            fr_g = []
            for i, r in zip(fr.index, fr.to_dict("records")):
                rows.append({"gid": gid, "run": run, "host": host, "ts": int(r["ts"]), "line": int(r["line"]), "kind": "fileread",
                             "y": -1, "stage": 0, **{f"tok_{f}": "NA" for f in V1.CAT_FIELDS}, "flags": np.zeros(18, np.float32),
                             **{g: SEP.join(lt[i][g]) for g in GROUPS}})
                fr_g.append((int(r["ts"]), gid)); gid += 1
            fr_ts = [x[0] for x in fr_g]
            lab = [e for e in recs if e["kind_raw"] in V1.LABEL_KINDS]
            extra = [e for e in recs if e["kind_raw"] in V1.EXTRA_KINDS]
            if len(lab) < 2:
                continue
            ts_lab = [e["ts"] for e in lab]; ts_ex = [e["ts"] for e in extra]
            cur, w = ts_lab[0], 0
            while cur <= ts_lab[-1]:
                li, ri = bisect_left(ts_lab, cur), bisect_right(ts_lab, cur + V1.WINDOW)
                if ri - li >= 2:
                    evs = lab[li:ri]
                    for ci in range(math.ceil(len(evs) / V1.MAX_LEN)):
                        ch = evs[ci * V1.MAX_LEN:(ci + 1) * V1.MAX_LEN]
                        lo, hi = ch[0]["ts"], ch[-1]["ts"]
                        allev = sorted(ch + extra[bisect_left(ts_ex, lo):bisect_right(ts_ex, hi)],
                                       key=lambda e: (e["ts"], e["kind_raw"] == "filemod"))
                        att = [e for e in ch if e["y"] == 1]
                        windows.append({"sample_id": f"{host}_{run}_w{w:04d}_c{ci:02d}", "run": run, "host": host, "split": split,
                                        "y": int(bool(att)), "stages": sorted({e["stage"] for e in att}),
                                        "stage_last": att[-1]["stage"] if att else 0,
                                        "idx": np.asarray([e["gid"] for e in allev], np.int64),
                                        "idx_fileread": np.asarray([g for _, g in fr_g[bisect_left(fr_ts, lo):bisect_right(fr_ts, hi)]], np.int64)})
                    w += 1
                cur += V1.STRIDE
        print(run, split, "windows so far", len(windows), "events", len(rows), flush=True)
    ev = pd.DataFrame(rows)
    ev.to_parquet(out / "events.parquet")
    with open(out / "windows.pkl", "wb") as fh:
        pickle.dump(windows, fh, protocol=pickle.HIGHEST_PROTOCOL)
    # ---- check: same windows / labels as v1
    blob = pickle.load(open(a.ref, "rb"))
    v1 = {s["sample_id"]: (s["y"], len(s["ev_y"])) for sp in blob["splits"].values() for s in sp}
    v2 = {w["sample_id"]: (w["y"], len(w["idx"])) for w in windows}
    print("v1 == v2 windows (ids, y, length):", v1 == v2, len(v1), len(v2))
    print("token groups, distinct tokens:", {g: len(Counter(t for s in ev[g] for t in s.split(SEP) if t)) for g in GROUPS})


if __name__ == "__main__":
    main()
