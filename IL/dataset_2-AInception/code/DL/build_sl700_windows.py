#!/usr/bin/env python3
"""AInception SL700 -> windows in the ATLASv2/optc_il format (IL step 3: OpTC -> ATLASv2 -> SL700).

Input : output/relabel_v2/SL700_<run>/events.parquet (auditd canonical events + y + per-process stage).
Output: output/sl700_windows_v1/dataset.pkl  {"meta": ..., "splits": {"train"/"val"/"test": [sample, ...]}}

Same recipe as bilstm_v9/build_dataset.py: 180 s windows, 30 s stride, >= 2 label-bearing events, chunks of
<= 512 label-bearing events, input-only file events added inside each chunk. Differences, all Linux-specific:
  * label-bearing kinds: procstart, netconn, crossproc (as ATLASv2) + auth and privchange (ssh/sudo logins and
    set*id calls carry the SL700 attack; ATLASv2 has no such events); input-only: filemod;
  * a procstart event is parent-centric like the CBC-EDR one: actor = exe of the parent (ppid), target = the
    new image; actor/target directories use contract.image_dir_class (has Linux classes);
  * user from the audit uid: 0 -> SYSTEM_ACCOUNT, 1..999 -> SERVICE_ACCOUNT, >= 1000 -> DOMAIN_USER;
  * no code signing on Linux: pub/tpub NONE.
Context tokens are stored raw (strings) and encoded by the step-3 trainer after extending the ATLASv2 vocabulary.
Split by run, fixed before any training: train a_a, a_b, b_a, e_a; val a_c (unseen persistence variant c);
test f_a (unseen privilege-escalation variant f).
"""
from __future__ import annotations

import argparse
import json
import math
import pickle
import sys
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

DL = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL")
sys.path.insert(0, str(DL / "optc_il"))
sys.path.insert(0, str(DL / "bilstm_v9"))
sys.path.insert(0, str(DL.parent))
sys.path.insert(0, str(DL / "preprocess"))
from contract import image_dir_class, optc_tokens  # noqa: E402
from build_dataset import CAT_FIELDS, cmd_flags, CMD_FLAGS, ip_scope  # noqa: E402
from build_network_shards import map_resp_port_class  # noqa: E402

RELABEL = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v2")
SPLIT = {"a_a": "train", "a_b": "train", "b_a": "train", "e_a": "train", "a_c": "val", "f_a": "test"}
LABEL_KINDS = ("procstart", "netconn", "crossproc", "auth", "privchange")
EXTRA_KINDS = ("filemod",)
WINDOW, STRIDE, MAX_LEN = 180_000_000, 30_000_000, 512
DELETE_SC = {84, 87, 263}


def base(p):
    return (p or "").rstrip("/").split("/")[-1].lower()


def user_class(u):
    u = (u or "").strip()
    if u in ("", "-", "unset", "4294967295"):
        return "NONE"
    if u.isdigit():
        n = int(u)
        return "SYSTEM_ACCOUNT" if n == 0 else ("SERVICE_ACCOUNT" if n < 1000 else "DOMAIN_USER")
    return "SYSTEM_ACCOUNT" if u == "root" else "DOMAIN_USER"


class ProcIndex:
    """pid -> time-ordered (ts, exe, cmd) seen in any event of that pid (auditd reports exe= on every syscall)."""

    def __init__(self, df):
        self.d = defaultdict(list)
        for ts, pid, img, cmd, kind in zip(df.ts, df.pid, df.image, df.cmd, df.kind):
            if pid is not None and not pd.isna(pid) and img:
                self.d[int(pid)].append((ts, img, cmd if kind == "procstart" else ""))
        self.t = {}
        for p, v in self.d.items():
            v.sort(key=lambda x: x[0])
            self.t[p] = [x[0] for x in v]

    def at(self, pid, ts):
        if pid is None or pd.isna(pid) or int(pid) not in self.d:
            return "", ""
        p = int(pid)
        i = bisect_right(self.t[p], ts) - 1
        if i < 0:
            return "", ""
        v = self.d[p]
        img = v[i][1]
        cmd = next((c for _, im, c in reversed(v[:i + 1]) if c), "")
        return img, cmd


def event_record(r, pidx):
    k = r["kind"]
    out = {"ts": int(r["ts"]), "line": int(r["line"]), "host": r["host"], "kind_raw": k,
           "y": int(r["y"]) if k in LABEL_KINDS else -1, "stage": int(r["stage"]) if k in LABEL_KINDS else 0}
    img, cmd = r["image"] or "", r["cmd"] or ""
    pimg, pcmd = pidx.at(r["ppid"], r["ts"])
    t = {"user": user_class(r["user"]), "pub": "NONE", "tpub": "NA", "net": "NA", "ip_scope": "NA",
         "target": "NA", "target_dir": "NA"}
    path = img
    if k == "procstart":
        # parent-centric like CBC-EDR: actor = parent image, target = new image
        t.update(kind="procstart", actor=base(pimg) or "<NONE>", actor_dir=image_dir_class(pimg) if pimg else "MISSING",
                 target=base(img) or "<NONE>", target_dir=image_dir_class(img) if img else "MISSING", tpub="NONE")
        gimg, _ = pidx.at(pidx_ppid(pidx, r), r["ts"])
        t["parent"] = base(gimg) or "<NONE>"
        path = pimg
        flags = cmd_flags(pcmd) + cmd_flags(cmd)
        rec_for_optc = {"kind": "procstart", "path": pimg}
    else:
        t.update(actor=base(img) or "<NONE>", actor_dir=image_dir_class(img) if img else "MISSING", parent=base(pimg) or "<NONE>")
        flags = cmd_flags(cmd) + [0.0] * len(CMD_FLAGS)
        rec_for_optc = {"kind": "other", "path": img}
        if k == "netconn":
            inbound = not bool(r["outbound"])
            port = None if pd.isna(r["rport"]) else int(r["rport"])
            t["kind"] = "net_in" if inbound else "net_out"
            # accept(): auditd gives the peer address only, so the local (responder) port is unknown
            t["net"] = f"tcp:{'MISSING' if inbound or port is None else map_resp_port_class(port)}:nodom"
            t["ip_scope"] = ip_scope(r["rip"] or "")
            rec_for_optc = {"kind": "netconn", "path": img, "proto": "TCP", "inbound": inbound,
                            "rport": port, "lport": None}
        elif k == "crossproc":
            t["kind"] = "xp:open_process"
        elif k in ("auth", "privchange"):
            t["kind"] = k
        else:  # filemod
            sc = None if pd.isna(r["syscall"]) else int(r["syscall"])
            t["kind"] = "file_delete" if sc in DELETE_SC else "file_write"
            t["target"] = "FILE:OTHER"
            t["target_dir"] = image_dir_class(r["tpath"]) if r["tpath"] else "MISSING"
    out["tok"] = tuple(t[f] for f in CAT_FIELDS)
    out["optc"] = optc_tokens(rec_for_optc)
    out["flags"] = flags
    out["actor_path"] = path
    return out


def pidx_ppid(pidx, r):
    """ppid of the parent (grandparent pid) from the parent's own events (needed for the 'parent' context token)."""
    pp = r["ppid"]
    if pp is None or pd.isna(pp):
        return None
    return pidx.pp.get(int(pp))


def build_run(run):
    run_df = pd.read_parquet(RELABEL / f"SL700_{run}/events.parquet",
                            columns=["ts", "line", "host", "kind", "pid", "ppid", "image", "cmd", "tpath", "rip", "rport",
                                     "outbound", "user", "syscall", "y", "stage"])
    df = run_df[run_df.kind.isin(LABEL_KINDS + EXTRA_KINDS)].sort_values("ts")
    samples = []
    for host, h in df.groupby("host"):
        full = run_df[run_df.host == host]
        pidx = ProcIndex(full)
        pidx.pp = {}
        for pid, ppid in zip(full.pid, full.ppid):
            if pid is not None and not pd.isna(pid) and ppid is not None and not pd.isna(ppid):
                pidx.pp.setdefault(int(pid), int(ppid))
        recs = [event_record(r, pidx) for r in h.to_dict("records")]
        lab = [e for e in recs if e["kind_raw"] in LABEL_KINDS]
        extra = [e for e in recs if e["kind_raw"] in EXTRA_KINDS]
        if len(lab) < 2:
            continue
        ts_lab = [e["ts"] for e in lab]
        ts_ex = [e["ts"] for e in extra]
        cur, w = ts_lab[0], 0
        while cur <= ts_lab[-1]:
            li, ri = bisect_left(ts_lab, cur), bisect_right(ts_lab, cur + WINDOW)
            if ri - li >= 2:
                evs = lab[li:ri]
                for ci in range(math.ceil(len(evs) / MAX_LEN)):
                    ch = evs[ci * MAX_LEN:(ci + 1) * MAX_LEN]
                    lo, hi = ch[0]["ts"], ch[-1]["ts"]
                    allev = sorted(ch + extra[bisect_left(ts_ex, lo):bisect_right(ts_ex, hi)],
                                   key=lambda e: (e["ts"], e["kind_raw"] == "filemod"))
                    att = [e for e in ch if e["y"] == 1]
                    samples.append({"sample_id": f"{host}_{run}_w{w:04d}_c{ci:02d}", "run": run, "host": host,
                                    "start": lo, "end": hi, "y": int(bool(att)),
                                    "stages": sorted({e["stage"] for e in att}),
                                    "stage_last": att[-1]["stage"] if att else 0, "events": allev})
                w += 1
            cur += STRIDE
    return samples


def encode(s):
    evs = s["events"]
    ts = np.asarray([e["ts"] for e in evs], dtype=np.float64)
    dt = np.log1p(np.diff(ts, prepend=ts[0]) / 1e6).astype(np.float32)
    rel = np.log1p((ts - ts[0]) / 1e6).astype(np.float32) / math.log1p(180.0)
    isx = np.asarray([e["kind_raw"] == "filemod" for e in evs], dtype=np.float32)
    flags = np.asarray([e["flags"] for e in evs], dtype=np.float32)
    return {k: s[k] for k in ("sample_id", "run", "host", "start", "end", "y", "stages", "stage_last")} | {
        "tok_raw": [e["tok"] for e in evs], "optc_raw": [e["optc"] for e in evs],
        "num": np.concatenate([flags, np.stack([dt, rel, isx], 1)], 1),
        "ev_y": np.asarray([e["y"] for e in evs], dtype=np.int8),
        "ev_stage": np.asarray([e["stage"] for e in evs], dtype=np.int8),
        "is_extra": isx.astype(bool),
        "trace": [(e["line"], e["kind_raw"], e["tok"][1], e["tok"][4]) for e in evs]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/sl700_windows_v1")
    a = ap.parse_args()
    out = Path(a.out)
    if (out / "dataset.pkl").exists():
        raise SystemExit(f"{out}/dataset.pkl exists")
    out.mkdir(parents=True, exist_ok=True)
    splits = {"train": [], "val": [], "test": []}
    for run, sp in SPLIT.items():
        ss = [encode(s) for s in build_run(run)]
        splits[sp] += ss
        print(f"{run} ({sp}): windows {len(ss)}, pos {sum(s['y'] for s in ss)}, by host "
              f"{dict(Counter(s['host'] for s in ss))}, stages presence {dict(Counter(k for s in ss for k in s['stages']))}", flush=True)
    meta = {"cat_fields": CAT_FIELDS, "num_dim": int(splits["train"][0]["num"].shape[1]), "split": SPLIT,
            "label_kinds": LABEL_KINDS, "extra_kinds": EXTRA_KINDS, "window_sec": 180, "stride_sec": 30, "max_len": MAX_LEN,
            "counts": {sp: {"windows": len(v), "pos": sum(s["y"] for s in v),
                            "stage_last": dict(Counter(s["stage_last"] for s in v if s["y"])),
                            "presence": dict(Counter(k for s in v for k in s["stages"])),
                            "median_len": int(np.median([len(s["num"]) for s in v]))} for sp, v in splits.items()}}
    with open(out / "dataset.pkl", "wb") as fh:
        pickle.dump({"meta": meta, "splits": splits}, fh, protocol=pickle.HIGHEST_PROTOCOL)
    (out / "dataset_meta.json").write_text(json.dumps(meta, indent=2, default=str))
    print(json.dumps(meta["counts"], indent=1, default=str))


if __name__ == "__main__":
    main()
