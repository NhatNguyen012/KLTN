#!/usr/bin/env python3
"""Host-ML matrices for ML IL step 3 (OpTC -> ATLASv2 -> AInception SL700), same contract as the ATLASv2 step.

Rows: SL700 auditd events of kind procstart, filemod, fileread, auth, privchange (network flows are not rows, as in
OpTC/ATLASv2 host ML), all hosts, labels from relabel_v3. Features: binary tokens (sl700_ecar.py) in the ATLASv2
vocabulary (vocab_extended.json, 12,365 columns = frozen OpTC 10,317 + ATLASv2 2,048), extended monotonically
with tokens seen in SL700 TRAIN rows. Split by run, as the DL step: train a_a, a_b, b_a, e_a / val a_c / test f_a.

Output (new dir): train.npz / val.npz / test.npz (CSR data, indices, indptr, shape, labels),
  meta_<split>.parquet (run, host, ts, line, kind, stage), vocab_sl700.json, columns.json (group of every new column),
  build_report.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sl700_ecar import ROW_KINDS, Sl700Tokenizer  # noqa: E402

RELABEL = Path("/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/relabel_v3")
ATLAS_VOCAB = Path("/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/ML/preprocess/output/assets/vocab_extended.json")
SPLIT = {"a_a": "train", "a_b": "train", "b_a": "train", "e_a": "train", "a_c": "val", "f_a": "test"}
SCOPE = ("lx:auth:src_scope", "lx:net:scope", "lx:ctx:session:src_scope")
COLS = ["ts", "line", "host", "kind", "pid", "ppid", "image", "cmd", "tpath", "rip", "rport", "outbound", "user",
        "uid", "auid", "ses", "syscall", "y", "stage"]


def group(tok: str) -> str:
    if tok.startswith(SCOPE):
        return "lx_scope"
    return "lx" if tok.startswith("lx:") else "ecar"


def tokenize_run(run: str):
    df = pd.read_parquet(RELABEL / f"SL700_{run}/events.parquet", columns=COLS)
    rows, meta = [], []
    for host, h in df.groupby("host"):
        tk = Sl700Tokenizer(with_scope=True)
        for r in h.sort_values(["ts", "line"], kind="stable").to_dict("records"):
            for c in ("pid", "ppid", "syscall"):
                r[c] = None if pd.isna(r[c]) else int(r[c])
            toks = tk.tokens(r)
            if toks is None:
                continue
            rows.append(sorted(set(toks)))
            meta.append((run, host, int(r["ts"]), int(r["line"]), r["kind"], int(r["y"]), int(r["stage"])))
    return run, rows, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/mnt/SSD_Data/optc/IL/dataset_2-AInception/output/ml_il_step3_20261113/data")
    a = ap.parse_args()
    out = Path(a.out)
    if (out / "build_report.json").exists():
        raise SystemExit(f"{out} exists")
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with ProcessPoolExecutor(6) as ex:
        res = {run: (rows, meta) for run, rows, meta in ex.map(tokenize_run, SPLIT)}
    print(f"tokenized in {time.time() - t0:.0f}s:", {r: len(v[0]) for r, v in res.items()}, flush=True)
    vocab = json.loads(ATLAS_VOCAB.read_text())
    base_width = len(vocab)
    assert base_width == 12365 and max(vocab.values()) == base_width - 1
    cnt = Counter(t for run, (rows, _) in res.items() if SPLIT[run] == "train" for row in rows for t in row if t not in vocab)
    new = [t for t, _ in sorted(cnt.items(), key=lambda x: (-x[1], x[0]))]
    ext = dict(vocab)
    for t in new:
        ext[t] = len(ext)
    width = len(ext)
    groups = {"ecar_new": 0, "lx": 0, "lx_scope": 0}
    col_group = {}
    for t in new:
        g = group(t)
        col_group[ext[t]] = g
        groups["ecar_new" if g == "ecar" else g] += 1
    report = {"base_width_atlasv2": base_width, "extended_width": width, "new_train_tokens": len(new), "new_by_group": groups,
              "row_kinds": list(ROW_KINDS), "split": SPLIT, "splits": {}}
    for sp in ("train", "val", "test"):
        indptr, indices, labels, meta, hit_old, n_tok = [0], [], [], [], 0, 0
        for run in [r for r, s in SPLIT.items() if s == sp]:
            rows, m = res[run]
            for row, mm in zip(rows, m):
                ids = sorted(ext[t] for t in row if t in ext)
                hit_old += sum(1 for i in ids if i < base_width); n_tok += len(row)
                indices += ids; indptr.append(len(indices)); labels.append(mm[5]); meta.append(mm)
        y = np.asarray(labels, np.uint8)
        np.savez_compressed(out / f"{sp}.npz", data=np.ones(len(indices), np.float32), indices=np.asarray(indices, np.int32),
                            indptr=np.asarray(indptr, np.int64), shape=np.asarray([len(labels), width]), labels=y)
        md = pd.DataFrame(meta, columns=["run", "host", "ts", "line", "kind", "y", "stage"])
        md.to_parquet(out / f"meta_{sp}.parquet", index=False)
        report["splits"][sp] = {"rows": len(labels), "attack": int(y.sum()), "nnz": len(indices),
                                "tokens_in_atlasv2_vocab": round(hit_old / max(1, n_tok), 4),
                                "attack_by_kind": md[md.y == 1].kind.value_counts().to_dict(),
                                "rows_by_kind": md.kind.value_counts().to_dict()}
        print(sp, json.dumps(report["splits"][sp]), flush=True)
    (out / "vocab_sl700.json").write_text(json.dumps(ext))
    (out / "columns.json").write_text(json.dumps({str(k): v for k, v in col_group.items()}))
    (out / "build_report.json").write_text(json.dumps(report, indent=1))
    print(json.dumps({k: v for k, v in report.items() if k != "splits"}), f"[{time.time() - t0:.0f}s]")


if __name__ == "__main__":
    main()
