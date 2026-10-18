#!/usr/bin/env python3
"""S7b - CHẨN ĐOÁN kết quả TEST (chỉ để hiểu, không dùng chọn gì): phân bố điểm, mẫu bỏ sót, luật đơn giản làm mốc, attention của Mixed-Type."""
import json
import sys
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
V2 = ROOT / "02_artifacts/22_v2_pipeline"
OUT = V2 / "S7_results"
S4 = V2 / "S4_shards"
spec = json.load(open(V2 / "S3_preprocess/data/preprocess_spec.json", encoding="utf-8"))
cats = spec["model_input_layout"]["x_cat_columns"]
vid = {f: {e["value"]: e["id"] for e in spec["categorical"]["fields"][f]["vocab"]} for f in cats}
sm = pd.read_csv(S4 / "data/samples.csv")
w = pd.read_csv(V2 / "S2_windows_split/data/windows.csv")[["hostname", "window_start_epoch", "scenario"]]
sm = sm.merge(w, on=["hostname", "window_start_epoch"], how="left")
test = sm[sm.split == "test"].copy()

# ---- cờ host theo sample từ shards (không cần raw)
flags = {"powershell": (0, vid["app_family"]["powershell.exe"]), "temp_appdata": (cats.index("image_dir_class"), vid["image_dir_class"]["TEMP_OR_APPDATA"]),
         "administrator": (cats.index("principal_class"), vid["principal_class"]["ADMINISTRATOR"])}
rows = []
for fn, g in test.groupby("shard_file"):
    z = np.load(S4 / fn)
    off, xc = z["sample_offsets"], z["x_cat"]
    for r in g.itertuples():
        a, b = int(off[r.shard_sample_index]), int(off[r.shard_sample_index + 1])
        seg = xc[a:b]
        rows.append({"sample_id": r.sample_id, **{k: int((seg[:, c] == v).any()) for k, (c, v) in flags.items()}})
fl = pd.DataFrame(rows)
test = test.merge(fl, on="sample_id")


def prf(y, pred):
    tp = int(((y == 1) & (pred == 1)).sum()); fp = int(((y == 0) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


y = test.label.to_numpy()
rules = {"co_powershell": prf(y, test.powershell.to_numpy()), "co_powershell_hoac_temp_appdata": prf(y, (test.powershell | test.temp_appdata).to_numpy()),
         "co_powershell_hoac_temp_hoac_administrator": prf(y, (test.powershell | test.temp_appdata | test.administrator).to_numpy()), "chi_administrator": prf(y, test.administrator.to_numpy()),
         "chi_temp_appdata": prf(y, test.temp_appdata.to_numpy())}
diag = {"rules_on_test": rules}
pos = test[test.label == 1]
diag["test_positive_flags"] = {"n": int(len(pos)), "powershell": int(pos.powershell.sum()), "temp_appdata": int(pos.temp_appdata.sum()), "administrator": int(pos.administrator.sum()),
                               "none_of_three": int(((pos.powershell + pos.temp_appdata + pos.administrator) == 0).sum())}
diag["test_negative_flags"] = {"n": int((test.label == 0).sum()), "powershell": int(test[test.label == 0].powershell.sum()), "temp_appdata": int(test[test.label == 0].temp_appdata.sum()),
                              "administrator": int(test[test.label == 0].administrator.sum())}
# ---- điểm
con = duckdb.connect()
F = str(V2 / "S1_join/data/flows_joined.parquet").replace("\\", "/")
for name in ("bilstm_v2", "mixed_v2"):
    d = ROOT / "05_models/v2_final" / name
    thr = json.load(open(d / "threshold.json", encoding="utf-8"))["threshold"]
    t = pd.read_csv(d / "test_predictions.csv").merge(test[["sample_id", "hostname", "window_start_epoch", "window_start_utc", "chunk_index", "scenario", "event_count", "powershell", "temp_appdata", "administrator"]], on="sample_id")
    p = t.probability.to_numpy()
    pos_p, neg_p = t[t.label == 1].probability, t[t.label == 0].probability
    diag[name] = {"threshold": thr, "n_positive_prob_eq_1": int((pos_p >= 1.0).sum()), "n_positive": int(len(pos_p)), "min_positive_prob": float(pos_p.min()), "max_negative_prob": float(neg_p.max()),
                  "n_negative_prob_ge_0.5": int((neg_p >= 0.5).sum()), "n_negative_prob_ge_0.01": int((neg_p >= 0.01).sum()),
                  "median_positive_prob": float(pos_p.median()), "positives_prob_lt_thr": []}
    miss = t[(t.label == 1) & (t.probability < thr)]
    for r in miss.itertuples():
        fl_ = con.execute(f"""SELECT app_family, image_path, principal, resp_h, resp_p, service, conn_state, count(*) n FROM read_parquet('{F}')
              WHERE hostname = '{r.hostname}' AND window_start_epoch = {int(r.window_start_epoch)} GROUP BY ALL ORDER BY n DESC LIMIT 5""").df().to_dict("records")
        diag[name]["positives_prob_lt_thr"].append({"hostname": r.hostname, "window_utc": r.window_start_utc, "scenario": r.scenario, "probability": float(r.probability), "event_count": int(r.event_count),
                                                    "has_powershell": int(r.powershell), "has_temp_appdata": int(r.temp_appdata), "has_administrator": int(r.administrator), "top_flow_groups": fl_})
    # recall theo ngưỡng cố định chỉ để xem độ bão hòa (KHÔNG dùng để chọn)
    diag[name]["recall_if_threshold"] = {str(x): round(float((pos_p >= x).mean()), 4) for x in (0.99, 0.9, 0.5, 0.1, 0.01)}
    diag[name]["fp_if_threshold"] = {str(x): int((neg_p >= x).sum()) for x in (0.99, 0.9, 0.5, 0.1, 0.01)}
try:
    au = json.load(open(ROOT / "05_models/v2_final/mixed_v2/attention_audit.json", encoding="utf-8"))
    diag["mixed_attention_audit_feature_attention_received"] = au.get("feature_attention_received")
except Exception as e:  # noqa: BLE001
    diag["mixed_attention_audit_error"] = str(e)
json.dump(diag, open(OUT / "diagnostics.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
print(json.dumps(diag, ensure_ascii=False, indent=1, default=str)[:9000])
