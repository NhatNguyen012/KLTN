#!/usr/bin/env python3
"""S32 (STEP 42) - đọc firefox_procs.json (s31): firefox.exe có nhãn vs không nhãn khác nhau ở sự kiện nào."""
import json
import os
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
pd.set_option("display.width", 250)
pd.set_option("display.max_colwidth", 90)
D = r"D:\UIT\KLTNv2\02_artifacts\42_atlas_firefox_label_v1"
R = json.load(open(os.path.join(D, "firefox_procs.json"), encoding="utf-8"))
fo = open(os.path.join(D, "summary.txt"), "w", encoding="utf-8")


def pr(*a):
    print(*a)
    print(*a, file=fo)


rows = []
for g, r in R.items():
    t = r["types"]
    rows.append({"guid": g, "kind": r["kind"], "host": r["host"], "sc": r["scenario"], "ff": str(r["path"]).lower().endswith("firefox.exe"), "label": r["label"], "parent_label": r["parent_label"],
                 "parent": str(r["parent_path"]).split("\\")[-1].lower(), "n_net": t.get("netconn", 0), "n_file": t.get("filemod", 0), "n_mod": t.get("moduleload", 0), "n_reg": t.get("regmod", 0),
                 "n_cross": t.get("crossproc", 0), "n_ps": t.get("procstart", 0), "n_script": t.get("scriptload", 0), "n_seed_conn": sum(r["seed_conn"].values()), "seed_file": r["seed_file"],
                 "n_dropped": len(r["exe_dll_swf_written"]), "ts_min": r["ts_min"], "ts_max": r["ts_max"]})
d = pd.DataFrame(rows)
ff = d[d.ff]
pr("tiến trình firefox.exe:", len(ff), "| nhãn dương", int(ff.label.sum()), "| tệp attack không nhãn", int(((ff.kind == "attack") & (ff.label == 0)).sum()), "| tệp benign", int((ff.kind == "benign").sum()))
pr("\n== số tiến trình có sự kiện loại X (>0), theo nhóm")
ff = ff.assign(grp=ff.apply(lambda r: "benign-tệp" if r.kind == "benign" else ("attack-DƯƠNG" if r.label else "attack-không-nhãn"), axis=1))
for c in ["n_net", "n_file", "n_mod", "n_reg", "n_cross", "n_ps", "n_script", "n_seed_conn", "seed_file", "n_dropped"]:
    pr(c.ljust(12), ff.groupby("grp")[c].apply(lambda s: f"{int((s > 0).sum())}/{len(s)}").to_dict(), "| trung vị", ff.groupby("grp")[c].median().to_dict())
pr("\n== firefox dương: theo host/scenario, số tiến trình dương mỗi (host-scenario)")
pr(ff[ff.grp == "attack-DƯƠNG"].groupby(["host", "sc"]).size().to_string())
pr("\n== firefox attack không nhãn: theo host/scenario")
pr(ff[ff.grp == "attack-không-nhãn"].groupby(["host", "sc"]).size().to_string())
pr("\n== cha có nhãn? (parent_label)")
pr(ff.groupby(["grp", "parent_label"]).size())
pr("\n== firefox dương: kết nối tới nút gốc/tác động (seed IP) và crossproc")
pr(ff[ff.grp == "attack-DƯƠNG"][["guid", "host", "sc", "n_net", "n_seed_conn", "n_cross", "n_ps", "n_dropped", "seed_file"]].assign(guid=lambda x: x.guid.str[-8:]).to_string())
pr("\n== firefox attack không nhãn: ví dụ")
pr(ff[ff.grp == "attack-không-nhãn"][["guid", "host", "sc", "n_net", "n_seed_conn", "n_cross", "n_ps", "n_file", "n_mod"]].assign(guid=lambda x: x.guid.str[-8:]).head(12).to_string())
pr("\n== chi tiết firefox dương có crossproc / seed / dropped")
for g, r in R.items():
    if r["label"] and str(r["path"]).lower().endswith("firefox.exe") and (r["crossproc"] or r["seed_conn"] or r["exe_dll_swf_written"] or r["seed_file"]):
        pr(g[-8:], r["host"], r["scenario"], "| seed_conn", r["seed_conn"], "| crossproc", r["crossproc"], "| dropped", list(r["exe_dll_swf_written"])[:3], "| children", r["children"])
pr("\n== các tiến trình có nhãn không phải firefox: chương trình (đếm)")
pr(pd.Series([str(r["path"]).split("\\")[-1].lower() for r in R.values() if r["label"] and not str(r["path"]).lower().endswith("firefox.exe")]).value_counts().head(15))
pr("\n== firefox dương: thời điểm đầu/cuối so với tiến trình không nhãn cùng host-scenario (khoảng thời gian)")
for (h, s), g in ff[ff.kind == "attack"].groupby(["host", "sc"]):
    pos, neg = g[g.label == 1], g[g.label == 0]
    if len(pos):
        pr(h, s, "dương", len(pos), pos.ts_min.min()[:19], "→", pos.ts_max.max()[:19], "| không nhãn", len(neg), (neg.ts_min.min() or "")[:19] if len(neg) else "", "→", (neg.ts_max.max() or "")[:19] if len(neg) else "")
fo.close()
