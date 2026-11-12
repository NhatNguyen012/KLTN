#!/usr/bin/env python3
"""S28 (STEP 40) - ATLASv2: flow (netconn) dương khác benign ở field nào. Đọc atlas_netconn_rows.csv và atlas_procstart_rows.csv (s26)."""
import ipaddress
import os
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
pd.set_option("display.width", 250)
pd.set_option("display.max_colwidth", 70)
D = r"D:\UIT\KLTNv2\02_artifacts\40_why_malicious_v1\atlas"
n = pd.read_csv(os.path.join(D, "atlas_netconn_rows.csv"), low_memory=False)
p = pd.read_csv(os.path.join(D, "atlas_procstart_rows.csv"), low_memory=False)


def base(x):
    return str(x).lower().replace("\\", "/").split("/")[-1] if isinstance(x, str) else ""


def priv(x):
    try:
        return "private" if ipaddress.ip_address(x).is_private else "public"
    except Exception:
        return "none"


n["app"] = n.process_path.map(base)
n["parent_app"] = n.parent_path.map(base)
n["dest_class"] = n.remote_ip.map(priv)
n["has_cmd"] = n.process_cmdline.notna()
f = n[(n.action != "ACTION_CONNECTION_LISTEN") & n.remote_ip.notna() & (n.remote_ip != "")]
out = os.path.join(D, "summary.txt")
fo = open(out, "w", encoding="utf-8")


def pr(*a):
    print(*a)
    print(*a, file=fo)


pr("netconn tổng", len(n), "| sau lọc LISTEN và remote rỗng", len(f), "| dương", int(f.label_proc.sum()), "| benign", int((f.label_proc == 0).sum()))
pr("\n== kind (tệp) x nhãn")
pr(f.groupby(["kind", "label_proc"]).size().unstack(fill_value=0))
pr("\n== dương theo app (top)")
g = f.groupby("app").label_proc.agg(["size", "sum"]).rename(columns={"size": "n_all", "sum": "n_pos"})
pr(g[g.n_pos > 0].sort_values("n_pos", ascending=False).head(15))
pr("\n== firefox.exe: dương và benign theo loại đích")
ff = f[f.app == "firefox.exe"]
pr(ff.groupby(["label_proc", "dest_class"]).size().unstack(fill_value=0))
pr("\n== firefox.exe: dương, top đích")
pr(ff[ff.label_proc == 1].groupby(["remote_ip", "remote_port"]).size().sort_values(ascending=False).head(10))
pr("\n== firefox.exe: dương và benign theo cha (parent_app), và cmdline có khác nhau không")
pr(ff.groupby(["label_proc", "parent_app"]).size().unstack(fill_value=0).T.sort_values(1, ascending=False).head(8))
pr(ff.groupby("label_proc").process_cmdline.agg(lambda s: s.value_counts().head(3).to_dict()))
pr("\n== firefox.exe: số hash binary khác nhau (dương / benign), có chung không")
hp, hb = set(ff[ff.label_proc == 1].process_md5.dropna()), set(ff[ff.label_proc == 0].process_md5.dropna())
pr("md5 dương", len(hp), "md5 benign", len(hb), "chung", len(hp & hb))
pr("\n== dương: top đích (ip:port), loại đích")
pr(f[f.label_proc == 1].groupby(["dest_class"]).size())
pr(f[f.label_proc == 1].groupby(["remote_ip", "remote_port"]).size().sort_values(ascending=False).head(12))
pr("\n== benign: tỷ lệ đích private")
pr(f[f.label_proc == 0].groupby("dest_class").size())
pr("\n== đích private theo nhãn và app (top)")
pp = f[f.dest_class == "private"]
pr(pp.groupby(["label_proc", "app"]).size().sort_values(ascending=False).head(12))
pr("\n== dương không phải firefox: app, cha, cmdline (mẫu)")
nf = f[(f.label_proc == 1) & (f.app != "firefox.exe")]
pr(nf.groupby(["app", "parent_app"]).size().sort_values(ascending=False).head(12))
pr(nf[["app", "process_cmdline", "parent_cmdline", "remote_ip", "remote_port", "process_username"]].drop_duplicates().head(12).to_string())
pr("\n== tên người dùng (dương / benign) top")
pr(f.groupby(["label_proc", "process_username"]).size().sort_values(ascending=False).head(10))
pr("\n== đường dẫn thư mục của app dương (không phải program files / windows)")
f2 = f.assign(dir=f.process_path.str.lower().str.replace(r"[^\\]+$", "", regex=True))
g2 = f2.groupby("dir").label_proc.agg(["size", "sum"]).rename(columns={"size": "n_all", "sum": "n_pos"})
pr(g2[g2.n_pos > 0].sort_values("n_pos", ascending=False).head(12))
pr("\n== procstart: cha dương sinh con (child) gì")
pp_ = p[p.label_parent == 1]
pr("procstart tổng", len(p), "| cha dương", len(pp_), "| con dương", int(p.label_child.sum()))
pr(pp_.assign(parent=pp_.process_path.map(base), child=pp_.childproc_name.map(base)).groupby(["parent", "child"]).size().sort_values(ascending=False).head(15))
pr("\n== procstart: con nhãn dương nhưng cha benign (cha, con)")
pc = p[(p.label_child == 1) & (p.label_parent == 0)]
pr(len(pc))
pr(pc.assign(parent=pc.process_path.map(base), child=pc.childproc_name.map(base)).groupby(["parent", "child"]).size().sort_values(ascending=False).head(10))
pr("\n== cặp (cha -> con) trong benign: có xuất hiện cặp giống dương không")
pb = p[(p.label_parent == 0) & (p.label_child == 0)]
pair_pos = set(zip(pp_.process_path.map(base), pp_.childproc_name.map(base)))
pair_ben = set(zip(pb.process_path.map(base), pb.childproc_name.map(base)))
pr("cặp dương", len(pair_pos), "trong đó cũng có ở benign", len(pair_pos & pair_ben))
fo.close()
