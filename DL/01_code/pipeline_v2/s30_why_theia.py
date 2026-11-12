#!/usr/bin/env python3
"""S30 (STEP 40) - THEIA 6r: flow thật (đầu xa thật) dương vs benign, theo chương trình (từ EVENT_EXECUTE), cha, đích. Đọc kết quả của s27."""
import os
import sys

import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
pd.set_option("display.width", 250)
pd.set_option("display.max_colwidth", 80)
D = r"D:\UIT\KLTNv2\02_artifacts\40_why_malicious_v1\theia"
sub = pd.read_csv(os.path.join(D, "subjects_all.csv"), low_memory=False, keep_default_na=False)
ex = pd.read_csv(os.path.join(D, "exec_by_subject.csv"), low_memory=False, keep_default_na=False)
net = pd.read_csv(os.path.join(D, "net_agg.csv"), low_memory=False, keep_default_na=False)
fo = open(os.path.join(D, "summary.txt"), "w", encoding="utf-8")


def pr(*a):
    print(*a)
    print(*a, file=fo)


def prog(c):
    c = str(c).strip()
    if not c:
        return ""
    t = c.split(" ")[0]
    return t.split("/")[-1]


ex["ts_ns"] = pd.to_numeric(ex.ts_ns, errors="coerce")
ex = ex.sort_values("ts_ns")
last_exec = ex.groupby("subject").cmdline.last()
first_exec = ex.groupby("subject").cmdline.first()
n_exec = ex.groupby("subject").size()
sub = sub.set_index("uuid")
sub["exec_last"] = last_exec.reindex(sub.index).fillna("")
sub["n_exec"] = n_exec.reindex(sub.index).fillna(0).astype(int)
sub["prog"] = sub.exec_last.map(prog)
sub["prog_fork"] = sub.subj_path.map(lambda x: str(x).split("/")[-1])
sub["parent_prog"] = sub.parent.map(lambda u: sub.prog.get(u, "") or sub.prog_fork.get(u, ""))
net["n_events"] = net.n_events.astype(int)
net["pos"] = (net.n_labeled_events > 0) | net.subject.isin(sub.index[sub.label_subject != ""])
net["prog"] = net.subject.map(sub.prog)
net["prog_fork"] = net.subject.map(sub.prog_fork)
net["parent_prog"] = net.subject.map(sub.parent_prog)
net["prog_any"] = net.prog.where(net.prog != "", net.prog_fork)
net["ip"] = net.remote.str.rsplit(":", n=1).str[0]
net["port"] = net.remote.str.rsplit(":", n=1).str[1]
pr("subjects", len(sub), "| subject có EXECUTE", int((sub.n_exec > 0).sum()), "| subject nhãn REAPr", int((sub.label_subject != "").sum()))
pr("(subject, netflow thật) khóa", len(net), "| dương (có cạnh nhãn hoặc subject nhãn)", int(net.pos.sum()), "| subject khác nhau", net.subject.nunique(), "| dương: subject", net[net.pos].subject.nunique(), "| netflow", net[net.pos].netflow.nunique())
pr("\n== cạnh có nhãn: n_labeled_events>0 (khóa)", int((net.n_labeled_events > 0).sum()), "| tổng sự kiện có nhãn", int(net.n_labeled_events.sum()))
pr("\n== top chương trình (EXECUTE) của subject dương, theo số khóa (subject,netflow) và sự kiện")
g = net[net.pos].groupby("prog_any").agg(keys=("n_events", "size"), events=("n_events", "sum"), subjects=("subject", "nunique")).sort_values("keys", ascending=False)
pr(g.head(15))
pr("\n== top chương trình của subject benign (có flow thật), theo khóa")
gb = net[~net.pos].groupby("prog_any").agg(keys=("n_events", "size"), events=("n_events", "sum"), subjects=("subject", "nunique")).sort_values("keys", ascending=False)
pr(gb.head(20))
pr("\n== chương trình có cả dương và benign (số khóa dương / benign)")
both = g[["keys"]].join(gb[["keys"]], lsuffix="_pos", rsuffix="_benign", how="inner").sort_values("keys_pos", ascending=False)
pr(both.head(15))
pr("\n== cha (chương trình) của subject dương vs benign")
pr(net[net.pos].groupby("parent_prog").size().sort_values(ascending=False).head(10))
pr(net[~net.pos].groupby("parent_prog").size().sort_values(ascending=False).head(10))
pr("\n== đích: dương top; benign có cùng đích không")
gd = net[net.pos].groupby("remote").agg(keys=("n_events", "size"), events=("n_events", "sum")).sort_values("events", ascending=False)
pr(gd.head(12))
posdest = set(net[net.pos].remote)
pr("khóa benign có cùng đích với dương:", int(net[(~net.pos) & net.remote.isin(posdest)].shape[0]), "/", int((~net.pos).sum()))
pr("benign đến cổng 80:", int(((~net.pos) & (net.port == "80")).sum()), "| dương đến cổng 80:", int((net.pos & (net.port == "80")).sum()))
pr("\n== loại sự kiện (dương / benign)")
pr(net.groupby(["pos", "types"]).size().sort_values(ascending=False).head(10))
pr("\n== cmdline mẫu của subject dương (EXECUTE cuối)")
pr(net[net.pos].drop_duplicates("subject")[["subject", "prog_any", "parent_prog"]].head(15).to_string())
pr("\n== dương: subject, số lần EXECUTE, có exec cmdline chứa firefox/bash/sh")
pp = sub.loc[net[net.pos].subject.unique()]
pr(pp.exec_last.map(lambda c: c[:60]).value_counts().head(12))
pr("\n== nhãn subject REAPr (125 attack) có flow thật không:", len(set(sub.index[sub.label_subject != ""]) & set(net.subject)), "/", int((sub.label_subject != "").sum()))
fo.close()
