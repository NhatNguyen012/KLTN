#!/usr/bin/env python3
"""STEP 12B - dung nhan da nhan (multi-label) theo tactic ATT&CK cho cua so (host, 15 phut) cua OpTC.

Chi doc du lieu local, khong can o E:. Dau vao:
  - stage_steps_v1.csv: bang buoc tan cong do nguoi dung tay tu nhat ky red team (OpTCRedTeamGroundTruth.pdf).
  - ground_truth_corrected_sc*_evts_*.json.gz: event eCAR cua process doc hai (A New Hope).
  - labelling/network/scenario-*/conn-*.log: flow Zeek bi gan nhan doc hai (A New Hope).
Quy tac: cua so 15 phut theo UTC epoch (floor(ts/900)*900), giong pipeline network. Mot buoc nhat ky tai thoi diem t
gan tactic cho moi cua so giao voi [t - pad_before, t + pad_after]. Cua so co flow doc hai duoc them tactic C2 (tu mang).
"""
import argparse
import collections
import csv
import datetime as dt
import glob
import gzip
import json
import os
import re

TACTICS = ["IA", "EX", "PE", "PR", "DE", "CA", "DI", "LM", "CO", "C2", "EXF"]
NAMES = {
    "IA": "Initial Access", "EX": "Execution", "PE": "Persistence", "PR": "Privilege Escalation",
    "DE": "Defense Evasion", "CA": "Credential Access", "DI": "Discovery", "LM": "Lateral Movement",
    "CO": "Collection", "C2": "Command and Control", "EXF": "Exfiltration",
}
WIN = 900
EDT = dt.timezone(dt.timedelta(hours=-4))
SC_BY_DIR = {"scenario-1": "SC1", "scenario-2": "SC2", "scenario-3": "SC3"}


def edt_to_epoch(s):
    return dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=EDT).timestamp()


def iso_to_epoch(s):
    return dt.datetime.fromisoformat(s).timestamp()


def win_of(ts):
    return int(ts // WIN) * WIN


def fmt_utc(w):
    return dt.datetime.fromtimestamp(w, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")


def fmt_edt(w):
    return dt.datetime.fromtimestamp(w, EDT).strftime("%Y-%m-%d %H:%M")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nh", default="D:/UIT/KLTN/KLTN-main/a_new_hope_for_darpa_optc/labelling")
    ap.add_argument("--steps", default="02_artifacts/12b_multilabel_stage_v1/stage_steps_v1.csv")
    ap.add_argument("--out", default="02_artifacts/12b_multilabel_stage_v1")
    a = ap.parse_args()

    rows = {}  # (sc, host, win) -> dict

    def get(sc, host, w):
        k = (sc, host, w)
        if k not in rows:
            rows[k] = {"tac": set(), "host_ev": 0, "net_pos": 0, "detail": set()}
        return rows[k]

    # 1) buoc nhat ky red team
    with open(a.steps, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            t = edt_to_epoch(r["time_edt"])
            lo, hi = t - float(r["pad_before_s"]), t + float(r["pad_after_s"])
            for w in range(win_of(lo), win_of(hi) + WIN, WIN):
                d = get(r["scenario"], r["host"], w)
                d["tac"].update(r["tactics"].split("|"))
                d["detail"].add(r["detail"])

    # 2) event eCAR doc hai (ban corrected)
    for p in sorted(glob.glob(a.nh + "/host/ground_truths/ground_truth_corrected_sc*_evts_sysclient*.json.gz")):
        m = re.search(r"corrected_(sc\d)_evts_(sysclient\d+)", p)
        sc, host = m.group(1).upper(), m.group(2)
        for line in gzip.open(p, "rt", encoding="utf-8"):
            line = line.strip()
            if line:
                get(sc, host, win_of(iso_to_epoch(json.loads(line)["timestamp"])))["host_ev"] += 1

    # 3) flow Zeek doc hai
    for p in sorted(glob.glob(a.nh + "/network/scenario-*/conn-*.log")):
        sc = SC_BY_DIR[os.path.basename(os.path.dirname(p))]
        b = os.path.basename(p)[5:-4]
        host = "dc1" if b == "dc1" else "sysclient" + b.split("-")[1].zfill(4)
        for line in open(p, encoding="utf-8", errors="replace"):
            if line.startswith("#"):
                continue
            c = line.split("\t", 1)
            if len(c) < 2:
                continue
            d = get(sc, host, win_of(float(c[0])))
            d["net_pos"] += 1
            d["tac"].add("C2")

    os.makedirs(a.out, exist_ok=True)
    hdr = ["scenario", "host", "window_start_utc", "window_start_edt"] + TACTICS + [
        "n_tactics", "n_host_mal_events", "n_net_pos_flows", "step_detail", "host_mal_no_stage", "stage_without_host_evidence"]
    out_rows = []
    for (sc, host, w), d in sorted(rows.items()):
        tac_wo_net = d["tac"] if d["detail"] else set()
        stage_tac = d["tac"] - ({"C2"} if (d["net_pos"] and not d["detail"]) else set())
        detail = "none" if not d["detail"] else ("detailed" if "detailed" in d["detail"] else "coarse")
        out_rows.append({
            "scenario": sc, "host": host, "window_start_utc": fmt_utc(w), "window_start_edt": fmt_edt(w),
            **{t: int(t in d["tac"]) for t in TACTICS},
            "n_tactics": len(d["tac"]), "n_host_mal_events": d["host_ev"], "n_net_pos_flows": d["net_pos"],
            "step_detail": detail,
            "host_mal_no_stage": int(d["host_ev"] > 0 and not d["detail"]),
            "stage_without_host_evidence": int(bool(d["detail"]) and d["host_ev"] == 0 and d["net_pos"] == 0),
        })
    with open(a.out + "/window_labels_v1.csv", "w", newline="\n", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=hdr)
        wr.writeheader()
        wr.writerows(out_rows)

    # 4) thong ke
    S = {"n_windows": len(out_rows)}
    per_sc = collections.defaultdict(lambda: collections.Counter())
    card = collections.Counter()
    pairs = collections.Counter()
    for r in out_rows:
        sc = r["scenario"]
        per_sc[sc]["windows"] += 1
        for t in TACTICS:
            if r[t]:
                per_sc[sc][t] += 1
                per_sc["ALL"][t] += 1
        per_sc["ALL"]["windows"] += 1
        card[r["n_tactics"]] += 1
        ts = [t for t in TACTICS if r[t]]
        for i in range(len(ts)):
            for j in range(i + 1, len(ts)):
                pairs[(ts[i], ts[j])] += 1
        if r["n_host_mal_events"] > 0:
            per_sc[sc]["host_mal_windows"] += 1
            if r["n_net_pos_flows"] == 0:
                per_sc[sc]["host_mal_net_none"] += 1
            if r["host_mal_no_stage"]:
                per_sc[sc]["host_mal_no_stage"] += 1
        if r["n_net_pos_flows"] > 0:
            per_sc[sc]["net_pos_windows"] += 1
            if r["n_host_mal_events"] == 0:
                per_sc[sc]["net_pos_no_host_ev"] += 1
        if r["stage_without_host_evidence"]:
            per_sc[sc]["stage_no_evidence"] += 1
    S["per_scenario"] = {k: dict(v) for k, v in per_sc.items()}
    S["cardinality"] = dict(sorted(card.items()))
    S["top_pairs"] = [[f"{a_}+{b_}", n] for (a_, b_), n in pairs.most_common(15)]
    with open(a.out + "/summary_12b.json", "w", newline="\n", encoding="utf-8") as f:
        json.dump(S, f, ensure_ascii=False, indent=2)
    with open(a.out + "/tactic_counts_v1.csv", "w", newline="\n", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["tactic", "name"] + ["SC1", "SC2", "SC3", "ALL"])
        for t in TACTICS:
            wr.writerow([t, NAMES[t]] + [per_sc[s].get(t, 0) for s in ["SC1", "SC2", "SC3", "ALL"]])
    print(json.dumps(S, ensure_ascii=False, indent=1))
    print("\nTACTIC COUNTS (SC1, SC2, SC3, ALL)")
    for t in TACTICS:
        print(f"{t:4s} {NAMES[t]:22s}", [per_sc[s].get(t, 0) for s in ["SC1", "SC2", "SC3", "ALL"]])
    print("\nSC3 windows")
    for r in out_rows:
        if r["scenario"] == "SC3":
            print(r["host"], r["window_start_edt"], "tac=", "|".join(t for t in TACTICS if r[t]),
                  "host_ev=", r["n_host_mal_events"], "net_pos=", r["n_net_pos_flows"], r["step_detail"])


if __name__ == "__main__":
    main()
