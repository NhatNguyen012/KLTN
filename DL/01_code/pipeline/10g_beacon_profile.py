"""STEP 10G — Dac trung beacon cua positive flow (chi doc joined parquet + mapping host/scenario cua 10a).

Tra loi: positive window thuoc "beacon" (C2 polling deu dan, cung template tren nhieu host) chiem bao nhieu %?
Beacon = host co >=20 positive event toi cung 1 endpoint (resp_h:resp_p), nhip deu (CV khoang cach giua 2 event <= 0.35).
Window "beacon" = window (host, floor(ts/900)*900) co endpoint chu dao la endpoint beacon (>= 50% positive event).

    python 10g_beacon_profile.py --project-root D:\\UIT\\KLTNv2
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()
    root = Path(args.project_root)
    out = Path(args.out_dir) if args.out_dir else root / "02_artifacts" / "10g_unseen_beacon_v1" / "beacon_profile"
    if out.exists():
        raise FileExistsError(f"{out} da ton tai; khong ghi de")
    out.mkdir(parents=True)

    scen: dict[str, str] = {}
    with (root / "02_artifacts" / "10a_random_split_v1" / "seed_1" / "host_split_frozen.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["gt_primary_scenario"]:
                scen[r["hostname"]] = r["gt_primary_scenario"]

    glob = (root / "02_artifacts" / "02_network_joined_v1" / "joined" / "split=*" / "date=*" / "*.parquet").as_posix()
    con = duckdb.connect()
    con.execute("SET threads=8")
    df = con.execute(
        f"SELECT hostname, ts, resp_h, resp_p, app_family, orig_bytes, resp_bytes, duration "
        f"FROM read_parquet('{glob}', hive_partitioning=true) WHERE label=1 ORDER BY hostname, ts").fetchdf()
    df["scenario"] = df["hostname"].map(scen)
    df["endpoint"] = df["resp_h"] + ":" + df["resp_p"].astype(int).astype(str)
    df["window"] = (df["ts"] // 900).astype(int) * 900

    # ---- 1) host x endpoint: nhip + kich thuoc ----
    rows = []
    for (h, ep), d in df.groupby(["hostname", "endpoint"]):
        if len(d) < 20:
            continue
        t = np.sort(d["ts"].values)
        dt = np.diff(t)
        dt = dt[dt < 600]
        cv = float(dt.std() / dt.mean()) if len(dt) > 2 else None
        rows.append({
            "hostname": h, "scenario": scen.get(h, ""), "endpoint": ep, "positive_events": len(d),
            "windows": int(d["window"].nunique()),
            "events_per_window_median": float(d.groupby("window").size().median()),
            "interval_median_s": round(float(np.median(dt)), 2) if len(dt) else None,
            "interval_cv": round(cv, 3) if cv is not None else None,
            "orig_bytes_median": float(d["orig_bytes"].median()), "resp_bytes_median": float(d["resp_bytes"].median()),
            "top_app": d["app_family"].value_counts().index[0], "span_hours": round(float((t[-1] - t[0]) / 3600), 1),
            "is_periodic": bool(cv is not None and cv <= 0.35),
        })
    hp = pd.DataFrame(rows).sort_values(["scenario", "endpoint", "positive_events"], ascending=[True, True, False])
    hp.to_csv(out / "host_endpoint_profile.csv", index=False)
    beacon_eps = sorted(set(hp.loc[hp["is_periodic"] & (hp["positive_events"] >= 100), "endpoint"]))

    # ---- 2) positive window x endpoint chu dao ----
    w = df.groupby(["hostname", "window"]).agg(
        events=("ts", "size"), scenario=("scenario", "first"),
        top=("endpoint", lambda s: s.value_counts().index[0]),
        share=("endpoint", lambda s: s.value_counts().iloc[0] / len(s))).reset_index()
    w["is_beacon_window"] = w["top"].isin(beacon_eps) & (w["share"] >= 0.5)
    w.to_csv(out / "positive_windows.csv", index=False)

    by_ep = w.groupby(["scenario", "top"]).agg(
        windows=("events", "size"), events_median=("events", "median"), beacon=("is_beacon_window", "first")).reset_index()
    by_ep.to_csv(out / "windows_by_scenario_endpoint.csv", index=False)

    summary = {
        "beacon_endpoints": beacon_eps,
        "positive_windows_total": int(len(w)),
        "beacon_windows": int(w["is_beacon_window"].sum()),
        "non_beacon_windows": int((~w["is_beacon_window"]).sum()),
        "non_beacon_by_scenario": w[~w["is_beacon_window"]].groupby("scenario").size().to_dict(),
        "beacon_windows_by_scenario": w[w["is_beacon_window"]].groupby("scenario").size().to_dict(),
        "beacon_templates": {
            ep: {
                "hosts": int(hp.loc[hp["endpoint"] == ep, "hostname"].nunique()),
                "interval_median_s": float(hp.loc[hp["endpoint"] == ep, "interval_median_s"].median()),
                "orig_bytes_median": float(hp.loc[hp["endpoint"] == ep, "orig_bytes_median"].median()),
                "resp_bytes_median": float(hp.loc[hp["endpoint"] == ep, "resp_bytes_median"].median()),
                "events_per_window_median": float(hp.loc[hp["endpoint"] == ep, "events_per_window_median"].median()),
            } for ep in beacon_eps},
        "note": "Window = (hostname, 15 phut); mot window co the tach nhieu chunk >512 event nen so sample trong manifest co the lon hon.",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("[OUT]", out)


if __name__ == "__main__":
    main()
