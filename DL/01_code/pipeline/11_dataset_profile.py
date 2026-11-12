"""STEP 11 — Ho so tong quan dataset DARPA OpTC (raw + host + network + scenario) tu artifact da co.

Chi doc (khong dung o E:). Nguon:
  - inventory raw (STEP 00): compressed_inventory.csv
  - manifest host da dong bang (STEP 02): split_manifest_frozen.csv, ground_truth_profile.json
  - network da join (STEP 04B): joined parquet
  - mapping scenario cua 10a, positive window cua 10g
Moc gio: eCAR dung gio dia phuong EDT (UTC-4); Bro/ts epoch la UTC. Bao cao scenario theo EDT.

    python 11_dataset_profile.py --project-root D:\\UIT\\KLTNv2 --legacy-root D:\\UIT\\KLTN
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd

EDT = 4 * 3600


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--legacy-root", required=True, help="D:\\UIT\\KLTN (artifact STEP 00/02 ngoai repo)")
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()
    root, legacy = Path(args.project_root), Path(args.legacy_root)
    out = Path(args.out_dir) if args.out_dir else root / "02_artifacts" / "11_dataset_overview_v1"
    if out.exists():
        raise FileExistsError(f"{out} da ton tai; khong ghi de")
    out.mkdir(parents=True)

    # ---------------------------------------------------------------- 1) raw inventory
    inv = pd.read_csv(legacy / "KLTN_bootstrap_step01" / "artifacts" / "step00_inventory" / "compressed_inventory.csv",
                      encoding="utf-8-sig")
    inv["gb"] = inv["compressed_size_bytes"] / 1024 ** 3
    src = inv.groupby("source").agg(files=("gb", "size"), compressed_gb=("gb", "sum"),
                                    avg_file_mb=("compressed_size_mb", "mean")).round(3)
    src.to_csv(out / "raw_inventory_by_source.csv")

    b = inv[inv["source"] == "bro"].copy()
    b["date"] = b["relative_path"].str.split("\\").str[1]
    b["log_type"] = b["filename"].str.split(".").str[0]
    bro_type = b.groupby("log_type").agg(files=("gb", "size"), compressed_gb=("gb", "sum")).sort_values("compressed_gb", ascending=False).round(4)
    bro_type.to_csv(out / "bro_by_log_type.csv")
    bro_day = b.pivot_table(index="date", columns="log_type", values="gb", aggfunc="size", fill_value=0)
    bro_day["compressed_gb_total"] = b.groupby("date")["gb"].sum().round(3)
    bro_day.to_csv(out / "bro_files_by_date.csv")

    e = inv[inv["source"] == "ecar-bro"].copy()
    e["group"] = e["relative_path"].str.split("\\").str[1] + "/" + e["relative_path"].str.split("\\").str[2]
    e.groupby("group").agg(files=("gb", "size"), compressed_gb=("gb", "sum"), avg_file_mb=("compressed_size_mb", "mean")).round(3).to_csv(out / "ecarbro_by_group.csv")

    # ---------------------------------------------------------------- 2) host raw (manifest)
    man = pd.read_csv(legacy / "artifacts" / "step02_label_split_v1_1" / "split_manifest_frozen.csv")
    man["day"] = man["date"].str[8:]
    hostdays = man.groupby("hostname")["day"].apply(lambda s: tuple(sorted(set(s))))
    names = {("16", "17", "18", "19", "20", "21", "22", "23", "24", "25"): "A_16-25 (xuyen suot)",
             ("18", "19", "20", "21", "22", "23", "24", "25"): "B_18-25",
             ("16", "17", "18"): "C_16-18 (chi benign)",
             ("23", "24", "25"): "D_23-25 (chi evaluation)",
             ("16", "17"): "E_16-17"}
    hosts = pd.DataFrame({"hostname": hostdays.index, "days": [",".join(x) for x in hostdays.values],
                          "n_days": [len(x) for x in hostdays.values], "group": [names[x] for x in hostdays.values]})
    hosts["host_id"] = hosts["hostname"].str[-4:].astype(int)
    hosts["original_split_step02"] = hosts["hostname"].map(man.drop_duplicates("hostname").set_index("hostname")["split"])
    grp = hosts.groupby("group").agg(hosts=("hostname", "size"), id_min=("host_id", "min"), id_max=("host_id", "max")).reset_index()
    grp.to_csv(out / "host_groups.csv", index=False)
    day_host = man.groupby(["date", "raw_source"])["hostname"].nunique().unstack(fill_value=0)
    day_host["hosts_total"] = man.groupby("date")["hostname"].nunique()
    day_host.to_csv(out / "host_files_by_day.csv")

    gt = json.loads((legacy / "artifacts" / "step02_label_split_v1_1" / "ground_truth_profile.json").read_text(encoding="utf-8"))
    gt_rows = []
    for f in gt["selected_files"]:
        gt_rows.append({"hostname": f["hostname_from_name"], "scenario": f["scenario_from_name"],
                        "gt_host_events": f["records"],
                        "gt_events_by_day_edt": json.dumps(f["observed_dates"])})
    gt_df = pd.DataFrame(gt_rows)

    # ---------------------------------------------------------------- 3) network (joined parquet)
    glob = (root / "02_artifacts" / "02_network_joined_v1" / "joined" / "split=*" / "date=*" / "*.parquet").as_posix()
    con = duckdb.connect()
    con.execute("SET threads=8")
    con.execute(f"CREATE VIEW j AS SELECT hostname, ts, label, app_family, resp_h, resp_p, split FROM read_parquet('{glob}', hive_partitioning=true)")
    net_host = con.execute("""SELECT hostname, count(*) net_events, sum((label=1)::INT) net_positive_events,
                              min(ts) ts0, max(ts) ts1, any_value(split) net_split FROM j GROUP BY 1""").fetchdf()
    net_host["net_days_edt"] = 0
    day_host_net = con.execute(f"""SELECT hostname, count(DISTINCT CAST(floor((ts - {EDT}) / 86400) AS BIGINT)) d FROM j GROUP BY 1""").fetchdf()
    net_host = net_host.merge(day_host_net, on="hostname").drop(columns="net_days_edt").rename(columns={"d": "net_days_edt"})

    hosts = hosts.merge(net_host, on="hostname", how="left")
    hosts["in_network_dataset"] = hosts["net_events"].notna()
    hosts = hosts.merge(gt_df, on="hostname", how="left")
    hosts["scenario"] = hosts["scenario"].fillna("")
    hosts.to_csv(out / "hosts_625.csv", index=False)

    unmatched = net_host[~net_host["hostname"].isin(hosts["hostname"])].copy()
    unmatched.to_csv(out / "network_hosts_without_ecar_host_files.csv", index=False)

    # ngay mang theo EDT
    day = con.execute(f"""SELECT strftime(to_timestamp(ts - {EDT}), '%Y-%m-%d') AS day_edt, count(*) events,
        count(DISTINCT hostname) hosts, sum((label=1)::INT) positive_events,
        count(DISTINCT CASE WHEN label=1 THEN hostname END) positive_hosts,
        round(100.0 * avg((app_family = 'firefox.exe')::INT), 2) pct_firefox
        FROM j GROUP BY 1 ORDER BY 1""").fetchdf()
    day.to_csv(out / "network_by_day_edt.csv", index=False)

    # ---------------------------------------------------------------- 4) scenario hosts
    scen = {r.hostname: r.scenario for r in gt_df.itertuples()}
    pos = con.execute("""SELECT hostname, resp_h || ':' || CAST(resp_p AS INT) endpoint, count(*) ev, min(ts) t0, max(ts) t1
                         FROM j WHERE label=1 GROUP BY 1,2""").fetchdf()
    top = pos.sort_values("ev", ascending=False).groupby("hostname").first().reset_index()[["hostname", "endpoint", "ev"]]
    top = top.rename(columns={"endpoint": "main_endpoint", "ev": "main_endpoint_events"})
    span = pos.groupby("hostname").agg(t0=("t0", "min"), t1=("t1", "max"), endpoints=("endpoint", lambda s: ";".join(sorted(set(s))))).reset_index()
    sc = gt_df.merge(net_host[["hostname", "net_events", "net_positive_events"]], on="hostname", how="left").merge(span, on="hostname", how="left").merge(top, on="hostname", how="left")
    sc["first_pos_edt"] = pd.to_datetime(sc["t0"] - EDT, unit="s").dt.strftime("%m-%d %H:%M")
    sc["last_pos_edt"] = pd.to_datetime(sc["t1"] - EDT, unit="s").dt.strftime("%m-%d %H:%M")
    sc = sc.drop(columns=["t0", "t1"])
    pw = pd.read_csv(root / "02_artifacts" / "10g_unseen_beacon_v1" / "beacon_profile" / "positive_windows.csv")
    sc["positive_windows_15min"] = sc["hostname"].map(pw.groupby("hostname").size()).fillna(0).astype(int)
    sc["group"] = sc["hostname"].map(hosts.set_index("hostname")["group"])
    sc["host_id"] = sc["hostname"].str[-4:].astype(int)
    sc.sort_values(["scenario", "host_id"]).drop(columns="host_id").to_csv(out / "scenario_hosts_29.csv", index=False)

    summary = {
        "raw_total_files": int(len(inv)), "raw_total_gb": round(float(inv["gb"].sum()), 2),
        "hosts_raw_manifest": int(len(hosts)), "hosts_in_network_dataset": int(hosts["in_network_dataset"].sum()),
        "hosts_without_network_rows": hosts.loc[~hosts["in_network_dataset"], "hostname"].tolist(),
        "network_hosts_without_ecar_host_files": int(len(unmatched)),
        "network_hosts_without_ecar_host_files_events": int(unmatched["net_events"].sum()),
        "scenario_host_counts": gt_df.groupby("scenario")["hostname"].nunique().to_dict(),
        "scenario_gt_host_events": gt_df.groupby("scenario")["gt_host_events"].sum().to_dict(),
        "scenario_network_positive_events": sc.groupby("scenario")["net_positive_events"].sum().astype(int).to_dict(),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("[OUT]", out)


if __name__ == "__main__":
    main()
