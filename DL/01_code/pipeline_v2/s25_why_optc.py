#!/usr/bin/env python3
"""S25 (STEP 40) - OpTC: flow dương (label=1) khác flow benign ở field nào. Chỉ đọc flows_joined.parquet (S1). Ghi vài CSV/JSON."""
import json
import os
import sys

import duckdb

sys.stdout.reconfigure(encoding="utf-8")
FLOWS = r"D:\UIT\KLTNv2\02_artifacts\22_v2_pipeline\S1_join\data\flows_joined.parquet"
OUT = r"D:\UIT\KLTNv2\02_artifacts\40_why_malicious_v1\optc"
os.makedirs(OUT, exist_ok=True)
con = duckdb.connect()
con.execute("pragma threads=6")
con.execute(f"create view f as select * from read_parquet('{FLOWS}')")


def q(name, sql):
    df = con.execute(sql).fetchdf()
    df.to_csv(os.path.join(OUT, name + ".csv"), index=False, encoding="utf-8", lineterminator="\n")
    print("==", name, len(df), flush=True)
    print(df.head(25).to_string(), flush=True)
    return df


tot = con.execute("select count(*), sum(label) from f").fetchone()
print("tổng flow, dương:", tot)
json.dump({"n_flows": tot[0], "n_pos": int(tot[1])}, open(os.path.join(OUT, "totals.json"), "w"))

q("pos_by_app", "select app_family, count(*) n_all, sum(label) n_pos, round(100.0*sum(label)/count(*),3) pct_pos from f group by 1 having sum(label)>0 order by n_pos desc")
q("pos_by_principal", "select principal, count(*) n_all, sum(label) n_pos from f group by 1 having sum(label)>0 order by n_pos desc limit 20")
q("pos_by_resp", "select resp_h, resp_p, count(*) n_all, sum(label) n_pos from f group by 1,2 having sum(label)>0 order by n_pos desc limit 30")
q("pos_by_direction_proto", "select direction, proto, service, count(*) n_all, sum(label) n_pos from f group by 1,2,3 having sum(label)>0 order by n_pos desc")
q("pos_by_day", "select date_utc, count(*) n_all, sum(label) n_pos, count(distinct hostname) filter (where label=1) hosts_pos from f group by 1 order by 1")
q("pos_by_imgdir", "select regexp_replace(lower(coalesce(image_path,'')), '[^\\\\/]+$', '') dir, count(*) n_all, sum(label) n_pos from f group by 1 having sum(label)>0 order by n_pos desc limit 15")
# các app có cả benign lẫn dương: tỷ lệ dương
q("apps_mixed", "select app_family, count(*) n_all, sum(label) n_pos from f group by 1 having sum(label)>0 and sum(label)<count(*) order by n_pos desc limit 20")
# Dương không do powershell
q("pos_nonps_by_resp", "select resp_h, resp_p, count(*) n_pos from f where label=1 and app_family<>'powershell.exe' group by 1,2 order by 3 desc limit 15")
# benign từng đến C2 (cùng đích với dương)?
q("benign_to_pos_dest", "with d as (select distinct resp_h, resp_p from f where label=1) select count(*) n_benign_same_dest from f join d using (resp_h, resp_p) where f.label=0")
# số cửa sổ dương, và nhịp (khoảng cách giữa các flow dương cùng máy)
q("pos_windows", "select count(distinct (hostname, window_start_epoch)) n_pos_windows, count(distinct hostname) n_hosts from f where label=1")
