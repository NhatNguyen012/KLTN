#!/usr/bin/env python3
"""S13a - Khảo sát DARPA TC E3 FIVEDIRECTIONS (Windows 10, Parquet): biến cạnh process-netflow thành bảng flow ứng viên (mỗi netflow node một dòng), kèm nhãn REAPr mức tiến trình.
Chỉ đọc E:, ghi vào 02_artifacts/29_fivedirections_analysis_v1/ (explore.json, flows_fd_candidates.parquet)."""
import json
import sys
import time
from pathlib import Path

import duckdb
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
BASE = "E:/NEWDATASET (1)/DARPA-TC-E3-FIVEDIRECTIONS/Parquet/"
LAB = "E:/NEWDATASET (1)/research/code_references/NDSS/theseus-main/ground_truth/reapr-ground-truth/darpa-tc-engagement3/fivedirections_labels.csv"
OUT = Path("D:/UIT/KLTNv2/02_artifacts/29_fivedirections_analysis_v1")
OUT.mkdir(parents=True, exist_ok=True)
con = duckdb.connect()
con.execute("SET memory_limit='12GB'; SET threads=8")
T0 = time.time()
R = {}


def log(k, v):
    R[k] = v
    print(k, "=", json.dumps(v, ensure_ascii=False, default=str)[:1500], f"({time.time() - T0:.0f}s)", flush=True)


P = lambda t: f"read_parquet('{BASE}{t}.parquet')"  # noqa: E731
con.execute(f"CREATE TEMP TABLE nf AS SELECT hash_id, node_uuid, src_addr, src_port, dst_addr, dst_port FROM {P('netflow_node_table')}")
con.execute(f"CREATE TEMP TABLE pr AS SELECT hash_id, node_uuid, path, cmd FROM {P('process_node_table')}")
log("process_cmd_top", con.execute("SELECT cmd, count(*) FROM pr GROUP BY 1 ORDER BY 2 DESC LIMIT 25").fetchall())
log("process_cmd_forms", con.execute("SELECT count(*), sum((cmd LIKE 'proc%')::INT), sum((cmd ILIKE '%.exe')::INT), sum((position('\\' in cmd) > 0 OR position('/' in cmd) > 0)::INT), sum((path IS NOT NULL)::INT) FROM pr").fetchone())
log("netflow_nodes", con.execute("SELECT count(*), sum((dst_port=0)::INT), sum((dst_addr='NA' OR dst_addr IS NULL)::INT), count(DISTINCT src_addr) FROM nf").fetchone())
con.execute(f"CREATE TEMP TABLE ev_out AS SELECT e.src_node AS proc_hash, e.dst_node AS nf_hash, e.operation, e.timestamp_rec AS ts FROM {P('event_table')} e JOIN nf ON e.dst_node = nf.hash_id")
con.execute(f"CREATE TEMP TABLE ev_in AS SELECT e.dst_node AS proc_hash, e.src_node AS nf_hash, e.operation, e.timestamp_rec AS ts FROM {P('event_table')} e JOIN nf ON e.src_node = nf.hash_id")
log("edges_process_to_netflow_by_op", con.execute("SELECT operation, count(*) FROM ev_out GROUP BY 1 ORDER BY 2 DESC").fetchall())
log("edges_netflow_to_process_by_op", con.execute("SELECT operation, count(*) FROM ev_in GROUP BY 1 ORDER BY 2 DESC").fetchall())
con.execute("CREATE TEMP TABLE ev AS SELECT *, 'out' AS dir FROM ev_out UNION ALL SELECT *, 'in' AS dir FROM ev_in")
log("netflow_nodes_with_events", con.execute("SELECT count(DISTINCT nf_hash) FROM ev").fetchone()[0])
log("netflow_nodes_with_multiple_processes", con.execute("SELECT count(*) FROM (SELECT nf_hash FROM ev GROUP BY 1 HAVING count(DISTINCT proc_hash) > 1)").fetchone()[0])
log("ts_range_utc", con.execute("SELECT strftime(make_timestamp(min(ts) // 1000), '%Y-%m-%d %H:%M'), strftime(make_timestamp(max(ts) // 1000), '%Y-%m-%d %H:%M') FROM ev").fetchone())
ldf = pd.read_csv(LAB, skipinitialspace=True, usecols=["attack_chain", "uuid", "process_name", "label"], on_bad_lines="skip", engine="python")
ldf["uuid"] = ldf.uuid.astype(str).str.strip().str.upper()
ldf["label"] = ldf.label.astype(str).str.strip()
log("label_rows", int(len(ldf)))
log("label_by_chain_label", ldf.groupby(["attack_chain", "label"]).size().reset_index().values.tolist())
con.register("ldf", ldf.drop_duplicates("uuid"))
con.execute("CREATE TEMP TABLE lab AS SELECT uuid, attack_chain, process_name, label AS lab_label FROM ldf")
log("labels_found_in_process_table", con.execute("SELECT count(*) FROM lab JOIN pr ON upper(pr.node_uuid) = lab.uuid").fetchone()[0])
con.execute("CREATE TEMP TABLE prl AS SELECT pr.hash_id, pr.node_uuid, pr.path, pr.cmd, lab.uuid IS NOT NULL AS pos, lab.lab_label, lab.attack_chain FROM pr LEFT JOIN lab ON upper(pr.node_uuid) = lab.uuid")
con.execute("""CREATE TEMP TABLE flows AS
  SELECT nf.hash_id AS nf_hash, nf.src_addr, nf.src_port, nf.dst_addr, nf.dst_port,
         min(ev.ts) AS ts_first_ns, max(ev.ts) AS ts_last_ns, count(*) AS n_events, count(DISTINCT ev.proc_hash) AS n_procs,
         arg_min(prl.cmd, ev.ts) AS cmd, arg_min(prl.node_uuid, ev.ts) AS proc_uuid, bool_or(prl.pos) AS pos, bool_or(prl.pos AND prl.lab_label = 'attack') AS pos_attack,
         any_value(prl.attack_chain) FILTER (WHERE prl.pos) AS attack_chain, string_agg(DISTINCT ev.operation, ',') AS ops
  FROM ev JOIN nf ON ev.nf_hash = nf.hash_id LEFT JOIN prl ON ev.proc_hash = prl.hash_id GROUP BY nf.hash_id, nf.src_addr, nf.src_port, nf.dst_addr, nf.dst_port""")
log("flows_total", con.execute("SELECT count(*), sum(pos::INT), sum(pos_attack::INT), count(DISTINCT cmd), sum((dst_port = 0)::INT) FROM flows").fetchone())
log("flows_by_day_utc", con.execute("SELECT strftime(make_timestamp(ts_first_ns // 1000), '%Y-%m-%d') d, count(*) n, sum(pos::INT) pos, sum(pos_attack::INT) posatk, count(DISTINCT cmd) apps FROM flows GROUP BY 1 ORDER BY 1").fetchall())
log("positive_flows_by_cmd", con.execute("SELECT cmd, count(*) n, sum(pos_attack::INT) atk, count(DISTINCT dst_addr) dips, min(dst_port), max(dst_port), any_value(attack_chain) FROM flows WHERE pos GROUP BY 1 ORDER BY 2 DESC LIMIT 15").fetchall())
log("top_cmd_all", con.execute("SELECT cmd, count(*) n, sum(pos::INT) pos FROM flows GROUP BY 1 ORDER BY 2 DESC LIMIT 20").fetchall())
log("dst_port_known_top", con.execute("SELECT dst_port, count(*) n, sum(pos::INT) pos FROM flows WHERE dst_port > 0 GROUP BY 1 ORDER BY 2 DESC LIMIT 12").fetchall())
log("windows_15min", con.execute("SELECT count(DISTINCT (ts_first_ns // 1000000000 // 900)), count(DISTINCT (ts_first_ns // 1000000000 // 900)) FILTER (WHERE pos) FROM flows").fetchone())
log("flows_per_window_quantiles", con.execute("SELECT quantile_cont(n, [0.5, 0.9, 0.99]), max(n) FROM (SELECT count(*) n FROM flows GROUP BY ts_first_ns // 1000000000 // 900)").fetchone())
con.execute(f"COPY (SELECT * FROM flows) TO '{(OUT / 'flows_fd_candidates.parquet').as_posix()}' (FORMAT PARQUET)")
json.dump(R, open(OUT / "explore.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
print("xong", round(time.time() - T0), "s")
