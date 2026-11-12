#!/usr/bin/env python3
"""S10a - skrghosh: các sự kiện FLOW eCAR (START/MESSAGE) -> bảng flow mức kết nối, cùng cột với flows_joined của OpTC (cột Bro để NULL).

Input : E:/NEWDATASET/skrghosh/{apt29,output_fin6,oilrig,output_menuPass,wizard_spider}.json và labeled/*.labels.csv (chỉ đọc)
Output: 02_artifacts/25_newdataset_preprocess_v1/skrghosh/data/flows_skrghosh.parquet, checks.json
Quy tắc (xem STEP_25):
  - 1 objectID FLOW = một chiều của một kết nối; mỗi kết nối thường có 2 object (outbound và inbound, địa chỉ không đảo). Gộp theo (IP:cổng hai đầu không phân chiều, giao thức,
    phiên cách nhau <= 120 giây) thành 1 flow để giống 1 dòng conn của Bro.
  - Đầu "phản hồi" (resp) = đầu không phải máy cục bộ; máy cục bộ = src_ip phổ biến nhất của các object outbound trong file.
  - ts = timestamp sớm nhất của kết nối (UTC); nhãn = 1 nếu có >= 1 sự kiện dương trong kết nối (nhãn do script KLTN gán, không phải của tác giả).
  - hostname = skr_<kịch bản> (mọi sự kiện trong file đều hostname=localhost nên mỗi file là một máy).
Chạy: python s10_skrghosh_flows.py [--scenarios fin6,apt29,...] [--limit-lines N] (limit chỉ để thử)"""
import argparse
import json
import sys
import time
from pathlib import Path

import duckdb

sys.stdout.reconfigure(encoding="utf-8")
SRC = Path("E:/NEWDATASET/skrghosh")
OUT = Path("D:/UIT/KLTNv2/02_artifacts/25_newdataset_preprocess_v1/skrghosh")
FILES = {"fin6": "output_fin6.json", "apt29": "apt29.json", "oilrig": "oilrig.json", "menupass": "output_menuPass.json", "wizard_spider": "wizard_spider.json"}
SESSION_GAP_S = 120

COLS = ("{id:'VARCHAR',action:'VARCHAR',object:'VARCHAR',objectID:'VARCHAR',timestamp:'VARCHAR',"
        "properties:'STRUCT(image_path VARCHAR,dest_ip VARCHAR,dest_port VARCHAR,src_ip VARCHAR,l4_protocol VARCHAR,direction VARCHAR,size VARCHAR,src_port VARCHAR)'}")

# epoch UTC từ chuỗi ISO có offset, không cần ICU: 2023-07-25T08:45:46.1193753-07:00
TS_EXPR = """(epoch(strptime(substr(timestamp, 1, 19), '%Y-%m-%dT%H:%M:%S'))
   + coalesce(try_cast('0.' || regexp_extract(timestamp, '\\.(\\d+)', 1) AS DOUBLE), 0.0)
   - (CASE WHEN substr(timestamp, length(timestamp) - 5, 1) = '-' THEN 1 ELSE -1 END)
     * (try_cast(substr(timestamp, length(timestamp) - 4, 2) AS INTEGER) * 3600 + try_cast(substr(timestamp, length(timestamp) - 1, 2) AS INTEGER) * 60))"""


def build_scenario(con, name, limit):
    t0 = time.time()
    js = (SRC / FILES[name]).as_posix()
    lb = (SRC / "labeled" / (FILES[name] + ".labels.csv")).as_posix()
    lim = f" LIMIT {limit}" if limit else ""
    con.execute(f"""CREATE OR REPLACE TEMP TABLE ev AS
        SELECT j.id, j.objectID AS oid, j.action, {TS_EXPR.replace('timestamp', 'j.timestamp')} AS ts,
               nullif(trim(j.properties.image_path), '') AS image_path, j.properties.dest_ip AS dest_ip, try_cast(j.properties.dest_port AS INTEGER) AS dest_port,
               j.properties.src_ip AS src_ip, try_cast(j.properties.src_port AS INTEGER) AS src_port, j.properties.l4_protocol AS l4, lower(j.properties.direction) AS direction,
               try_cast(j.properties.size AS BIGINT) AS size
        FROM read_json('{js}', format='newline_delimited', ignore_errors=true, columns={COLS}) j WHERE j.object = 'FLOW'{lim}""")
    if con.execute("SELECT count(*) FROM ev").fetchone()[0] == 0:  # OilRig và Wizard Spider không có sự kiện FLOW
        return {"scenario": name, "events": 0, "skipped": "không có sự kiện FLOW", "seconds": round(time.time() - t0, 1)}
    con.execute(f"CREATE OR REPLACE TEMP TABLE lb AS SELECT id, label FROM read_csv_auto('{lb}')")
    con.execute("CREATE OR REPLACE TEMP TABLE evl AS SELECT ev.*, coalesce(lb.label, 0)::INTEGER AS label FROM ev LEFT JOIN lb USING (id)")
    # object -> một dòng
    con.execute("""CREATE OR REPLACE TEMP TABLE obj AS
        SELECT oid, min(ts) AS ts, arg_min(image_path, ts) FILTER (WHERE image_path IS NOT NULL) AS image_path,
               any_value(src_ip) AS src_ip, any_value(src_port) AS src_port, any_value(dest_ip) AS dest_ip, any_value(dest_port) AS dest_port, any_value(l4) AS l4,
               any_value(direction) AS direction, max(label) AS label, count(*) AS n_events, sum(size) AS total_size
        FROM evl GROUP BY oid""")
    local_ip = con.execute("SELECT src_ip FROM obj WHERE direction = 'outbound' GROUP BY 1 ORDER BY count(*) DESC LIMIT 1").fetchone()[0]
    con.execute(f"""CREATE OR REPLACE TEMP TABLE obj2 AS
        SELECT *, CASE WHEN src_ip = '{local_ip}' THEN dest_ip ELSE src_ip END AS resp_h, CASE WHEN src_ip = '{local_ip}' THEN dest_port ELSE src_port END AS resp_p,
               CASE WHEN src_ip = '{local_ip}' THEN src_port ELSE dest_port END AS orig_p FROM obj""")
    # kết nối = (đầu cục bộ:cổng, đầu xa:cổng, l4); phiên mới khi cách phiên trước > SESSION_GAP_S
    con.execute(f"""CREATE OR REPLACE TEMP TABLE sess AS
        SELECT *, sum(newsess) OVER (PARTITION BY resp_h, resp_p, orig_p, l4 ORDER BY ts, oid) AS sess_no FROM (
          SELECT *, CASE WHEN lag(ts) OVER (PARTITION BY resp_h, resp_p, orig_p, l4 ORDER BY ts, oid) IS NULL
                          OR ts - lag(ts) OVER (PARTITION BY resp_h, resp_p, orig_p, l4 ORDER BY ts, oid) > {SESSION_GAP_S} THEN 1 ELSE 0 END AS newsess FROM obj2)""")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE flows AS
        SELECT '{name}:' || min(oid) AS uid, 'skr_{name}' AS hostname, min(ts) AS ts, (floor(min(ts) / 900) * 900)::BIGINT AS window_start_epoch,
               max(label)::TINYINT AS label, regexp_extract(lower(replace(trim(arg_min(image_path, ts) FILTER (WHERE image_path IS NOT NULL)), '/', '\\')), '[^\\\\]*$') AS app_family,
               arg_min(image_path, ts) FILTER (WHERE image_path IS NOT NULL) AS image_path,
               string_agg(DISTINCT direction, '+') AS direction, any_value(l4) AS l4_raw,
               CASE any_value(l4) WHEN '6' THEN 'tcp' WHEN '4' THEN 'tcp' WHEN '17' THEN 'udp' ELSE NULL END AS proto,  -- '4' chỉ gặp ở FIN6, kèm cổng 443/80/8888 => đoán là TCP (xem STEP_25)
               resp_h, resp_p, orig_p, count(*) AS n_objects, sum(n_events) AS n_events, sum(total_size) AS total_size,
               '{name}' AS scenario
        FROM sess GROUP BY resp_h, resp_p, orig_p, l4, sess_no""")
    st = {"scenario": name, "local_ip": local_ip, "events": con.execute("SELECT count(*) FROM ev").fetchone()[0], "events_positive": con.execute("SELECT sum(label) FROM evl").fetchone()[0],
          "objects": con.execute("SELECT count(*) FROM obj").fetchone()[0], "objects_positive": con.execute("SELECT sum((label=1)::INT) FROM obj").fetchone()[0],
          "flows": con.execute("SELECT count(*) FROM flows").fetchone()[0], "flows_positive": con.execute("SELECT sum(label) FROM flows").fetchone()[0],
          "flows_without_image_path": con.execute("SELECT count(*) FROM flows WHERE image_path IS NULL").fetchone()[0],
          "l4_values": dict(con.execute("SELECT l4_raw, count(*) FROM flows GROUP BY 1 ORDER BY 2 DESC").fetchall()),
          "l4_by_top_ports": con.execute("SELECT l4_raw, resp_p, count(*) n FROM flows GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 8").fetchall(),
          "ts_min": con.execute("SELECT min(ts) FROM flows").fetchone()[0], "ts_max": con.execute("SELECT max(ts) FROM flows").fetchone()[0],
          "positive_windows": con.execute("SELECT count(DISTINCT window_start_epoch) FROM flows WHERE label = 1").fetchone()[0], "windows": con.execute("SELECT count(DISTINCT window_start_epoch) FROM flows").fetchone()[0],
          "seconds": round(time.time() - t0, 1)}
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=",".join(FILES))
    ap.add_argument("--limit-lines", type=int, default=0)
    ap.add_argument("--out", default=str(OUT / "data"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute("SET memory_limit='10GB'; SET threads=8")
    stats, parts = [], []
    for name in a.scenarios.split(","):
        st = build_scenario(con, name, a.limit_lines)
        stats.append(st)
        if st.get("skipped"):
            print(json.dumps(st, ensure_ascii=False), flush=True)
            continue
        p = out / f"flows_{name}.parquet"
        con.execute(f"COPY (SELECT * FROM flows ORDER BY ts, uid) TO '{p.as_posix()}' (FORMAT PARQUET)")
        parts.append(p)
        print(json.dumps(st, ensure_ascii=False, default=str), flush=True)
    allp = out / "flows_skrghosh.parquet"
    pl = ", ".join(f"'{p.as_posix()}'" for p in parts)
    con.execute(f"COPY (SELECT * FROM read_parquet([{pl}])) TO '{allp.as_posix()}' (FORMAT PARQUET)")
    json.dump({"session_gap_seconds": SESSION_GAP_S, "scenarios": stats, "rows": con.execute(f"SELECT count(*) FROM read_parquet('{allp.as_posix()}')").fetchone()[0]},
              open(out.parent / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)


if __name__ == "__main__":
    main()
