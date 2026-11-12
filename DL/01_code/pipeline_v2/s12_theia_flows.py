#!/usr/bin/env python3
"""S12b - THEIA E3: bảng "flow" (mỗi netflow node = một socket) cùng cột với flows_joined của OpTC, kèm 3 biến thể nhãn.

Input : 02_artifacts/28_theia_analysis_v1/flows_theia_candidates.parquet (từ s12_theia_explore.py; nguồn E:/NEWDATASET (1)/DARPA-TC-E3-THEIA, chỉ đọc)
Output: 02_artifacts/28_theia_analysis_v1/data/flows_theia.parquet, checks_flows.json
Quy tắc:
  - flow = netflow node; ts = timestamp sớm nhất của các cạnh chạm node (epoch UTC); tiến trình của flow = tiến trình của cạnh sớm nhất; hostname = theia_e3 (một máy 128.55.12.110).
  - app_family = tên file (basename) của đường dẫn tiến trình, chữ thường, bỏ hậu tố ' (deleted)'; image_path giữ nguyên (để mã hóa image_dir_class); proto = NULL (bảng netflow không có);
    resp_h/resp_p = dst_addr/dst_port, nhưng 'NA' và cổng 0 coi là thiếu (NULL) vì đó là socket không có địa chỉ đích.
  - label_A = nhãn REAPr mức tiến trình (flow chạm >= 1 tiến trình có UUID trong theia_labels.csv); label_B = đích thuộc tập IP tấn công trong báo cáo Kudu (E3 Update);
    label_C (nhãn CHÍNH, cột `label`) = label_A VÀ flow nằm trong cửa sổ tấn công theo báo cáo (giờ báo cáo là EDT = UTC-4, đã đối chiếu với dữ liệu).
Cửa sổ tấn công UTC: 2018-04-10 17:35-19:05 (3.3), 2018-04-12 16:40-17:35 (3.11), 2018-04-13 17:55-18:15 (4.8 tcexec thất bại)."""
import json
import sys
from pathlib import Path

import duckdb

sys.stdout.reconfigure(encoding="utf-8")
ART = Path("D:/UIT/KLTNv2/02_artifacts/28_theia_analysis_v1")
IPS = ("145.199.103.57", "61.130.69.232", "5.214.163.155", "161.116.88.72", "146.153.68.151", "104.228.117.212", "141.43.176.203", "7.149.198.40", "149.52.198.23", "62.83.155.175", "208.75.117.3",
       "208.75.117.2")
WIN = [("2018-04-10 17:35", "2018-04-10 19:05"), ("2018-04-12 16:40", "2018-04-12 17:35"), ("2018-04-13 17:55", "2018-04-13 18:15")]


def main():
    (ART / "data").mkdir(exist_ok=True)
    con = duckdb.connect()
    inw = " OR ".join(f"(ts_utc BETWEEN TIMESTAMP '{a}' AND TIMESTAMP '{b}')" for a, b in WIN)
    ips = ", ".join(f"'{i}'" for i in IPS)
    con.execute(f"""CREATE TEMP TABLE f AS SELECT *, make_timestamp(ts_first_ns // 1000) AS ts_utc FROM read_parquet('{(ART / 'flows_theia_candidates.parquet').as_posix()}')""")
    con.execute(f"""CREATE TEMP TABLE g AS SELECT *, ({inw}) AS in_attack_window, (dst_addr IN ({ips})) AS to_report_ip FROM f""")
    out = (ART / "data/flows_theia.parquet").as_posix()
    con.execute(f"""COPY (
      SELECT 'theia:' || nf_hash AS uid, 'theia_e3' AS hostname, ts_first_ns / 1e9 AS ts, ((ts_first_ns // 1000000000) // 900 * 900)::BIGINT AS window_start_epoch,
             (pos AND in_attack_window)::TINYINT AS label, pos::TINYINT AS label_A, to_report_ip::TINYINT AS label_B, (pos AND in_attack_window)::TINYINT AS label_C,
             CASE WHEN path IS NULL OR path = 'N/A' THEN NULL ELSE regexp_extract(lower(regexp_replace(path, ' \\(deleted\\)$', '')), '[^/]*$') END AS app_family,
             CASE WHEN path IS NULL OR path = 'N/A' THEN NULL ELSE path END AS image_path,
             NULL::VARCHAR AS proto, CASE WHEN dst_addr = 'NA' OR dst_port = 0 THEN NULL ELSE dst_addr END AS resp_h, CASE WHEN dst_addr = 'NA' OR dst_port = 0 THEN NULL ELSE dst_port END AS resp_p,
             src_port AS orig_p, n_events, n_procs, cmd, ops, attack_chain, 'theia' AS scenario
      FROM g ORDER BY ts_first_ns, nf_hash) TO '{out}' (FORMAT PARQUET)""")
    r = lambda q: con.execute(q).fetchall()  # noqa: E731
    P = f"read_parquet('{out}')"
    ck = {"flows": r(f"SELECT count(*) FROM {P}")[0][0], "label_A_flows": r(f"SELECT sum(label_A) FROM {P}")[0][0], "label_B_flows": r(f"SELECT sum(label_B) FROM {P}")[0][0],
          "label_C_flows": r(f"SELECT sum(label_C) FROM {P}")[0][0],
          "windows": r(f"SELECT count(DISTINCT window_start_epoch) FROM {P}")[0][0],
          "windows_pos_A": r(f"SELECT count(DISTINCT window_start_epoch) FILTER (WHERE label_A = 1) FROM {P}")[0][0],
          "windows_pos_B": r(f"SELECT count(DISTINCT window_start_epoch) FILTER (WHERE label_B = 1) FROM {P}")[0][0],
          "windows_pos_C": r(f"SELECT count(DISTINCT window_start_epoch) FILTER (WHERE label_C = 1) FROM {P}")[0][0],
          "resp_port_missing_share": r(f"SELECT avg((resp_p IS NULL)::INT) FROM {P}")[0][0], "proto_missing_share": 1.0,
          "app_family_distinct": r(f"SELECT count(DISTINCT app_family) FROM {P}")[0][0],
          "top_app_family": r(f"SELECT app_family, count(*) n, sum(label_C) c FROM {P} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
          "label_C_by_app": r(f"SELECT app_family, count(*) FROM {P} WHERE label_C = 1 GROUP BY 1 ORDER BY 2 DESC"),
          "label_C_resp_port_missing": r(f"SELECT sum((resp_p IS NULL)::INT), count(*) FROM {P} WHERE label_C = 1")[0],
          "note": "label_C là cột `label`; B và A giữ để đối chiếu độ nhạy của nhãn"}
    json.dump(ck, open(ART / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print(json.dumps(ck, ensure_ascii=False, indent=1, default=str))


if __name__ == "__main__":
    main()
