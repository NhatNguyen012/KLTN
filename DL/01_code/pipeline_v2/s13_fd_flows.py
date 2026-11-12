#!/usr/bin/env python3
"""S13b - FIVEDIRECTIONS E3: bảng flow cùng cột với flows_joined của OpTC (cột Bro để NULL), kèm các biến thể nhãn.

Input : 02_artifacts/29_fivedirections_analysis_v1/flows_fd_candidates.parquet (từ s13_fd_explore.py; nguồn E:/NEWDATASET (1)/DARPA-TC-E3-FIVEDIRECTIONS/Parquet, chỉ đọc)
Output: 02_artifacts/29_fivedirections_analysis_v1/data/flows_fd.parquet, checks_flows.json
Quy tắc:
  - flow = netflow node; ts = cạnh sớm nhất; tiến trình = tiến trình của cạnh sớm nhất; hostname = fd_e3 (log gồm vài máy nhưng 98% flow thuộc máy 128.55.12.67; không tách máy).
  - LOẠI các socket chỉ có cạnh EVENT_BIND (không có đầu xa, không phải kết nối): 36,112 node.
  - Bảng tiến trình không có `path`; cột `cmd` là dòng lệnh. image_path = mục đầu của dòng lệnh (có hoặc không có nháy), app_family = tên file chữ thường.
  - Đầu phản hồi: nếu có CONNECT thì resp = (dst_addr, dst_port); nếu có ACCEPT thì resp_p = src_port (cổng dịch vụ cục bộ), resp_h = src_addr; còn lại (chỉ SENDTO/RECVFROM) resp_p = cổng nhỏ hơn trong hai cổng khác 0.
    Cổng 0 và địa chỉ rỗng coi là thiếu (NULL). proto = NULL (bảng netflow không có).
  - label_attack = flow chạm tiến trình có nhãn `attack` của REAPr; label_all = attack hoặc `contaminated`; label_B = đích thuộc tập IP tấn công trong báo cáo Kudu (E3 Update);
    `label` (nhãn CHÍNH) = label_attack HOẶC label_B (thêm 2 flow powershell tới 208.75.117.5/6 ngày 9/4 mà REAPr đánh dấu contaminated).
Giờ trong báo cáo là EDT (UTC-4), đã đối chiếu với dữ liệu (tấn công 11/4 lúc 14:08 UTC = 10:08 EDT)."""
import json
import sys
from pathlib import Path

import duckdb

sys.stdout.reconfigure(encoding="utf-8")
ART = Path("D:/UIT/KLTNv2/02_artifacts/29_fivedirections_analysis_v1")
IPS = ("179.252.65.246", "16.54.116.146", "156.78.147.114", "193.189.212.26", "27.56.56.211", "132.85.63.248", "135.84.161.202", "221.205.132.182", "208.75.117.5", "208.75.117.6", "208.75.117.3",
       "208.75.117.2")


def main():
    (ART / "data").mkdir(exist_ok=True)
    con = duckdb.connect()
    ips = ", ".join(f"'{i}'" for i in IPS)
    cand = (ART / "flows_fd_candidates.parquet").as_posix()
    out = (ART / "data/flows_fd.parquet").as_posix()
    img = "coalesce(nullif(regexp_extract(cmd, '^\\s*\"([^\"]+)\"', 1), ''), nullif(regexp_extract(cmd, '^\\s*(\\S+)', 1), ''))"
    con.execute(f"""CREATE TEMP TABLE g0 AS SELECT *, {img} AS image_path0 FROM read_parquet('{cand}')""")
    con.execute("""CREATE TEMP TABLE g1 AS SELECT *, CASE WHEN image_path0 IS NULL THEN NULL ELSE regexp_extract(lower(replace(image_path0, '/', '\\')), '[^\\\\]*$') END AS base0 FROM g0""")
    con.execute(f"""CREATE TEMP TABLE g AS SELECT *, (ops LIKE '%CONNECT%') AS has_connect, (ops LIKE '%ACCEPT%') AS has_accept,
                    (ops = 'EVENT_BIND') AS bind_only, (dst_addr IN ({ips})) AS to_report_ip FROM g1""")
    con.execute(f"""COPY (
      SELECT 'fd:' || nf_hash AS uid, 'fd_e3' AS hostname, ts_first_ns / 1e9 AS ts, ((ts_first_ns // 1000000000) // 900 * 900)::BIGINT AS window_start_epoch,
             (coalesce(pos_attack, false) OR to_report_ip)::TINYINT AS label, coalesce(pos_attack, false)::TINYINT AS label_attack, coalesce(pos, false)::TINYINT AS label_all, to_report_ip::TINYINT AS label_B,
             CASE WHEN base0 IS NULL THEN NULL WHEN position('.' IN base0) = 0 AND base0 <> 'system' THEN base0 || '.exe' ELSE base0 END AS app_family,
             image_path0 AS image_path, NULL::VARCHAR AS proto,
             CASE WHEN has_connect THEN dst_addr WHEN has_accept THEN src_addr ELSE dst_addr END AS resp_h,
             CASE WHEN has_connect THEN nullif(dst_port, 0)
                  WHEN has_accept THEN nullif(src_port, 0)
                  ELSE CASE WHEN src_port > 0 AND dst_port > 0 THEN least(src_port, dst_port) ELSE nullif(greatest(src_port, dst_port), 0) END END AS resp_p,
             src_port AS orig_p, n_events, n_procs, cmd, ops, attack_chain, 'fivedirections' AS scenario
      FROM g WHERE NOT bind_only ORDER BY ts_first_ns, nf_hash) TO '{out}' (FORMAT PARQUET)""")
    r = lambda q: con.execute(q).fetchall()  # noqa: E731
    P = f"read_parquet('{out}')"
    ck = {"flows_candidates": r(f"SELECT count(*) FROM read_parquet('{cand}')")[0][0], "bind_only_removed": r("SELECT sum(bind_only::INT), sum((bind_only AND pos_attack)::INT) FROM g")[0],
          "flows": r(f"SELECT count(*) FROM {P}")[0][0], "label_primary_flows": r(f"SELECT sum(label) FROM {P}")[0][0], "label_attack_flows": r(f"SELECT sum(label_attack) FROM {P}")[0][0],
          "label_all_flows": r(f"SELECT sum(label_all) FROM {P}")[0][0], "label_B_flows": r(f"SELECT sum(label_B) FROM {P}")[0][0],
          "windows": r(f"SELECT count(DISTINCT window_start_epoch) FROM {P}")[0][0], "windows_pos_primary": r(f"SELECT count(DISTINCT window_start_epoch) FILTER (WHERE label = 1) FROM {P}")[0][0],
          "app_family_distinct": r(f"SELECT count(DISTINCT app_family) FROM {P}")[0][0], "app_family_null": r(f"SELECT count(*) FROM {P} WHERE app_family IS NULL")[0][0],
          "resp_port_missing_share": r(f"SELECT avg((resp_p IS NULL)::INT) FROM {P}")[0][0],
          "top_app_family": r(f"SELECT app_family, count(*) n, sum(label) c FROM {P} GROUP BY 1 ORDER BY 2 DESC LIMIT 14"),
          "label_by_app": r(f"SELECT app_family, count(*) FROM {P} WHERE label = 1 GROUP BY 1 ORDER BY 2 DESC"),
          "label_resp_port_missing": r(f"SELECT sum((resp_p IS NULL)::INT), count(*) FROM {P} WHERE label = 1")[0],
          "positive_windows": r(f"SELECT strftime(make_timestamp(window_start_epoch * 1000000), '%Y-%m-%d %H:%M') w, count(*) n, sum(label) pos FROM {P} GROUP BY window_start_epoch HAVING sum(label) > 0 ORDER BY window_start_epoch")}
    json.dump(ck, open(ART / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print(json.dumps(ck, ensure_ascii=False, indent=1, default=str))


if __name__ == "__main__":
    main()
