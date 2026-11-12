#!/usr/bin/env python3
"""S1 - JOIN: Bro conn (E:\\bro) INNER JOIN eCAR-Bro (E:\\ecar-bro) theo bro_uid = uid, đọc thẳng từ raw bằng DuckDB.

Input : E:\\bro\\<ngày>\\conn.*.log.gz (22 trường Zeek, có `label`), E:\\ecar-bro\\**\\ecarbro.json.gz (event FLOW có properties.bro_uid)
Output: <out>/data/flows_joined.parquet  (1 dòng = 1 flow, sắp theo hostname, ts, uid)
        <out>/schema.json, preview.csv, preview_record.json, checks.json, unmatched_flows_audit.csv, unmatched_counts_by_host_date.csv, run_log.txt
Quy tắc: inner join (đã chốt); 1 dòng mỗi uid; eCAR-Bro trùng uid -> lấy bản ghi sớm nhất (timestamp, rồi id); loại uid có hostname xung đột.
Chỉ ĐỌC từ E:; không ghi vào E:.
"""
import argparse
import csv
import json
import os
import shutil
import sys
import time
from pathlib import Path

import duckdb

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
BRO = Path("E:/bro")
ECAR = os.environ.get("S1_ECAR_GLOB", "E:/ecar-bro/**/ecarbro.json.gz")
DEFAULT_DATES = [f"2019-09-{d}" for d in range(17, 26)]
ZEEK_COLS = ["ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
             "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "label"]

HOST_SQL = ("CASE WHEN regexp_matches(lower(trim({h})), '\\bsysclient\\d{{4}}\\b') THEN regexp_extract(lower(trim({h})), '\\b(sysclient\\d{{4}})\\b', 1) "
            "ELSE lower(trim({h})) END")

SCHEMA = [
    ("uid", "string", "khóa", "Bro conn.uid (= eCAR-Bro properties.bro_uid)", "Mã kết nối duy nhất; khóa nối hai nguồn."),
    ("ts", "double", "khóa", "Bro conn.ts", "Thời điểm bắt đầu kết nối, epoch giây (UTC)."),
    ("ts_utc", "string", "audit", "dẫn xuất từ ts", "ts dạng đọc được, UTC, 'YYYY-MM-DD HH:MM:SS.ffffff'."),
    ("date_utc", "string", "audit", "dẫn xuất từ ts", "Ngày UTC của ts."),
    ("window_start_epoch", "int64", "khóa", "floor(ts/900)*900", "Đầu cửa sổ 15 phút chứa flow (epoch UTC)."),
    ("hostname", "string", "khóa", "eCAR-Bro hostname, chữ thường, rút 'sysclientNNNN' khỏi tên miền", "Máy sinh ra flow."),
    ("label", "int8", "nhãn", "Bro conn.label (A New Hope)", "0 = benign, 1 = flow thuộc hoạt động tấn công (IP máy bị chiếm + IP C2 + thời gian, kiểm tay)."),
    ("app_family", "string", "feature", "tên file của eCAR-Bro properties.image_path, chữ thường", "Tiến trình (ứng dụng) tạo ra flow."),
    ("image_path", "string", "audit", "eCAR-Bro properties.image_path (nguyên văn)", "Đường dẫn file thực thi đầy đủ."),
    ("direction", "string", "audit", "eCAR-Bro properties.direction (chữ thường)", "outbound / inbound."),
    ("ecar_l4protocol", "string", "audit", "eCAR-Bro properties.l4protocol (chữ thường)", "Số hiệu giao thức IP theo eCAR (6 = TCP, 17 = UDP); chỉ để đối chiếu với proto."),
    ("orig_h", "string", "audit", "Bro id.orig_h", "IP nguồn (máy khởi tạo)."),
    ("orig_p", "int32", "audit", "Bro id.orig_p", "Cổng nguồn."),
    ("resp_h", "string", "audit", "Bro id.resp_h", "IP đích."),
    ("resp_p", "int32", "feature", "Bro id.resp_p", "Cổng đích (mã hóa thành resp_port_class ở S3)."),
    ("proto", "string", "feature", "Bro proto (chữ thường)", "tcp / udp / icmp."),
    ("service", "string", "feature", "Bro service (chữ thường)", "Dịch vụ Zeek nhận diện; '-' trong raw -> NULL."),
    ("duration", "double", "feature", "Bro duration", "Thời lượng kết nối (giây); NULL nếu thiếu."),
    ("orig_bytes", "int64", "feature", "Bro orig_bytes", "Byte ứng dụng nguồn gửi."),
    ("resp_bytes", "int64", "feature", "Bro resp_bytes", "Byte ứng dụng đích gửi."),
    ("conn_state", "string", "feature", "Bro conn_state", "SF, S0, REJ, RSTO, ..."),
    ("local_orig", "string", "audit", "Bro local_orig", "T/F."),
    ("local_resp", "string", "audit", "Bro local_resp", "T/F."),
    ("missed_bytes", "int64", "feature", "Bro missed_bytes", "Byte bị lỡ (thành cờ has_missed_bytes ở S3)."),
    ("history", "string", "audit", "Bro history", "Chuỗi cờ TCP."),
    ("orig_pkts", "int64", "feature", "Bro orig_pkts", "Gói nguồn gửi."),
    ("orig_ip_bytes", "int64", "feature", "Bro orig_ip_bytes", "Byte tầng IP nguồn."),
    ("resp_pkts", "int64", "feature", "Bro resp_pkts", "Gói đích gửi."),
    ("resp_ip_bytes", "int64", "feature", "Bro resp_ip_bytes", "Byte tầng IP đích."),
    ("actor_id", "string", "audit", "eCAR-Bro actorID", "UUID tiến trình tạo flow (chỉ để audit; KHÔNG vào feature/shards)."),
    ("pid", "int64", "audit", "eCAR-Bro pid", "Process ID (chỉ là số; KHÔNG vào feature/shards)."),
    ("ppid", "int64", "audit", "eCAR-Bro ppid", "Process ID cha (chỉ là số; KHÔNG vào feature/shards)."),
    ("principal", "string", "audit", "eCAR-Bro principal", "Tài khoản chạy tiến trình (KHÔNG vào feature/shards)."),
    ("ecar_occurrence_count", "int64", "audit", "đếm số bản ghi eCAR-Bro cùng uid trước khi khử trùng", "1 = không trùng."),
]

LOG = None


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    if LOG:
        LOG.write(line + "\n")
        LOG.flush()


def connect(threads, mem, tmp):
    tmp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"SET threads={threads}; SET memory_limit='{mem}'; SET temp_directory='{str(tmp).replace(chr(92), '/')}'; SET preserve_insertion_order=false;")
    return con


def p(path):
    return str(path).replace("\\", "/").replace("'", "''")


def stage_ecar(con, work, force):
    """Đọc eCAR-Bro 2 pha để không giữ 92M nhóm với nhiều cột trong RAM:
    (a) ghi bảng thô ecar_raw.parquet (streaming); (b) tìm uid trùng (chỉ đếm); (c) bảng khử trùng: uid không trùng lấy nguyên, uid trùng lấy bản ghi sớm nhất (ets, id)."""
    out = work / "ecar_dedup.parquet"
    if out.exists() and not force:
        log(f"ecar_dedup đã có, dùng lại: {out}")
        return out, None
    t0 = time.time()
    raw = work / "ecar_raw.parquet"
    h = HOST_SQL.format(h="hostname")
    if force or not raw.exists():
        log("eCAR-Bro (a): đọc 156 file JSON gz -> ecar_raw.parquet ...")
        con.execute(f"""
        COPY (
          SELECT trim(properties.bro_uid) AS uid, {h} AS hostname, id,
                 COALESCE(epoch(TRY_CAST(timestamp AS TIMESTAMPTZ)), 1e18) AS ets,
                 properties.image_path AS image_path, lower(trim(properties.direction)) AS direction, lower(trim(properties.l4protocol)) AS ecar_l4protocol,
                 actorID AS actor_id, TRY_CAST(pid AS BIGINT) AS pid, TRY_CAST(ppid AS BIGINT) AS ppid, principal
          FROM read_json('{ECAR}', format='newline_delimited', ignore_errors=true, maximum_object_size=16777216,
               columns={{timestamp:'VARCHAR', id:'VARCHAR', hostname:'VARCHAR', actorID:'VARCHAR', pid:'VARCHAR', ppid:'VARCHAR', principal:'VARCHAR',
                        properties:'STRUCT(bro_uid VARCHAR, image_path VARCHAR, direction VARCHAR, l4protocol VARCHAR)'}})
          WHERE properties.bro_uid IS NOT NULL AND trim(properties.bro_uid) <> ''
        ) TO '{p(raw)}.building' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 250000)
        """)
        Path(str(raw) + ".building").replace(raw)
    n_raw = con.execute(f"SELECT count(*) FROM read_parquet('{p(raw)}')").fetchone()[0]
    log(f"eCAR-Bro (a) xong: {n_raw:,} bản ghi có bro_uid ({time.time() - t0:.0f}s)")
    con.execute("DROP TABLE IF EXISTS dup_uid")
    con.execute(f"CREATE TEMP TABLE dup_uid AS SELECT uid FROM read_parquet('{p(raw)}') GROUP BY uid HAVING count(*) > 1")
    n_dup = con.execute("SELECT count(*) FROM dup_uid").fetchone()[0]
    log(f"eCAR-Bro (b): {n_dup:,} uid trùng ({time.time() - t0:.0f}s)")
    app = "lower(regexp_extract(replace(trim({x}), '/', '\\\\'), '[^\\\\\\\\]*$'))"
    con.execute(f"""
    COPY (
      SELECT uid, hostname, image_path, {app.format(x='image_path')} AS app_family, direction, ecar_l4protocol, actor_id, pid, ppid, principal,
             1::BIGINT AS ecar_occurrence_count, false AS hostname_conflict
      FROM read_parquet('{p(raw)}') WHERE uid NOT IN (SELECT uid FROM dup_uid)
      UNION ALL
      SELECT uid, arg_min(hostname, (ets, id)), arg_min(image_path, (ets, id)), {app.format(x="arg_min(image_path, (ets, id))")},
             arg_min(direction, (ets, id)), arg_min(ecar_l4protocol, (ets, id)), arg_min(actor_id, (ets, id)), arg_min(pid, (ets, id)),
             arg_min(ppid, (ets, id)), arg_min(principal, (ets, id)), count(*)::BIGINT, (min(hostname) <> max(hostname))
      FROM read_parquet('{p(raw)}') WHERE uid IN (SELECT uid FROM dup_uid) GROUP BY uid
    ) TO '{p(out)}.building' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 250000)
    """)
    Path(str(out) + ".building").replace(out)
    st = con.execute(f"SELECT count(*), sum(ecar_occurrence_count), sum((ecar_occurrence_count>1)::INT), sum(hostname_conflict::INT) FROM read_parquet('{p(out)}')").fetchone()
    stats = {"unique_uid": int(st[0]), "raw_rows": int(st[1]), "duplicate_uid": int(st[2]), "hostname_conflict_uid": int(st[3]), "seconds": round(time.time() - t0, 1)}
    log(f"eCAR-Bro (c) xong: {stats}")
    return out, stats


def conn_files(date):
    d = BRO / date
    return sorted(str(f).replace("\\", "/") for f in d.glob("conn.*.log.gz"))


def stage_day(con, date, ecar, work, force):
    done = work / f"joined_{date}.parquet"
    if done.exists() and not force:
        log(f"{date}: đã có, bỏ qua")
        return None
    files = conn_files(date)
    if not files:
        log(f"{date}: không có file conn")
        return None
    t0 = time.time()
    cols = ", ".join(f"'{c}':'VARCHAR'" for c in ZEEK_COLS)
    nul = lambda c: f"NULLIF({c}, '-')"  # noqa: E731
    con.execute("DROP TABLE IF EXISTS conn_day")
    con.execute(f"""
      CREATE TEMP TABLE conn_day AS
      SELECT TRY_CAST(ts AS DOUBLE) AS ts, uid, orig_h, TRY_CAST(orig_p AS INTEGER) AS orig_p, resp_h, TRY_CAST(resp_p AS INTEGER) AS resp_p,
             lower(trim(proto)) AS proto, lower(trim({nul('service')})) AS service, TRY_CAST({nul('duration')} AS DOUBLE) AS duration,
             TRY_CAST({nul('orig_bytes')} AS BIGINT) AS orig_bytes, TRY_CAST({nul('resp_bytes')} AS BIGINT) AS resp_bytes, conn_state, local_orig, local_resp,
             TRY_CAST({nul('missed_bytes')} AS BIGINT) AS missed_bytes, history, TRY_CAST({nul('orig_pkts')} AS BIGINT) AS orig_pkts,
             TRY_CAST({nul('orig_ip_bytes')} AS BIGINT) AS orig_ip_bytes, TRY_CAST({nul('resp_pkts')} AS BIGINT) AS resp_pkts,
             TRY_CAST({nul('resp_ip_bytes')} AS BIGINT) AS resp_ip_bytes, TRY_CAST(label AS TINYINT) AS label
      FROM read_csv({json.dumps(files)}, delim='\\t', header=false, skip=8, quote='', escape='', auto_detect=false, null_padding=true,
                    columns={{{cols}}})
      WHERE ts NOT LIKE '#%'
    """)
    n_conn = con.execute("SELECT count(*) FROM conn_day").fetchone()[0]
    t1 = time.time()
    log(f"{date}: đọc {len(files)} file conn, {n_conn:,} dòng ({t1 - t0:.0f}s)")
    ep = p(ecar)
    # MỘT lần join (conn_day LEFT JOIN eCAR) -> bảng tạm; ba đầu ra (flow ghép, đếm không ghép, flow dương không ghép) lấy từ bảng này.
    con.execute("DROP TABLE IF EXISTS jday")
    con.execute(f"""
      CREATE TEMP TABLE jday AS
      SELECT c.*, e.uid AS e_uid, e.hostname, e.image_path, e.app_family, e.direction, e.ecar_l4protocol, e.actor_id, e.pid, e.ppid, e.principal,
             e.ecar_occurrence_count, e.hostname_conflict
      FROM conn_day c LEFT JOIN read_parquet('{ep}') e ON c.uid = e.uid
    """)
    con.execute("DROP TABLE conn_day")
    con.execute(f"""
      COPY (
        SELECT uid, ts,
               strftime(make_timestamp((ts*1000000)::BIGINT), '%Y-%m-%d %H:%M:%S.%f') AS ts_utc,
               strftime(make_timestamp((ts*1000000)::BIGINT), '%Y-%m-%d') AS date_utc,
               (floor(ts/900)*900)::BIGINT AS window_start_epoch,
               hostname, label, app_family, image_path, direction, ecar_l4protocol,
               orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp,
               missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes,
               actor_id, pid, ppid, principal, ecar_occurrence_count
        FROM jday WHERE e_uid IS NOT NULL AND NOT hostname_conflict
        QUALIFY row_number() OVER (PARTITION BY uid ORDER BY ts NULLS LAST) = 1
      ) TO '{p(done)}.building' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 250000)
    """)
    Path(str(done) + ".building").replace(done)
    con.execute(f"""
      COPY (
        SELECT orig_h, '{date}' AS bro_dir_date, count(*)::BIGINT AS bro_rows,
               sum((e_uid IS NOT NULL AND NOT hostname_conflict)::INT)::BIGINT AS matched_rows,
               sum((NOT (e_uid IS NOT NULL AND NOT hostname_conflict))::INT)::BIGINT AS unmatched_rows,
               sum(((NOT (e_uid IS NOT NULL AND NOT hostname_conflict)) AND label = 1)::INT)::BIGINT AS unmatched_positive_rows
        FROM jday GROUP BY orig_h
      ) TO '{p(work)}/counts_{date}.parquet' (FORMAT PARQUET)
    """)
    con.execute(f"""
      COPY (
        SELECT uid, ts, strftime(make_timestamp((ts*1000000)::BIGINT), '%Y-%m-%d %H:%M:%S.%f') AS ts_utc, '{date}' AS bro_dir_date,
               orig_h, orig_p, resp_h, resp_p, proto, service, conn_state, orig_bytes, resp_bytes, label
        FROM jday WHERE label = 1 AND NOT (e_uid IS NOT NULL AND NOT hostname_conflict)
      ) TO '{p(work)}/unmatched_pos_{date}.parquet' (FORMAT PARQUET)
    """)
    n_join = con.execute(f"SELECT count(*) FROM read_parquet('{p(done)}')").fetchone()[0]
    log(f"{date}: join xong {n_join:,} flow ({time.time() - t1:.0f}s); tổng {time.time() - t0:.0f}s")
    con.execute("DROP TABLE jday")
    return {"date": date, "conn_files": len(files), "conn_rows": int(n_conn), "joined_rows": int(n_join), "seconds": round(time.time() - t0, 1)}


def stage_final(con, work, out, dates, ecar_stats, day_stats):
    data = out / "data"
    data.mkdir(parents=True, exist_ok=True)
    final = data / "flows_joined.parquet"
    parts = [work / f"joined_{d}.parquet" for d in dates if (work / f"joined_{d}.parquet").exists()]
    lst = json.dumps([str(x).replace("\\", "/") for x in parts])
    t0 = time.time()
    log(f"gộp {len(parts)} file ngày -> flows_joined.parquet (sắp theo hostname, ts, uid) ...")
    con.execute(f"""
      COPY (SELECT * FROM read_parquet({lst}) ORDER BY hostname, ts, uid)
      TO '{p(final)}.building' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 250000)
    """)
    Path(str(final) + ".building").replace(final)
    log(f"ghi xong ({time.time() - t0:.0f}s), {final.stat().st_size / 1e9:.2f} GB")
    f = p(final)
    # --- kiểm tra
    ck = {}
    r = con.execute(f"SELECT count(*), count(distinct uid), count(distinct hostname), sum((hostname IS NULL)::INT), min(ts), max(ts), sum(label), "
                    f"sum((label NOT IN (0,1) OR label IS NULL)::INT), sum((app_family IS NULL OR app_family='')::INT) FROM read_parquet('{f}')").fetchone()
    keys = ["rows", "distinct_uid", "hosts", "null_hostname", "ts_min", "ts_max", "positive_flows", "bad_label", "empty_app_family"]
    for k, v in zip(keys, r):
        ck[k] = v if k in ("ts_min", "ts_max") else int(v or 0)
    ck["rows_by_date_utc"] = {k: int(v) for k, v in con.execute(f"SELECT date_utc, count(*) FROM read_parquet('{f}') GROUP BY 1 ORDER BY 1").fetchall()}
    ck["positive_by_date_utc"] = {k: int(v) for k, v in con.execute(f"SELECT date_utc, sum(label) FROM read_parquet('{f}') GROUP BY 1 ORDER BY 1").fetchall()}
    ck["top_app_family"] = {k: int(v) for k, v in con.execute(f"SELECT app_family, count(*) FROM read_parquet('{f}') GROUP BY 1 ORDER BY 2 DESC LIMIT 8").fetchall()}
    ck["ecar"] = ecar_stats
    ck["days"] = day_stats
    ck["PASS"] = bool(ck["rows"] == ck["distinct_uid"] and ck["null_hostname"] == 0 and ck["bad_label"] == 0 and ck["rows"] > 0)
    # --- audit không ghép
    ip = con.execute(f"SELECT orig_h, any_value(hostname) AS hostname FROM read_parquet('{f}') GROUP BY orig_h HAVING count(distinct hostname)=1").fetchall()
    con.execute("CREATE OR REPLACE TEMP TABLE ipmap(orig_h VARCHAR, hostname VARCHAR)")
    con.executemany("INSERT INTO ipmap VALUES (?, ?)", ip)
    cnt = p(work) + "/counts_*.parquet"
    con.execute(f"""
      COPY (
        SELECT COALESCE(m.hostname, '(IP không có trong bảng ghép)') AS hostname_by_ip, c.orig_h, c.bro_dir_date, c.bro_rows, c.matched_rows, c.unmatched_rows, c.unmatched_positive_rows
        FROM read_parquet('{cnt}') c LEFT JOIN ipmap m USING (orig_h)
        WHERE c.unmatched_rows > 0 AND m.hostname IS NOT NULL
        ORDER BY hostname_by_ip, c.bro_dir_date
      ) TO '{p(out)}/unmatched_counts_by_host_date.csv' (FORMAT CSV, HEADER)
    """)
    un = p(work) + "/unmatched_pos_*.parquet"
    con.execute(f"""
      COPY (
        SELECT u.uid, u.ts, u.ts_utc, u.bro_dir_date, u.orig_h, u.orig_p, u.resp_h, u.resp_p, u.proto, u.service, u.conn_state, u.orig_bytes, u.resp_bytes, u.label,
               mo.hostname AS hostname_by_orig_ip, mr.hostname AS hostname_by_resp_ip, 'không có bản ghi eCAR-Bro cho uid này' AS reason
        FROM read_parquet('{un}') u LEFT JOIN ipmap mo ON u.orig_h = mo.orig_h LEFT JOIN ipmap mr ON u.resp_h = mr.orig_h
        ORDER BY u.ts
      ) TO '{p(out)}/unmatched_flows_audit.csv' (FORMAT CSV, HEADER)
    """)
    ck["unmatched_positive_flows"] = int(con.execute(f"SELECT count(*) FROM read_parquet('{un}')").fetchone()[0])
    ck["unmatched_positive_by_host"] = {str(k): int(v) for k, v in con.execute(
        f"SELECT COALESCE(mo.hostname, mr.hostname, '(không suy ra được)'), count(*) FROM read_parquet('{un}') u LEFT JOIN ipmap mo ON u.orig_h=mo.orig_h "
        f"LEFT JOIN ipmap mr ON u.resp_h=mr.orig_h GROUP BY 1 ORDER BY 2 DESC LIMIT 15").fetchall()}
    # --- preview và schema
    sc = {}
    try:
        for row in csv.DictReader(open(ROOT / "02_artifacts/11_dataset_overview_v1/scenario_hosts_29.csv", encoding="utf-8-sig")):
            sc[row["hostname"]] = row["scenario"]
    except Exception:
        pass
    rows = []
    for s in ("scenario_1", "scenario_2", "scenario_3"):
        hs = [h for h, v in sc.items() if v == s]
        if hs:
            ph = ",".join(f"'{h}'" for h in hs)
            rows += con.execute(f"SELECT * FROM (SELECT * FROM read_parquet('{f}') WHERE label=1 AND hostname IN ({ph})) USING SAMPLE 40 ROWS (reservoir, 7)").fetchall()
    rows += con.execute(f"SELECT * FROM (SELECT * FROM read_parquet('{f}') WHERE label=0) USING SAMPLE 100 ROWS (reservoir, 7)").fetchall()
    names = [d[0] for d in con.description]
    with open(out / "preview.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(names)
        w.writerows(rows)
    pos = next((r for r in rows if r[names.index("label")] == 1), None)
    ben = next((r for r in rows if r[names.index("label")] == 0), None)
    rec = {"flow_tan_cong_label1": dict(zip(names, pos)) if pos else None, "flow_binh_thuong_label0": dict(zip(names, ben)) if ben else None}
    json.dump(rec, open(out / "preview_record.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    sch = []
    ex = rec["flow_tan_cong_label1"] or {}
    for n, t, role, src, mean in SCHEMA:
        sch.append({"field": n, "type": t, "role": role, "source": src, "meaning_vi": mean, "example": ex.get(n)})
    json.dump({"table": "flows_joined.parquet", "grain": "1 dòng = 1 flow (uid duy nhất)", "n_fields": len(sch), "fields": sch}, open(out / "schema.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    json.dump(ck, open(out / "checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    log(f"checks: PASS={ck['PASS']} rows={ck['rows']:,} positive={ck['positive_flows']:,} hosts={ck['hosts']}")
    return ck


def compare_old(con, work, date):
    """Chỉ dùng khi chạy thử: so tập uid của ngày thư mục Bro với parquet cũ (02_network_joined_v1)."""
    new = p(work / f"joined_{date}.parquet")
    old = p(ROOT / "02_artifacts/02_network_joined_v1/joined") + f"/split=*/date={date}/*.parquet"
    r = con.execute(f"""
      WITH n AS (SELECT uid, label, hostname FROM read_parquet('{new}')),
           o AS (SELECT uid, label, hostname FROM read_parquet('{old}', hive_partitioning=false))
      SELECT (SELECT count(*) FROM n), (SELECT count(*) FROM o), (SELECT count(*) FROM n JOIN o USING (uid)),
             (SELECT count(*) FROM n ANTI JOIN o USING (uid)), (SELECT count(*) FROM o ANTI JOIN n USING (uid)),
             (SELECT sum(label) FROM n), (SELECT sum(label) FROM o),
             (SELECT count(*) FROM n JOIN o USING (uid) WHERE n.hostname <> o.hostname OR n.label <> o.label)
    """).fetchone()
    res = dict(zip(["new_rows", "old_rows", "in_both", "only_new", "only_old", "new_positive", "old_positive", "mismatch_host_or_label"], [int(x) if x is not None else None for x in r]))
    log(f"so với parquet cũ ({date}): {res}")
    return res


def main():
    global LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--dates", default="all", help="'all' (17-25/9) hoặc danh sách YYYY-MM-DD cách nhau dấu phẩy")
    ap.add_argument("--out", default=str(ROOT / "02_artifacts/22_v2_pipeline/S1_join"))
    ap.add_argument("--work", default=str(ROOT / "02_artifacts/22_v2_pipeline/_work"))
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--memory", default="20GB")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--compare-old", action="store_true")
    a = ap.parse_args()
    dates = DEFAULT_DATES if a.dates == "all" else a.dates.split(",")
    out, work = Path(a.out), Path(a.work)
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    LOG = open(out / "run_log.txt", "a", encoding="utf-8")
    log(f"S1 bắt đầu: ngày={dates}, out={out}")
    con = connect(a.threads, a.memory, work / "duck_tmp")
    ecar, ecar_stats = stage_ecar(con, work, a.force)
    day_stats = []
    for d in dates:
        s = stage_day(con, d, ecar, work, a.force)
        if s:
            day_stats.append(s)
        if a.compare_old and (work / f"joined_{d}.parquet").exists():
            compare_old(con, work, d)
    stage_final(con, work, out, dates, ecar_stats, day_stats)
    log("S1 xong")


if __name__ == "__main__":
    main()
