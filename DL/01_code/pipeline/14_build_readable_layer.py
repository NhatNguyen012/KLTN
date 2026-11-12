#!/usr/bin/env python3
"""STEP 14 - lớp "đọc được" cho pipeline OpTC: mỗi bước có CSV/JSON mẫu với tên trường rõ ràng.
Không sửa artifact/shard cũ. Chạy từng stage:  python 14_build_readable_layer.py --stage S0 S1 S2 S3
"""
import argparse
import csv
import datetime as dt
import glob
import gzip
import json
import os
import shutil

import duckdb
import orjson
import pandas as pd

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/14_readable_pipeline_v1"
JOINED = R + "/02_artifacts/02_network_joined_v1/joined/split=*/date=*/*.parquet"
SCHEMA = R + "/01_code/pipeline/network_event_schema_v1.json"


def wjson(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def wcsv(path, rows, header):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


# ----------------------------------------------------------------------------- S0
ECAR_FIELDS = [
    ("top", "timestamp", "mọi event", "string (ISO 8601)", "Thời điểm event xảy ra, giờ EDT (UTC−4). Ví dụ 2019-09-24T13:58:59.137-04:00"),
    ("top", "id", "mọi event", "string (UUID)", "Mã duy nhất của event"),
    ("top", "hostname", "mọi event", "string", "Máy sinh ra event, dạng SysClient0005.systemia.com"),
    ("top", "object", "mọi event", "string", "Loại đối tượng bị tác động: PROCESS, FILE, FLOW, MODULE, REGISTRY, THREAD, TASK, USER_SESSION, SHELL, SERVICE"),
    ("top", "action", "mọi event", "string", "Hành động trên đối tượng: CREATE, READ, WRITE, START, MESSAGE, LOAD, EDIT, REMOTE_CREATE, ..."),
    ("top", "actorID", "mọi event", "string (UUID)", "Mã tiến trình thực hiện hành động (khóa để lần theo process)"),
    ("top", "objectID", "mọi event", "string (UUID)", "Mã đối tượng bị tác động (file, process đích, flow...)"),
    ("top", "pid", "mọi event", "int", "Process ID của tiến trình thực hiện"),
    ("top", "ppid", "mọi event", "int", "Process ID của tiến trình cha"),
    ("top", "tid", "mọi event", "int", "Thread ID; −1 nếu không có"),
    ("top", "principal", "mọi event", "string", "Tài khoản người dùng chạy tiến trình, ví dụ SYSTEMIACOM\\sysadmin"),
    ("top", "label", "bản corrected (host-begnin, host-malicious)", "int 0/1", "Nhãn do A New Hope gán: 1 nếu event do tiến trình độc hại hoặc tiến trình con của nó tạo ra"),
    ("properties", "acuity_level", "mọi event", "string", "Mức quan trọng của event (1–5) do nền tảng thu thập gán"),
    ("properties", "image_path", "đa số object", "string", "Đường dẫn file thực thi của tiến trình thực hiện"),
    ("properties", "parent_image_path", "PROCESS", "string", "Đường dẫn file thực thi của tiến trình cha"),
    ("properties", "command_line", "PROCESS", "string", "Dòng lệnh dùng để chạy tiến trình"),
    ("properties", "user", "PROCESS, USER_SESSION", "string", "Tài khoản liên quan"),
    ("properties", "sid", "PROCESS", "string", "Security ID của tài khoản"),
    ("properties", "file_path", "FILE", "string", "Đường dẫn file bị đọc/ghi/tạo/xóa"),
    ("properties", "new_path", "FILE RENAME", "string", "Đường dẫn mới sau khi đổi tên"),
    ("properties", "size", "FILE READ/WRITE, FLOW MESSAGE", "string (số)", "Số byte đọc/ghi hoặc số byte của thông điệp mạng"),
    ("properties", "info_class", "FILE MODIFY/DELETE", "string", "Loại thông tin file bị sửa"),
    ("properties", "key", "REGISTRY", "string", "Đường dẫn khóa registry"),
    ("properties", "value", "REGISTRY", "string", "Tên giá trị trong khóa registry"),
    ("properties", "data", "REGISTRY", "string", "Dữ liệu mới ghi vào giá trị registry"),
    ("properties", "type", "REGISTRY", "string", "Kiểu dữ liệu registry (REG_SZ...)"),
    ("properties", "src_ip", "FLOW, USER_SESSION REMOTE", "string", "IP nguồn"),
    ("properties", "src_port", "FLOW, USER_SESSION REMOTE", "string (số)", "Cổng nguồn"),
    ("properties", "dest_ip", "FLOW", "string", "IP đích"),
    ("properties", "dest_port", "FLOW", "string (số)", "Cổng đích"),
    ("properties", "direction", "FLOW", "string", "Hướng kết nối: inbound hoặc outbound"),
    ("properties", "l4protocol", "FLOW", "string", "Giao thức tầng 4: 6 = TCP, 17 = UDP"),
    ("properties", "start_time / end_time", "FLOW MESSAGE", "string", "Thời điểm bắt đầu/kết thúc của thông điệp (nếu có)"),
    ("properties", "module_path", "MODULE LOAD", "string", "Đường dẫn DLL được nạp"),
    ("properties", "base_address", "MODULE LOAD", "string", "Địa chỉ nạp module"),
    ("properties", "src_pid / src_tid", "THREAD", "string (số)", "Process/thread tạo ra thread"),
    ("properties", "tgt_pid / tgt_tid", "THREAD", "string (số)", "Process/thread đích (REMOTE_CREATE: process bị chèn thread)"),
    ("properties", "start_address / stack_base / stack_limit / user_stack_base / user_stack_limit / subprocess_tag", "THREAD", "string", "Thông số kỹ thuật của thread"),
    ("properties", "task_name / task_pid / task_process_uuid / user_name / path", "TASK", "string", "Thông tin tác vụ Windows Task Scheduler"),
    ("properties", "logon_id / privileges / requesting_user / requesting_domain / requesting_logon_id", "USER_SESSION", "string", "Thông tin phiên đăng nhập"),
    ("properties", "bro_uid", "FLOW INFO (eCAR-Bro)", "string", "Mã kết nối Bro; khóa nối với Bro conn.uid"),
]
BRO_FIELDS = [
    ("ts", "time", "Thời điểm bắt đầu kết nối, epoch UTC (giây)"),
    ("uid", "string", "Mã kết nối duy nhất; khóa nối với eCAR-Bro (bro_uid)"),
    ("id.orig_h", "addr", "IP máy khởi tạo kết nối"),
    ("id.orig_p", "port", "Cổng máy khởi tạo"),
    ("id.resp_h", "addr", "IP máy nhận"),
    ("id.resp_p", "port", "Cổng máy nhận"),
    ("proto", "enum", "Giao thức: tcp, udp, icmp"),
    ("service", "string", "Dịch vụ Zeek nhận diện: ssl, http, dns... ('-' nếu không nhận ra)"),
    ("duration", "interval", "Thời lượng kết nối (giây)"),
    ("orig_bytes", "count", "Số byte ứng dụng máy khởi tạo gửi"),
    ("resp_bytes", "count", "Số byte ứng dụng máy nhận gửi"),
    ("conn_state", "string", "Trạng thái kết thúc: SF (bình thường), S0 (không trả lời), REJ (bị từ chối), RSTO, ..."),
    ("local_orig", "bool", "Máy khởi tạo thuộc mạng nội bộ"),
    ("local_resp", "bool", "Máy nhận thuộc mạng nội bộ"),
    ("missed_bytes", "count", "Số byte bị mất gói trong lúc bắt"),
    ("history", "string", "Chuỗi cờ TCP theo thời gian (S, H, A, D, F, R...)"),
    ("orig_pkts", "count", "Số gói máy khởi tạo gửi"),
    ("orig_ip_bytes", "count", "Số byte tầng IP máy khởi tạo gửi"),
    ("resp_pkts", "count", "Số gói máy nhận gửi"),
    ("resp_ip_bytes", "count", "Số byte tầng IP máy nhận gửi"),
    ("tunnel_parents", "set[string]", "Danh sách kết nối đường hầm cha ('(empty)' nếu không có)"),
    ("label", "int", "Nhãn 0/1 của bản OpTC đã gán nhãn (1 = kết nối độc hại)"),
]
SAMPLE_KEYS = [("PROCESS", "CREATE"), ("FLOW", "START"), ("FLOW", "MESSAGE"), ("FILE", "READ"), ("FILE", "WRITE"),
               ("MODULE", "LOAD"), ("REGISTRY", "EDIT"), ("THREAD", "REMOTE_CREATE"), ("USER_SESSION", "LOGIN")]


def stage_S0():
    d = OUT + "/S0_raw_schema"
    p = glob.glob("E:/host-malicious/2019-09-24/*/*ecar-2019-09-24-sysclient0618.json.gz")[0]
    first, n = {}, 0
    with gzip.open(p, "rb") as f:
        for line in f:
            e = orjson.loads(line)
            n += 1
            k = (e["object"], e["action"])
            if k in SAMPLE_KEYS and k not in first:
                first[k] = e
            if len(first) == len(SAMPLE_KEYS) or n > 1500000:
                break
    wjson(d + "/sample_ecar_events.json", {f"{o}_{a}": first[(o, a)] for o, a in SAMPLE_KEYS if (o, a) in first})
    for q in sorted(glob.glob("E:/ecar-bro/evaluation/24Sep19/*/ecarbro.json.gz")):
        with gzip.open(q, "rt", encoding="utf-8") as f:
            line = f.readline()
        if line.strip():
            wjson(d + "/sample_ecar_bro_record.json", json.loads(line))
            break
    c = sorted(glob.glob("E:/bro/2019-09-24/conn.*.log.gz"))[5]
    with gzip.open(c, "rt", encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f]
    fields = next(l for l in lines if l.startswith("#fields")).split("\t")[1:]
    vals = next(l for l in lines if not l.startswith("#")).split("\t")
    conn = dict(zip(fields, vals))
    wjson(d + "/sample_bro_conn_record.json", conn)
    ex_e = {}
    for e in first.values():
        for kk, vv in e.items():
            if kk != "properties":
                ex_e.setdefault(("top", kk), vv)
        for kk, vv in (e.get("properties") or {}).items():
            ex_e.setdefault(("properties", kk), vv)
    rows = []
    for lvl, name, applies, dtype, meaning in ECAR_FIELDS:
        ex = ex_e.get((lvl, name.split(" / ")[0]), "")
        rows.append([lvl, name, applies, dtype, meaning, ex if not isinstance(ex, (dict, list)) else json.dumps(ex)])
    wcsv(d + "/fields_ecar_event.csv", rows, ["level", "field", "applies_to", "type", "meaning_vi", "example"])
    wcsv(d + "/fields_bro_conn.csv", [[n_, t, m, conn.get(n_, "")] for n_, t, m in BRO_FIELDS],
         ["field", "zeek_type", "meaning_vi", "example"])
    print("S0 ok", len(first), "eCAR samples")


# ----------------------------------------------------------------------------- S1
def stage_S1():
    d = OUT + "/S1_network_flows"
    os.makedirs(d, exist_ok=True)
    sch = json.load(open(SCHEMA, encoding="utf-8"))
    rows = [[f["name"], f["role"], f["dtype"], f["source"], f.get("derived_from", ""), f["meaning_vi"], f["example"], f.get("notes", "")]
            for f in sch["fields"]]
    wcsv(d + "/fields_flow.csv", rows, ["field", "role", "type", "source", "derived_from", "meaning_vi", "example", "notes"])
    con = duckdb.connect()
    base = f"read_parquet('{JOINED}', hive_partitioning=true)"
    con.execute(f"CREATE VIEW j AS SELECT * EXCLUDE (split) , split AS split_step02_original FROM {base}")
    ov = con.execute("""SELECT CAST(date AS VARCHAR) AS date_utc, split_step02_original, count(*) AS n_flows,
        sum(label) AS n_attack_flows, count(DISTINCT hostname) AS n_hosts FROM j GROUP BY 1,2 ORDER BY 1,2""").fetchdf()
    ov.to_csv(d + "/flows_overview_by_date_split.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    tot = con.execute("select count(*), sum(label), count(distinct hostname) from j").fetchone()
    print("joined totals", tot)
    cols = "uid, strftime(make_timestamp(CAST(round(ts * 1000000) AS BIGINT)), '%Y-%m-%d %H:%M:%S.%f') AS ts_utc, ts, hostname, label, app_family, direction, " \
           "ecar_l4protocol, orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, " \
           "local_orig, local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, " \
           "ecar_occurrence_count, CAST(date AS VARCHAR) AS date_utc, split_step02_original"
    pos = con.execute(f"SELECT * FROM (SELECT {cols} FROM j WHERE label=1) USING SAMPLE 1000 ROWS (reservoir, 42)").fetchdf()
    neg = con.execute(f"SELECT * FROM (SELECT {cols} FROM j WHERE label=0) USING SAMPLE 1000 ROWS (reservoir, 42)").fetchdf()
    print("sample sizes pos/neg", len(pos), len(neg))
    s = pd.concat([pos, neg]).sort_values(["label", "ts"], ascending=[False, True])
    s.to_csv(d + "/flows_sample.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    ex_pos = con.execute(f"SELECT {cols} FROM j WHERE hostname='sysclient0618' AND label=1 AND ts>=1569355200 ORDER BY ts LIMIT 1").fetchdf()
    ex_neg = con.execute(f"SELECT {cols} FROM j WHERE label=0 AND app_family='firefox.exe' AND service='http' ORDER BY ts LIMIT 1").fetchdf()
    wjson(d + "/sample_flow.json", {"flow_tan_cong_beacon": json.loads(ex_pos.iloc[0].to_json()),
                                    "flow_binh_thuong": json.loads(ex_neg.iloc[0].to_json())})
    print("S1 ok")


# ----------------------------------------------------------------------------- S2
TACTICS = [
    ("IA", "Initial Access", "TA0001", "Truy cập ban đầu: cách kẻ tấn công vào được máy đầu tiên (phishing, cập nhật giả mạo)"),
    ("EX", "Execution", "TA0002", "Thực thi mã độc trên máy nạn nhân"),
    ("PE", "Persistence", "TA0003", "Duy trì hiện diện: registry Run, WMI subscription, tài khoản mới"),
    ("PR", "Privilege Escalation", "TA0004", "Leo thang đặc quyền: bypass UAC, getsystem, migrate vào LSASS"),
    ("DE", "Defense Evasion", "TA0005", "Né tránh phòng thủ: timestomp, dọn dẹp dấu vết, chèn process"),
    ("CA", "Credential Access", "TA0006", "Lấy thông tin xác thực: Mimikatz, lsadump"),
    ("DI", "Discovery", "TA0007", "Dò thám: quét ARP, ping sweep, liệt kê domain, share"),
    ("LM", "Lateral Movement", "TA0008", "Di chuyển ngang sang máy khác: WMI, RDP"),
    ("CO", "Collection", "TA0009", "Thu thập dữ liệu: nén tài liệu, chụp màn hình"),
    ("C2", "Command and Control", "TA0011", "Điều khiển từ xa: beacon, tải công cụ"),
    ("EXF", "Exfiltration", "TA0010", "Đánh cắp dữ liệu ra ngoài"),
]
LABEL_RULES = [
    ["Network (flow)", "A New Hope + pipeline STEP 02", "Flow nối tới IP/domain của máy điều khiển (C2) của từng scenario, trong khung giờ tấn công, được kiểm tra tay qua từng uid", "label = 1 nếu là kết nối C2, ngược lại 0", "Bro không ghi traffic nội bộ nên không có nhãn cho di chuyển ngang"],
    ["Host (event eCAR)", "A New Hope (bản corrected)", "Event do tiến trình độc hại (pid trong file red team) hoặc tiến trình con của nó tạo ra", "label = 1 cho mọi event của process đó trong khoảng thời gian sống", "Nhãn theo process, không theo từng hành vi; event vô hại của process bị chiếm cũng bị gán 1"],
    ["Window (host, 15 phút), nhị phân", "pipeline STEP 04B/10C", "Window được gán 1 nếu chứa ít nhất một flow có label = 1", "sample_labels trong shard; window_labels_multilabel.csv có cột n_net_pos_flows", "Window là đơn vị mà model nhìn thấy"],
    ["Window, đa nhãn (multi-label)", "STEP 12B (đề xuất của nhóm)", "Mỗi bước trong nhật ký red team ghi tactic ATT&CK; cửa sổ giao với [t−60s, t+300s] của bước nhận tactic đó; cửa sổ có flow độc hại được thêm C2", "11 cột 0/1 (IA, EX, PE, PR, DE, CA, DI, LM, CO, C2, EXF)", "Ánh xạ bước → tactic là đề xuất, chưa được thẩm định; chỉ 90 cửa sổ có tactic ngoài C2"],
]


def stage_S2():
    d = OUT + "/S2_labels"
    gt = "D:/UIT/KLTN/KLTN-main/a_new_hope_for_darpa_optc/labelling"
    rows = []
    for sc in (1, 2, 3):
        for r in csv.reader(open(f"{gt}/host/ground_truths/ground_truth_corrected_sc{sc}_updated.csv", encoding="utf-8")):
            rows.append([f"SC{sc}", r[0].lower(), r[1], r[2], r[3]])
    wcsv(d + "/host_malicious_processes.csv", rows, ["scenario", "hostname", "pid", "start_edt", "end_edt"])
    agg = {}
    for p in sorted(glob.glob(gt + "/network/scenario-*/conn-*.log")):
        sc = "SC" + os.path.basename(os.path.dirname(p)).split("-")[1]
        b = os.path.basename(p)[5:-4]
        host = "dc1" if b == "dc1" else "sysclient" + b.split("-")[1].zfill(4)
        for l in open(p, encoding="utf-8", errors="replace"):
            if l.startswith("#"):
                continue
            c = l.split("\t")
            if len(c) < 7:
                continue
            k = (sc, host, c[4], c[5], c[6])
            ts = float(c[0])
            a = agg.setdefault(k, [0, ts, ts])
            a[0] += 1
            a[1], a[2] = min(a[1], ts), max(a[2], ts)
    f = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    wcsv(d + "/network_malicious_flows_summary.csv",
         [[*k, v[0], f(v[1]), f(v[2])] for k, v in sorted(agg.items())],
         ["scenario", "hostname", "resp_h", "resp_p", "proto", "n_flows", "first_ts_utc", "last_ts_utc"])
    wcsv(d + "/label_rules.csv", LABEL_RULES, ["mức_độ", "nguồn_nhãn", "quy_tắc", "đầu_ra", "hạn_chế"])
    wcsv(d + "/tactic_definitions.csv", [[a, b, c, e] for a, b, c, e in TACTICS], ["mã_cột", "tactic", "attack_id", "ý_nghĩa"])
    src = R + "/02_artifacts/12b_multilabel_stage_v1/"
    shutil.copy(src + "window_labels_v1.csv", d + "/window_labels_multilabel.csv")
    shutil.copy(src + "stage_steps_v1.csv", d + "/stage_steps_red_team.csv")
    print("S2 ok")


# ----------------------------------------------------------------------------- S3
def stage_S3():
    d = OUT + "/S3_split"
    os.makedirs(d, exist_ok=True)
    h = pd.read_csv(R + "/02_artifacts/11_dataset_overview_v1/hosts_625.csv")
    base = h[["hostname", "group", "scenario", "in_network_dataset", "original_split_step02", "net_events", "net_positive_events",
              "gt_host_events"]].copy()
    base = base.rename(columns={"group": "host_group", "original_split_step02": "split_original", "net_events": "n_flows",
                                "net_positive_events": "n_attack_flows", "gt_host_events": "n_host_malicious_events"})
    sp = {}
    for k in (1, 2, 3):
        s = pd.read_csv(R + f"/02_artifacts/10a_random_split_v1/seed_{k}/host_split_frozen.csv")[["hostname", "assigned_split"]]
        sp[k] = s.set_index("hostname")["assigned_split"]
    for k in (1, 2, 3):
        base[f"split_random_seed{k}"] = base["hostname"].map(sp[k])
    extra = sorted(set(sp[1].index) - set(base["hostname"]))
    base["has_host_log"] = True
    if extra:
        e = pd.DataFrame({"hostname": extra, "has_host_log": False})
        for k in (1, 2, 3):
            e[f"split_random_seed{k}"] = e["hostname"].map(sp[k])
        base = pd.concat([base, e], ignore_index=True)
    base.to_csv(d + "/host_split_all.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    out = []
    for k in (1, 2, 3):
        c = f"split_random_seed{k}"
        for s_ in ("train", "val", "test"):
            x = base[base[c] == s_]
            out.append([f"seed_{k}", s_, len(x), int((x["n_attack_flows"].fillna(0) > 0).sum()),
                        int((x["scenario"] == "scenario_1").sum()), int((x["scenario"] == "scenario_2").sum()),
                        int((x["scenario"] == "scenario_3").sum()), int(x["has_host_log"].sum())])
    wcsv(d + "/split_summary.csv", out, ["seed", "split", "n_hosts", "n_hosts_with_attack_flows", "n_SC1_hosts", "n_SC2_hosts", "n_SC3_hosts", "n_hosts_with_host_log"])
    print("S3 ok", len(base), "hosts")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", nargs="+", required=True)
    a = ap.parse_args()
    for s in a.stage:
        globals()["stage_" + s]()
