#!/usr/bin/env python3
"""S19 - Xuất các dòng JSON để chụp bỏ vào slide: (1) một dòng raw mỗi dataset (THEIA, ATLASv2), (2) cùng dòng đó sau preprocessing bản B, (3) OpTC sau join đầy đủ và sau khi drop.

Dòng raw lấy NGUYÊN VĂN từ sample_*_raw.txt (đã lấy thẳng từ raw). Preprocessing dùng đúng quy tắc/ id của preprocess_spec.json của OpTC (v2).
Cách dùng: python s19_slide_records.py"""
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import duckdb

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("D:/UIT/KLTNv2")
SAMP = ROOT / "02_artifacts/37_new_dataset_raw_samples_v1"
OUT = ROOT / "02_artifacts/38_slide_records_v1"
SPEC = json.load(open(ROOT / "02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json", encoding="utf-8"))
VOCAB = {f: {e["value"]: e["id"] for e in SPEC["categorical"]["fields"][f]["vocab"]} for f in ("app_family", "proto", "resp_port_class", "image_dir_class")}
COMMON = SPEC["derived_rules"]["port_class"]["common_ports"]


# Từ điển MỞ RỘNG ngay từ đầu: token chưa có trong từ điển OpTC được nối thêm với id mới (id gốc không đổi).
# Id mới ở đây là minh họa (id thật theo thứ tự tần suất trên TRAIN của dữ liệu mới); id đầu tiên mới = số hàng embedding cũ (app_family 61, image_dir_class 10).
EXT = {"app_family": {"next": 61, "new": {}}, "image_dir_class": {"next": 10, "new": {}}}


def vid(field, value):
    if value is None:
        return 1  # <MISSING>
    if value in VOCAB[field]:
        return VOCAB[field][value]
    if field in EXT:
        e = EXT[field]
        if value not in e["new"]:
            e["new"][value] = e["next"]
            e["next"] += 1
        return e["new"][value]
    return 0  # <UNK>


def port_class(p):
    p = int(float(p))
    if str(p) in COMMON:
        return f"PORT_{p}_{COMMON[str(p)]}"
    if p <= 1023:
        return "WELL_KNOWN_OTHER"
    if p <= 49151:
        return "REGISTERED"
    if p <= 65535:
        return "EPHEMERAL"
    return "OTHER"


def image_dir_class(path):
    if not path:
        return "MISSING"
    if path.startswith("/"):  # đường dẫn Linux: các lớp MỚI (token mới nối vào từ điển)
        lp = path.lower()
        for prefixes, name in ((("/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/"), "SYSTEM_BIN"), (("/usr/lib/", "/lib/"), "SYSTEM_LIB"), (("/tmp/", "/var/tmp/"), "TEMP_LINUX"),
                               (("/var/log/",), "VAR_LOG"), (("/home/",), "HOME_USER"), (("/etc/", "/opt/"), "ETC_OPT")):
            if lp.startswith(prefixes):
                return name
        return "BARE_NAME" if lp.count("/") == 0 else "OTHER"
    q = path.lower().replace("/", "\\")
    if "\\" not in q:
        return "BARE_NAME"
    if "\\temp\\" in q or "\\appdata\\" in q:
        return "TEMP_OR_APPDATA"
    if "\\windows\\system32\\" in q or "\\windows\\syswow64\\" in q:
        return "SYSTEM32"
    if "\\windows\\" in q:
        return "WINDOWS_OTHER"
    if "\\program files" in q:
        return "PROGRAM_FILES"
    if "\\users\\" in q:
        return "USERS_OTHER"
    return "OTHER"


def basename(path):
    return re.split(r"[\\/]", path)[-1].lower()


def processed(dataset, host, ts, label, app, proto, port, path, delta):
    ac = image_dir_class(path)
    pc = port_class(port)
    return {"dataset": dataset, "hostname": host, "ts_utc": ts, "label": label,
            "app_family": app, "app_family_id": vid("app_family", app),
            "proto": proto, "proto_id": vid("proto", proto),
            "resp_port_class": pc, "resp_port_class_id": vid("resp_port_class", pc),
            "image_dir_class": ac, "image_dir_class_id": vid("image_dir_class", ac),
            "delta_t_log1p": delta}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # ---- THEIA: một dòng Event raw (CONNECT đầu tiên của mẫu attack 1) + 3 bản ghi liên quan
    T = (SAMP / "sample_THEIA_raw.txt").read_text(encoding="utf-8").splitlines()
    i0 = next(i for i, l in enumerate(T) if l.startswith("=== [attack] mẫu 1/3"))
    block = []
    for l in T[i0 + 1:]:
        if l.startswith("==="):
            break
        block.append(l)
    raw = [l for l in block if not l.startswith("#")]
    ev = next(l for l in raw if '.cdm18.Event"' in l and '"EVENT_CONNECT"' in l)
    subj = next(l for l in raw if '.cdm18.Subject"' in l)
    nf = next(l for l in raw if '.cdm18.NetFlowObject"' in l)
    pr = next(l for l in raw if '.cdm18.Principal"' in l)
    evd = json.loads(ev)["datum"]["com.bbn.tc.schema.avro.cdm18.Event"]
    sjd = json.loads(subj)["datum"]["com.bbn.tc.schema.avro.cdm18.Subject"]
    nfd = json.loads(nf)["datum"]["com.bbn.tc.schema.avro.cdm18.NetFlowObject"]
    assert evd["predicateObject"]["com.bbn.tc.schema.avro.cdm18.UUID"] == nfd["uuid"]
    t_ts = datetime.fromtimestamp(evd["timestampNanos"] / 1e9, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    theia_path = sjd["properties"]["map"]["path"]
    # Subject.properties.path là tên LÚC FORK (cha: fluxbox); tên chương trình thật nằm ở sự kiện EVENT_EXECUTE (properties.map.cmdLine). Xem s21_theia_exec_check.py.
    chk = OUT / "_theia_exec_check.json"
    theia_img, exec_lines = theia_path, []
    if chk.exists():
        exec_lines = json.load(open(chk, encoding="utf-8"))["execute_events"]
        exs = sorted(((json.loads(l)["datum"][next(iter(json.loads(l)["datum"]))]) for l in exec_lines), key=lambda e: e["timestampNanos"])
        exs = [e for e in exs if e["timestampNanos"] <= evd["timestampNanos"]]
        if exs:
            theia_img = exs[-1]["properties"]["map"]["cmdLine"].split()[0]
    theia_row = processed("THEIA", "ta1-theia (10.0.6.60)", t_ts, 1, basename(theia_img), None, nfd["remotePort"], theia_img, 0.0)
    theia_row["ghi_chu"] = "id >= 61 (app_family) và >= 10 (image_dir_class) là token MỚI nối vào từ điển lúc mở rộng; giá trị id minh họa"
    (OUT / "1c_THEIA_execute_event.jsonl").write_text("\n".join(exec_lines) + ("\n" if exec_lines else ""), encoding="utf-8", newline="")
    # ---- ATLASv2: một dòng netconn raw (hàng firefox.exe attack tới cổng 443, CREATE)
    A = (SAMP / "sample_ATLASv2_raw.txt").read_text(encoding="utf-8").splitlines()
    cand = [l for l in A if l.startswith('{"type":"endpoint.event.netconn"')]
    atl = next(l for l in cand if "firefox.exe" in json.loads(l)["process_path"] and json.loads(l)["remote_port"] == 443.0 and json.loads(l)["action"] == "ACTION_CONNECTION_CREATE" and json.loads(l)["process_guid"].endswith("1d89b88df46bd5c"))
    ad = json.loads(atl)
    a_ts = ad["device_timestamp"].replace(" +0000 UTC", "")[:23]
    atlas_row = processed("ATLASv2", ad["device_name"], a_ts, 1, basename(ad["process_path"]), {"PROTO_TCP": "tcp", "PROTO_UDP": "udp"}[ad["netconn_protocol"]], ad["remote_port"], ad["process_path"], 0.0)
    (OUT / "1_raw_2dong_THEIA_ATLASv2.jsonl").write_text(ev + "\n" + atl + "\n", encoding="utf-8", newline="")
    (OUT / "1b_THEIA_ban_ghi_lien_quan.jsonl").write_text("\n".join([subj, pr, nf, ev]) + "\n", encoding="utf-8", newline="")
    (OUT / "2_sau_preprocess_2dong_THEIA_ATLASv2.jsonl").write_text(json.dumps(theia_row, ensure_ascii=False) + "\n" + json.dumps(atlas_row, ensure_ascii=False) + "\n", encoding="utf-8", newline="")
    # ---- OpTC: dòng sau join đầy đủ (verbatim preview_record.json) và sau drop (bản B, delta_t thật từ flows_joined)
    rec = json.load(open(ROOT / "02_artifacts/22_v2_pipeline/S1_join/preview_record.json", encoding="utf-8"))["flow_tan_cong_label1"]
    con = duckdb.connect()
    q = f"""select uid, ts from read_parquet('{(ROOT / '02_artifacts/22_v2_pipeline/S1_join/data/flows_joined.parquet').as_posix()}')
            where hostname = ? and window_start_epoch = ? order by ts, uid"""
    rows = con.execute(q, [rec["hostname"], rec["window_start_epoch"]]).fetchall()
    idx = next(i for i, r in enumerate(rows) if r[0] == rec["uid"])
    first_in_chunk = idx % 512 == 0
    delta = 0.0 if first_in_chunk else math.log1p(max(0.0, rows[idx][1] - rows[idx - 1][1]))
    optc_row = processed("OpTC", rec["hostname"], rec["ts_utc"][:23], rec["label"], rec["app_family"], rec["proto"], rec["resp_p"], rec["image_path"], round(delta, 6))
    (OUT / "3_optc_join_day_du_va_sau_drop.jsonl").write_text(json.dumps(rec, ensure_ascii=False) + "\n" + json.dumps(optc_row, ensure_ascii=False) + "\n", encoding="utf-8", newline="")
    print(json.dumps({"theia": theia_row, "atlas": atlas_row, "optc": optc_row, "optc_window_rows": len(rows), "optc_idx": idx}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
