#!/usr/bin/env python3
"""STEP 14 (phần 3) - S6: nhánh host; S8: Unraveled; S9: bảng đầu vào fusion. Chỉ đọc artifact cũ, ghi vào 14_readable_pipeline_v1.
Chạy: python 14c_readable_host_unraveled_fusion.py --stage S6 S8 S9
"""
import argparse
import csv
import datetime as dt
import glob
import gzip
import json
import os

import pandas as pd

R = "D:/UIT/KLTNv2"
OUT = R + "/02_artifacts/14_readable_pipeline_v1"
F12C = R + "/02_artifacts/12c_host_features_v1"


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


def to_epoch(win_edt):
    t = pd.to_datetime(win_edt) + pd.Timedelta(hours=4)
    return ((t - pd.Timestamp("1970-01-01")).dt.total_seconds()).astype("int64")


HOST_FIELDS = [
    ("hostname", "Tên máy, ví dụ sysclient0051"),
    ("day", "Ngày của file log host (EDT)"),
    ("window_start_edt", "Thời điểm bắt đầu cửa sổ 15 phút, giờ EDT (UTC−4)"),
    ("window_start_utc", "Thời điểm bắt đầu cửa sổ 15 phút, giờ UTC (khớp với cửa sổ của nhánh network)"),
    ("split_seed1", "Tập của host này trong split ngẫu nhiên seed_1: train, val hoặc test"),
    ("n_events", "Tổng số event eCAR của máy trong cửa sổ"),
    ("n_flow_start", "Số event FLOW START (kết nối mạng mới mở)"),
    ("n_proc_create", "Số event PROCESS CREATE (tiến trình mới)"),
    ("n_proc_writable", "Số tiến trình mới có file thực thi nằm trong thư mục ghi được (Temp, AppData, ProgramData)"),
    ("n_parent_lsass", "Số tiến trình mới có cha là lsass.exe"),
    ("n_remote_thread", "Số event THREAD REMOTE_CREATE (chèn thread vào process khác)"),
    ("n_reg_persist", "Số event ghi registry ở khóa Run, Services hoặc SAM"),
    ("n_exec_drop", "Số event tạo/ghi/đổi tên file thực thi (.exe, .dll, .vbs, .bat, .ps1...) trong thư mục ghi được"),
    ("n_cmd_susp", "Số tiến trình mới có dòng lệnh đáng ngờ (net user, /add, wmic, encodedcommand, mimikatz...)"),
    ("n_host_mal_events", "Số event được A New Hope gán nhãn độc hại trong cửa sổ (0 nếu máy không bị tấn công)"),
]


def stage_S6():
    d = OUT + "/S6_host_branch"
    os.makedirs(d, exist_ok=True)
    scan = pd.read_csv(F12C + "/scan_list.csv").drop_duplicates(["host", "day"]).set_index(["host", "day"])["split"]
    parts = []
    for f in glob.glob(F12C + "/features/*.csv"):
        parts.append(pd.read_csv(f).drop(columns=["pairs_json"]))
    x = pd.concat(parts, ignore_index=True)
    x["split_seed1"] = [scan.get((h, dy)) for h, dy in zip(x["host"], x["day"])]
    x["win_epoch"] = to_epoch(x["win_edt"])
    x["window_start_utc"] = pd.to_datetime(x["win_epoch"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
    lab = pd.read_csv(R + "/02_artifacts/12b_multilabel_stage_v1/window_labels_v1.csv")
    lab["win_epoch"] = ((pd.to_datetime(lab["window_start_utc"]) - pd.Timestamp("1970-01-01")).dt.total_seconds()).astype("int64")
    x = x.merge(lab[["host", "win_epoch", "n_host_mal_events"]], on=["host", "win_epoch"], how="left")
    x["n_host_mal_events"] = x["n_host_mal_events"].fillna(0).astype(int)
    x = x.rename(columns={"host": "hostname", "win_edt": "window_start_edt", "n_flow": "n_flow_start"})
    cols = [c for c, _ in HOST_FIELDS]
    x = x.sort_values(["hostname", "window_start_utc"])[cols]
    x.to_csv(d + "/host_window_features.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    wcsv(d + "/fields_host_window.csv", [[a, b] for a, b in HOST_FIELDS], ["field", "meaning_vi"])
    s0051 = x[(x.hostname == "sysclient0051") & (x.window_start_edt == "2019-09-25 10:45")].iloc[0]
    b0051 = x[(x.split_seed1 == "train") & (x.window_start_edt == "2019-09-22 10:45") & (x.n_host_mal_events == 0)]
    wjson(d + "/sample_host_window.json", {
        "cua_so_tan_cong_SC3": json.loads(s0051.to_json()),
        "cua_so_binh_thuong_cung_gio_ngay_22_9_host_TRAIN_khac": json.loads(b0051.iloc[0].to_json()) if len(b0051) else None})
    gt = "D:/UIT/KLTN/KLTN-main/a_new_hope_for_darpa_optc/labelling/host/ground_truths/ground_truth_corrected_sc3_evts_sysclient0051.json.gz"
    ex = {}
    for line in gzip.open(gt, "rt", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        pr = e.get("properties", {})
        k = None
        if e["object"] == "PROCESS" and e["action"] == "CREATE":
            if "cKfGW.exe" in pr.get("image_path", ""):
                k = "PROCESS_CREATE_dropper_tu_notepad_updater"
            elif pr.get("parent_image_path", "").lower().endswith("lsass.exe") and "net user" in pr.get("command_line", ""):
                k = "PROCESS_CREATE_net_user_cha_la_lsass"
        elif e["object"] == "REGISTRY" and e["action"] == "ADD" and "\\Run\\" in pr.get("key", ""):
            k = "REGISTRY_ADD_khoa_Run_persistence"
        elif e["object"] == "THREAD" and e["action"] == "REMOTE_CREATE":
            k = "THREAD_REMOTE_CREATE"
        if k and k not in ex:
            ex[k] = e
    wjson(d + "/sample_host_malicious_events.json", ex)
    print("S6 ok", len(x), "host windows;", len(ex), "event samples")


def stage_S8():
    d = OUT + "/S8_unraveled"
    os.makedirs(d, exist_ok=True)
    f = glob.glob(R + "/03_datasets/unraveled_v1_clean/network-flows/*/net1011x_Flow_labeled.csv")[0]
    cols = list(pd.read_csv(f, nrows=0).columns)

    def grp(c):
        if c.startswith(("bidirectional_",)):
            return "hai chiều (bidirectional)"
        if c.startswith("src2dst_"):
            return "chiều nguồn → đích"
        if c.startswith("dst2src_"):
            return "chiều đích → nguồn"
        if c in ("id", "expiration_id", "src_ip", "src_mac", "src_oui", "src_port", "dst_ip", "dst_mac", "dst_oui", "dst_port",
                 "protocol", "ip_version", "vlan_id", "tunnel_id"):
            return "định danh luồng"
        if c.startswith(("application", "requested", "client_", "server_", "user_agent", "content_type")):
            return "tầng ứng dụng (nDPI)"
        if c in ("Activity", "Stage", "DefenderResponse", "Signature"):
            return "NHÃN"
        return "khác"

    meaning = {
        "id": "Số thứ tự luồng", "expiration_id": "Lý do NFStream kết thúc luồng", "src_ip": "IP nguồn", "dst_ip": "IP đích",
        "src_port": "Cổng nguồn", "dst_port": "Cổng đích", "protocol": "Số giao thức IP (6 = TCP, 17 = UDP)",
        "application_name": "Ứng dụng nDPI nhận diện (TLS, DNS, SSH, HTTP...)", "application_category_name": "Nhóm ứng dụng nDPI",
        "requested_server_name": "Tên máy chủ yêu cầu (SNI/Host)", "client_fingerprint": "Dấu vân tay client (JA3 hoặc danh sách option DHCP)",
        "server_fingerprint": "Dấu vân tay server", "user_agent": "Chuỗi User-Agent", "content_type": "Loại nội dung HTTP",
        "Activity": "Kỹ thuật MITRE ATT&CK của kẻ tấn công ('Normal' nếu bình thường)",
        "Stage": "Giai đoạn APT: Reconnaissance, Establish Foothold, Lateral Movement, Data Exfiltration, Cover up, hoặc Benign",
        "DefenderResponse": "Phản ứng của bên phòng thủ: Detected hoặc Benign (không có Mitigated trong dữ liệu)",
        "Signature": "Nhóm kẻ tấn công: AA (nghiệp dư), APT; None nếu bình thường",
    }
    rows = [[c, grp(c), meaning.get(c, "")] for c in cols]
    wcsv(d + "/fields_unraveled_flow.csv", rows, ["field", "nhóm", "ý_nghĩa"])
    rep = json.load(open(R + "/03_datasets/unraveled_v1_clean/clean_report.json", encoding="utf-8"))
    wcsv(d + "/stage_counts_after_cleaning.csv", [[k, v] for k, v in rep["stage_counts"].items()], ["Stage", "số_flow"])
    wcsv(d + "/cleaning_repairs.csv",
         [["user_agent có dấu phẩy", rep["row_repairs"].get("user_agent_comma", 0), "ghép các trường bị tách thành một user_agent"],
          ["client_fingerprint DHCP là danh sách", rep["row_repairs"].get("dhcp_fingerprint", 0), "ghép danh sách option thành một client_fingerprint"],
          ["dòng bình thường", rep["row_repairs"].get("ok", 0), "giữ nguyên"], ["dòng bị loại", rep["quarantined"], "không có"]],
         ["loại_lỗi", "số_dòng", "cách_sửa"])
    import shutil
    shutil.copy(R + "/02_artifacts/13_unraveled_overview_v1/unraveled_sample_flows.csv", d + "/unraveled_sample_flows.csv")
    print("S8 ok", len(cols), "cols")


FUSION_FIELDS = [
    ("hostname", "Tên máy"), ("day", "Ngày log host (EDT)"), ("window_start_edt", "Cửa sổ 15 phút, giờ EDT"),
    ("window_start_epoch_utc", "Cửa sổ 15 phút, epoch UTC (khóa ghép với nhánh network)"),
    ("split", "val hoặc test (split ngẫu nhiên seed_1)"),
    ("p_net", "Xác suất tấn công của model network (Mixed-Type bỏ app_family, seed_1); rỗng nếu không có flow trong cửa sổ"),
    ("has_net", "1 nếu cửa sổ có mẫu của nhánh network"),
    ("y_net", "Nhãn mạng của pipeline (1 = có flow độc hại)"),
    ("y_host", "Nhãn host của A New Hope (1 = có event độc hại trong cửa sổ)"),
    ("n_proc_writable", "xem fields_host_window.csv"), ("n_parent_lsass", "xem fields_host_window.csv"),
    ("n_cmd_susp", "xem fields_host_window.csv"), ("n_novel_pairs", "Số cặp cha→con chưa từng thấy ở host TRAIN"),
    ("s_host", "Điểm host dạng luật (0–1), độ hiếm của đặc trưng so với cửa sổ benign TRAIN"),
]


def stage_S9():
    d = OUT + "/S9_fusion_inputs"
    os.makedirs(d, exist_ok=True)
    x = pd.read_csv(F12C + "/window_scores_test_val_seed1.csv")
    x = x[x["split"].isin(["val", "test"])].rename(columns={"host": "hostname", "win_edt": "window_start_edt", "win_epoch": "window_start_epoch_utc"})
    keep = [c for c, _ in FUSION_FIELDS]
    x = x.sort_values(["hostname", "window_start_epoch_utc"])[keep]
    x.to_csv(d + "/window_fusion_table_seed1.csv", index=False, encoding="utf-8-sig", lineterminator="\n")
    wcsv(d + "/fields_fusion_table.csv", [[a, b] for a, b in FUSION_FIELDS], ["field", "meaning_vi"])
    pos = x[(x.hostname == "sysclient0051") & (x.window_start_edt.between("2019-09-25 10:15", "2019-09-25 11:15"))]
    wjson(d + "/sample_fusion_rows_SC3.json", [json.loads(r.to_json()) for _, r in pos.iterrows()])
    print("S9 ok", len(x), "rows")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", nargs="+", required=True)
    a = ap.parse_args()
    for s in a.stage:
        globals()["stage_" + s]()
