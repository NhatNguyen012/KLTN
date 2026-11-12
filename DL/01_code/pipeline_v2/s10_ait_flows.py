#!/usr/bin/env python3
"""S10b - AIT_Log_V2.1: Suricata eve.json (event_type = flow) -> bảng flow cùng cột với flows_joined của OpTC (cột Bro và cột tiến trình để NULL).

Input : E:/NEWDATASET/AIT_Log_V2.1/{fox,harrison}_dataset/gather/<máy>/logs/suricata/eve.json[.1]; nhãn chính thức của các log khác (labels/...) và gather/attacker_0/logs/attacks.log (chỉ đọc)
Output: 02_artifacts/25_newdataset_preprocess_v1/ait/data/flows_ait.parquet, checks_flows.json
NHÃN LÀ NHÃN SUY RA (AIT không có nhãn cho eve.json): flow dương nếu (src_ip hoặc dest_ip thuộc tập IP kẻ tấn công) và flow.start nằm trong [vpn_connect, vpn_disconnect] của attacks.log.
  Tập IP kẻ tấn công = IP khách trên các dòng apache access và openvpn đã được AIT gán nhãn dương. Pha dnsteal (nhiều ngày trước) và cùng IP NAT dùng cho cả traffic benign
  trong cửa sổ có thể làm nhãn sai; xem STEP_25.
hostname = ait_<fox|harrison>_<máy>; ts = flow.start (UTC)."""
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

import duckdb
import pandas as pd

sys.stdout.reconfigure(encoding="utf-8")
SRC = Path("E:/NEWDATASET/AIT_Log_V2.1")
OUT = Path("D:/UIT/KLTNv2/02_artifacts/25_newdataset_preprocess_v1/ait")
SCEN = {"fox": ("fox_dataset", "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2"),
        "harrison": ("harrison_dataset", "intranet_server/logs/apache2/intranet.mannsmith.harrison.com-access.log.1")}
NEEDLE = b'"event_type":"flow"'


def positive_lines(label_file, tag=None):
    s = set()
    with open(label_file, encoding="utf-8") as f:
        for l in f:
            d = json.loads(l)
            if tag is None or tag in d["labels"]:
                s.add(d["line"])
    return s


def attacker_ips(folder, apache_rel):
    ips = Counter()
    pa = positive_lines(SRC / folder / "labels" / apache_rel, "attacker_http")
    with open(SRC / folder / "gather" / apache_rel, encoding="utf-8", errors="replace") as f:
        for i, l in enumerate(f, 1):
            if i in pa:
                ips[l.split(" ", 1)[0]] += 1
    pv = positive_lines(SRC / folder / "labels" / "vpn/logs/openvpn.log")
    with open(SRC / folder / "gather" / "vpn/logs/openvpn.log", encoding="utf-8", errors="replace") as f:
        for i, l in enumerate(f, 1):
            if i in pv:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+):\d+", l)
                if m:
                    ips[m.group(1)] += 1
    return ips


def attack_window(folder):
    lines = (SRC / folder / "gather/attacker_0/logs/attacks.log").read_text(encoding="utf-8").splitlines()
    conn = [l for l in lines if l.endswith(" vpn_connect")][0]
    disc = [l for l in lines if l.endswith(" vpn_disconnect")][-1]
    ep = lambda s: pd.Timestamp(" ".join(s.split(" ")[:2])).timestamp()  # noqa: E731
    return ep(conn), ep(disc)


def read_eve(path):
    rows = []
    with open(path, "rb") as f:
        for line in f:
            if NEEDLE not in line:
                continue
            d = json.loads(line)
            fl = d.get("flow") or {}
            rows.append((d.get("flow_id"), fl.get("start"), d.get("src_ip"), d.get("src_port"), d.get("dest_ip"), d.get("dest_port"), d.get("proto"),
                         (fl.get("pkts_toserver") or 0) + (fl.get("pkts_toclient") or 0), (fl.get("bytes_toserver") or 0) + (fl.get("bytes_toclient") or 0), fl.get("state")))
    return rows


def main():
    t0 = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "data").mkdir(exist_ok=True)
    frames, report = [], {"scenarios": {}}
    for sc, (folder, apache_rel) in SCEN.items():
        ips = attacker_ips(folder, apache_rel)
        t_a, t_b = attack_window(folder)
        report["scenarios"][sc] = {"attacker_ips": dict(ips), "attack_window_epoch": [t_a, t_b], "machines": {}}
        for mdir in sorted((SRC / folder / "gather").iterdir()):
            files = sorted(mdir.glob("logs/suricata/eve.json*"))
            if not files:
                continue
            rows = []
            for fp in files:
                rows += read_eve(fp)
            df = pd.DataFrame(rows, columns=["flow_id", "start", "src_ip", "src_port", "dest_ip", "dest_port", "proto_raw", "pkts", "bytes", "state"])
            assert df.start.notna().all() and df.start.str.endswith("+0000").all(), "mốc thời gian không phải UTC +0000"
            df["ts"] = (pd.to_datetime(df.start.str.slice(0, 26), format="%Y-%m-%dT%H:%M:%S.%f") - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)  # độc lập với đơn vị thời gian của pandas
            att = df.src_ip.isin(ips.keys()) | df.dest_ip.isin(ips.keys())
            df["label"] = (att & (df.ts >= t_a) & (df.ts <= t_b)).astype("int8")
            df["hostname"] = f"ait_{sc}_{mdir.name}"
            df["uid"] = df.hostname + ":" + df.flow_id.astype(str) + ":" + df.index.astype(str)
            df["window_start_epoch"] = (df.ts // 900 * 900).astype("int64")
            df["proto"] = df.proto_raw.str.lower()
            df["resp_h"], df["resp_p"], df["orig_p"] = df.dest_ip, df.dest_port, df.src_port
            df["scenario"] = sc
            frames.append(df[["uid", "hostname", "ts", "window_start_epoch", "label", "proto_raw", "proto", "resp_h", "resp_p", "orig_p", "pkts", "bytes", "state", "scenario"]])
            report["scenarios"][sc]["machines"][mdir.name] = {"flows": int(len(df)), "positive_flows": int(df.label.sum()), "attacker_ip_flows_any_time": int(att.sum()),
                                                              "proto": dict(df.proto.value_counts().head(5)), "ts_min": float(df.ts.min()), "ts_max": float(df.ts.max())}
            print(sc, mdir.name, report["scenarios"][sc]["machines"][mdir.name], f"{time.time() - t0:.0f}s", flush=True)
    allf = pd.concat(frames, ignore_index=True).sort_values(["hostname", "ts", "uid"]).reset_index(drop=True)
    allf.to_parquet(OUT / "data/flows_ait.parquet", index=False)
    report["rows"] = int(len(allf))
    report["positive_flows"] = int(allf.label.sum())
    report["seconds"] = round(time.time() - t0)
    json.dump(report, open(OUT / "checks_flows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    print("xong", report["rows"], report["positive_flows"], report["seconds"], "s")


if __name__ == "__main__":
    main()
