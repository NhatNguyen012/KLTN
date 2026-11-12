#!/usr/bin/env python3
"""S18c - Ghép hai tệp mẫu NGUYÊN VĂN (THEIA, ATLASv2) từ pool do s18_theia_sample.py và s18_atlas_sample.py.

Dòng không bắt đầu bằng '#' là dòng raw giữ nguyên từng ký tự. Dòng bắt đầu bằng '#' hoặc '===' là chú thích do mình thêm (không phải dữ liệu).
Cách dùng: python -I s18_assemble.py <theia_pool.json> <atlas_pool.json> <thư mục ra>"""
import csv
import json
import re
import sys
import tarfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
EDGE_TAR = "E:/IL_DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3/theia_edge_labels.tar.gz"
THEIA_LABELS = "E:/IL_DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3/theia_labels.csv"
TS_RE = re.compile(r'"timestampNanos":(\d+)')
PO_RE = re.compile(r'"predicateObject":\{"com\.bbn\.tc\.schema\.avro\.cdm18\.UUID":"([0-9A-Fa-f-]+)"')
EUUID = re.compile(r'cdm18\.Event":\{"uuid":"([0-9A-Fa-f-]+)"')
LP_RE = re.compile(r'"localPrincipal":"([0-9A-Fa-f-]+)"')


def theia(pool, outdir, extra=None):
    L = []
    P = L.append
    labels = open(THEIA_LABELS, encoding="utf-8").read().splitlines()
    edge_rows = {}
    with tarfile.open(EDGE_TAR, "r:gz") as tf:
        for m in tf:
            if m.isfile():
                lines = tf.extractfile(m).read().decode("utf-8").splitlines()
                edge_hdr = lines[0]
                for ln in lines[1:]:
                    edge_rows.setdefault(ln.split(",")[3].strip().upper(), []).append(ln)
    princ_by_uuid = {}
    for ln in pool["principal_lines"]:
        m = re.search(r'"uuid":"([0-9A-Fa-f-]+)"', ln)
        princ_by_uuid.setdefault(m.group(1).upper(), []).append(ln)
    P("# TỆP MẪU NGUYÊN VĂN - THEIA E3 (DARPA TC), lấy từ ta1-theia-e3-official-6r.json.tar.gz (attack, contaminated, benign 1-2) và từ các lát cắt không có nhãn ...-3 và ...-5m (benign 3-5)")
    P("# Quy ước: dòng KHÔNG bắt đầu bằng '#' hoặc '===' là một dòng JSON gốc của raw, giữ nguyên từng ký tự (không sửa/thêm/bớt trường).")
    P("# Dòng bắt đầu bằng '#' hoặc '===' là chú thích của mình, không phải dữ liệu.")
    P("# Raw THEIA KHÔNG có trường nhãn. Nhãn nằm ở repo REAPr (ngoài raw): theia_labels.csv (khóa = Subject.uuid) và edge_labels.csv (khóa = Event.uuid).")
    P("# Các dòng '# nhãn ...' bên dưới là dòng trích nguyên văn từ hai file nhãn đó.")
    P("# Nhãn có 3 loại: attack, contaminated, benign (= không có trong file nhãn). Mỗi mẫu = một tiến trình (Subject) + các NetFlowObject nó chạm + các Event.")
    P("# Cấu trúc mỗi dòng: {\"datum\":{\"com.bbn.tc.schema.avro.cdm18.<Loại>\":{...}},\"CDMVersion\":\"18\",\"source\":\"SOURCE_LINUX_THEIA\"}")
    P("")
    P("=== BẢN GHI DÙNG CHUNG: Host ===")
    P(pool["host_line"])
    P("")

    def sample(title, subject, events, nf_uuids, label_lines, edge_note):
        P(f"=== {title} ===")
        for ln in label_lines:
            P("# nhãn (theia_labels.csv): " + ln)
        P("# -- Subject (tiến trình) --")
        lp = set()
        for ln in pool["subject_lines"].get(subject, []):
            P(ln)
            m = LP_RE.search(ln)
            if m:
                lp.add(m.group(1).upper())
        P("# -- Principal của tiến trình --")
        for u in sorted(lp):
            for ln in princ_by_uuid.get(u, []):
                P(ln)
        if nf_uuids:
            P("# -- NetFlowObject (ổ cắm) mà các Event bên dưới chạm tới --")
            for u in nf_uuids:
                if u in pool["netflow_lines"]:
                    P(pool["netflow_lines"][u])
        P("# -- Event (theo thời gian) --")
        for ln in sorted(events, key=lambda s: int(TS_RE.search(s).group(1))):
            P(ln)
            if edge_note:
                u = EUUID.search(ln).group(1).upper()
                for er in edge_rows.get(u, []):
                    P("# nhãn cạnh (edge_labels.csv): " + er)
        P("")

    # attack
    for i, (tag, p) in enumerate(pool["picks"].items(), 1):
        evs = [pool["ev_lines"][u] for u in p["events"] if u in pool["ev_lines"]]
        nfs = []
        for ln in evs:
            u = PO_RE.search(ln).group(1).upper()
            if u not in nfs:
                nfs.append(u)
        ll = [x for x in labels if p["subject"].lower() in x.lower()]
        sample(f"[attack] mẫu {i}/3 - chuỗi {p['chain']} - tiến trình {p['subject']} - đầu xa: {', '.join(sorted(set(p['remote'])))}", p["subject"], evs, nfs, ll, True)
    # contaminated
    cs = pool["contam_subject"]
    evs = [pool["ev_lines"][u] for u in pool["contam_events"] if u in pool["ev_lines"]]
    ll = [x for x in labels if cs.lower() in x.lower()]
    P("# LƯU Ý contaminated: trong THEIA chỉ có 1 tiến trình (2 dòng nhãn, 2 chuỗi) và 4 dòng nhãn cạnh (2 sự kiện khác nhau); không có sự kiện nào trong số này chạm NetFlowObject, nên không có flow contaminated. Chỉ có 2 sự kiện khác nhau để minh họa (không đủ 3).")
    sample("[contaminated] mẫu 1-2 - tiến trình " + cs + " (2 sự kiện có nhãn contaminated)", cs, evs, [], ll, True)
    # benign
    for i, (path, b) in enumerate(pool["benign_pick"].items(), 1):
        evs = b["events"]
        nfs = []
        for ln in evs:
            u = PO_RE.search(ln).group(1).upper()
            if u not in nfs:
                nfs.append(u)
        sample(f"[benign] mẫu {i}/5 - tiến trình {b['subject']} ({path}) - không có trong theia_labels.csv và edge_labels.csv", b["subject"], evs, nfs, ["(không có dòng nhãn: benign = không được liệt kê)"], False)
    n0 = len(pool["benign_pick"])
    k = n0
    for fname, ex in (extra or {}).items():
        for path, b in ex["picks"].items():
            if k >= 5 or any(path == pp for pp in [x for x in pool["benign_pick"]]):
                continue
            if path == "/usr/bin/python2.7" and fname.endswith("5m.json.tar.gz") and any("python2.7" in t for t in L if t.startswith("=== [benign]")):
                continue
            k += 1
            P(f"=== [benign] mẫu {k}/5 - tiến trình {b['subject']} ({path}) - lát cắt KHÔNG có nhãn: {fname} - không có trong theia_labels.csv và edge_labels.csv ===")
            P("# nhãn: (không có dòng nhãn: benign = không được liệt kê; lát cắt này không chứa đợt tấn công nào)")
            P("# -- Subject (tiến trình) --")
            for ln in b["subject_lines"]:
                P(ln)
            P("# -- Principal của tiến trình --")
            for ln in b["principal_lines"]:
                P(ln)
            P("# -- NetFlowObject (ổ cắm) mà các Event bên dưới chạm tới --")
            for ln in b["netflow_lines"].values():
                P(ln)
            P("# -- Event (theo thời gian) --")
            for ln in sorted(b["events"], key=lambda s: int(TS_RE.search(s).group(1))):
                P(ln)
            P("")
    Path(outdir, "sample_THEIA_raw.txt").write_text("\n".join(L) + "\n", encoding="utf-8")
    return len(L)


def atlas(pool, outdir):
    L = []
    P = L.append
    lab_lines = pool["label_lines"]
    lab = set(lab_lines)
    P("# TỆP MẪU NGUYÊN VĂN - ATLASv2, lấy từ atlasv2.tar.gz (host h1)")
    P("# Quy ước: dòng KHÔNG bắt đầu bằng '#' hoặc '===' là một dòng gốc của raw (jsonl của Carbon Black hoặc xml), giữ nguyên từng ký tự.")
    P("# Dòng bắt đầu bằng '#' hoặc '===' là chú thích của mình, không phải dữ liệu.")
    P("# Raw ATLASv2 KHÔNG có trường nhãn. Nhãn nằm ở repo REAPr (ngoài raw): atlasv2/<máy>-<kịch bản>.labels, khóa process_uuid = trường process_guid của dòng cbc-edr.")
    P("# Dòng '# nhãn ...' là dòng trích nguyên văn từ file .labels. Nhãn có 2 loại: attack (có trong .labels) và benign (không có).")
    P("# Mỗi mẫu = các hàng netconn liên tiếp của một tiến trình (cùng process_guid). Một hàng = một kết nối mạng đã kèm process_*, parent_*.")
    P("")
    P("# Tiêu đề file nhãn: " + pool["label_header"])
    P("")
    pos = pool["attack_file_labeled"]

    def info(lines):
        d = json.loads(lines[0])
        return d.get("process_path"), {json.loads(x).get("remote_ip") for x in lines}

    chosen = []
    for g, ls in sorted(pos.items(), key=lambda kv: -len(kv[1])):
        path, ips = info(ls)
        if "10.193.66.115" in ips and not chosen:
            chosen.append(g)
    for g, ls in sorted(pos.items(), key=lambda kv: -len(kv[1])):
        if (info(ls)[0] or "").endswith("payload.exe") and g not in chosen:
            chosen.append(g)
            break
    for g, ls in sorted(pos.items(), key=lambda kv: -len(kv[1])):
        path, ips = info(ls)
        if (path or "").endswith("firefox.exe") and "10.193.66.115" not in ips and g not in chosen:
            chosen.append(g)
            break
    for g in sorted(pos, key=lambda k: -len(pos[k])):
        if g not in chosen:
            chosen.append(g)
    for i, g in enumerate(chosen, 1):
        path, ips = info(pos[g])
        P(f"=== [attack] mẫu {i}/{len(chosen)} - kịch bản h1-m1 (tấn công) - process_guid {g} - {path} - đầu xa: {', '.join(sorted(x for x in ips if x))} ===")
        P("# nhãn (h1-m1.labels): " + lab_lines[g])
        for ln in pos[g]:
            P(ln)
        P("")
    neg = pool["benign_file"]
    chosen_b = []
    for pref in ("firefox.exe", "svchost.exe", "discord.exe", "iexplore.exe", "python.exe", "sublime_text.exe", "wmplayer.exe", "lsass.exe", "mmc.exe"):
        for g, ls in sorted(neg.items(), key=lambda kv: -len(kv[1])):
            path = json.loads(ls[0]).get("process_path") or ""
            if path.endswith(pref) and len(ls) >= 3 and g not in chosen_b and len(chosen_b) < 5 and all((json.loads(neg[c][0]).get("process_path") or "") != path for c in chosen_b):
                chosen_b.append(g)
                break
    for i, g in enumerate(chosen_b, 1):
        path = json.loads(neg[g][0]).get("process_path")
        ips = sorted({json.loads(x).get("remote_ip") for x in neg[g] if json.loads(x).get("remote_ip")})
        P(f"=== [benign] mẫu {i}/{len(chosen_b)} - kịch bản benign (4 ngày nền, h1) - process_guid {g} - {path} - đầu xa: {', '.join(ips)} ===")
        P("# nhãn: không có (benign = không được liệt kê trong .labels; file benign không có file .labels)")
        for ln in neg[g]:
            P(ln)
        P("")
    P("=== PHỤ LỤC (nguồn khác trong cùng dataset, chỉ để tham khảo; không dùng làm flow) ===")
    P("# Windows Security, EventID 5156 (kết nối được phép), từ msft-security-h1-m1.xml")
    P(pool["security_events"].get("5156", "(không thấy)"))
    P("# Windows Security, EventID 4688 (tạo tiến trình)")
    P(pool["security_events"].get("4688", "(không thấy)"))
    P("# Sysmon EventID 1 (tạo tiến trình) - lưu ý trong file này không có EventID 3 (kết nối mạng)")
    P(pool["sysmon_events"].get("1", "(không thấy)"))
    P("# Sysmon EventID 5 (kết thúc tiến trình)")
    P(pool["sysmon_events"].get("5", "(không thấy)"))
    P("# DNS (Wireshark txt), 8 dòng đầu của dns-h1-m1")
    for ln in pool["dns_head"]:
        P(ln)
    P("# Nhãn Windows Security (groundtruth/h1_m1): EventRecordID độc hại, 6 dòng đầu")
    for ln in pool["sec_gt_head"]:
        P(ln)
    Path(outdir, "sample_ATLASv2_raw.txt").write_text("\n".join(L) + "\n", encoding="utf-8")
    return len(L), len(chosen), len(chosen_b)


if __name__ == "__main__":
    tp = json.load(open(sys.argv[1], encoding="utf-8"))
    ap = json.load(open(sys.argv[2], encoding="utf-8"))
    out = sys.argv[3]
    extra = json.load(open(sys.argv[4], encoding="utf-8")) if len(sys.argv) > 4 else None
    print("THEIA lines", theia(tp, out, extra))
    print("ATLAS lines, attack picks, benign picks", atlas(ap, out))
