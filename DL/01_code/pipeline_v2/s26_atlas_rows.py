#!/usr/bin/env python3
"""S26 (STEP 40) - ATLASv2: trích mọi dòng netconn và procstart của Carbon Black EDR cùng ngữ cảnh (cha, cmdline, hash) và nhãn REAPr (process_guid).
Một lượt streaming trên atlasv2.tar.gz (chỉ đọc). Ghi CSV nhỏ (~30k netconn, ~6.6k procstart).
Cách dùng: python s26_atlas_rows.py <atlasv2.tar.gz> <thư mục .labels> <thư mục ra>"""
import csv
import glob
import json
import os
import re
import sys
import tarfile

sys.stdout.reconfigure(encoding="utf-8")
MEM = re.compile(r"atlasv2/data/(attack|benign)/(h\d)/cbc-edr/edr-(h\d)-([a-z0-9-]+)\.jsonl$")
NET = ["kind", "host", "scenario", "device_timestamp", "action", "process_guid", "process_pid", "process_path", "process_cmdline", "process_username", "process_md5", "parent_guid", "parent_path",
       "parent_cmdline", "parent_md5", "remote_ip", "remote_port", "local_ip", "local_port", "netconn_protocol", "netconn_inbound", "netconn_domain", "process_reputation", "label_proc"]
PS = ["kind", "host", "scenario", "device_timestamp", "action", "process_guid", "process_path", "process_cmdline", "process_username", "process_md5", "parent_path", "childproc_guid",
      "childproc_name", "childproc_pid", "target_cmdline", "childproc_md5", "label_parent", "label_child"]


def md5(h):
    return h[0] if isinstance(h, list) and h else ""


def main():
    path, labdir, outdir = sys.argv[1:4]
    os.makedirs(outdir, exist_ok=True)
    labels = {}
    for f in glob.glob(os.path.join(labdir, "*.labels")):
        name = os.path.basename(f).replace(".labels", "")
        s = set()
        for i, line in enumerate(open(f, encoding="utf-8")):
            if i:
                p = [x.strip() for x in line.rstrip().split(",")]
                if len(p) >= 5:
                    s.add(p[3])
        labels[name] = s
    fn = open(os.path.join(outdir, "atlas_netconn_rows.csv"), "w", encoding="utf-8", newline="")
    fp = open(os.path.join(outdir, "atlas_procstart_rows.csv"), "w", encoding="utf-8", newline="")
    wn, wp = csv.writer(fn), csv.writer(fp)
    wn.writerow(NET)
    wp.writerow(PS)
    n_net = n_ps = 0
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            mm = MEM.search(m.name) if m.isfile() else None
            if not mm:
                continue
            kind, host, _, sc = mm.groups()
            lab = labels.get(f"{host}-{sc}", set()) if kind == "attack" else set()
            print("[member]", kind, host, sc, m.size, flush=True)
            for raw in tf.extractfile(m):
                head = raw[:60]
                isn = b'"endpoint.event.netconn"' in head
                isp = b'"endpoint.event.procstart"' in head
                if not (isn or isp):
                    continue
                try:
                    d = json.loads(raw)
                except Exception:
                    continue
                if isn:
                    wn.writerow([kind, host, sc, d.get("device_timestamp"), d.get("action"), d.get("process_guid"), d.get("process_pid"), d.get("process_path"), d.get("process_cmdline"),
                                 d.get("process_username"), md5(d.get("process_hash")), d.get("parent_guid"), d.get("parent_path"), d.get("parent_cmdline"), md5(d.get("parent_hash")),
                                 d.get("remote_ip"), d.get("remote_port"), d.get("local_ip"), d.get("local_port"), d.get("netconn_protocol"), d.get("netconn_inbound"), d.get("netconn_domain"),
                                 d.get("process_reputation"), int(d.get("process_guid") in lab)])
                    n_net += 1
                else:
                    wp.writerow([kind, host, sc, d.get("device_timestamp"), d.get("action"), d.get("process_guid"), d.get("process_path"), d.get("process_cmdline"), d.get("process_username"),
                                 md5(d.get("process_hash")), d.get("parent_path"), d.get("childproc_guid"), d.get("childproc_name"), d.get("childproc_pid"), d.get("target_cmdline"),
                                 md5(d.get("childproc_hash")), int(d.get("process_guid") in lab), int(d.get("childproc_guid") in lab)])
                    n_ps += 1
            fn.flush()
            fp.flush()
    print("[xong] netconn", n_net, "procstart", n_ps, flush=True)


if __name__ == "__main__":
    main()
