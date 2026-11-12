#!/usr/bin/env python3
"""S17c - ATLASv2: đọc streaming vài thành viên của atlasv2.tar.gz (h1, scenario m1 và benign tùy chọn) để liệt kê trường: Carbon Black EDR (jsonl), Sysmon (xml), Windows Security (xml), DNS, Firefox, groundtruth.

Không giải nén ra đĩa. Cách dùng: python -I s17_atlas_peek.py <tar.gz> <json ra> <scenario, ví dụ m1>"""
import json
import re
import sys
import tarfile
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8")


def flat(obj, prefix, out, depth=3):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)) and depth > 0:
                flat(v, p, out, depth - 1)
            else:
                out.add(p)
    elif isinstance(obj, list):
        out.add(prefix + "[]")
        for it in obj[:1]:
            flat(it, prefix + "[]", out, depth - 1)


def main():
    path, out, sc = sys.argv[1], sys.argv[2], sys.argv[3]
    base = "atlasv2/data/attack/h1/"
    want = {f"{base}cbc-edr/edr-h1-{sc}.jsonl": "edr", f"{base}sysmon/sysmon-h1-{sc}.xml": "sysmon", f"{base}msft-security/msft-security-h1-{sc}.xml": "sec", f"{base}msft-security/groundtruth/h1_{sc}": "gt",
            f"{base}dns/dns-h1-{sc}": "dns", f"{base}firefox/firefox-h1-{sc}": "ff", f"{base}cbc-edr-alerts/edr-alerts-h1-{sc}.jsonl": "alerts", f"{base}cbc-ngav/ngav-h1-{sc}.jsonl": "ngav"}
    res = {}
    done = set()
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            kind = want.get(m.name)
            if not kind:
                continue
            print("[member]", m.name, m.size, flush=True)
            f = tf.extractfile(m)
            if kind in ("edr", "alerts", "ngav"):
                types = Counter()
                keys = defaultdict(Counter)
                ex = {}
                n = 0
                for raw in f:
                    n += 1
                    try:
                        r = json.loads(raw)
                    except Exception:
                        continue
                    t = str(r.get("type") or r.get("event_type") or r.get("alert_type") or "?")
                    types[t] += 1
                    if types[t] <= 3000:
                        s = set()
                        flat(r, "", s)
                        for p in s:
                            keys[t][p] += 1
                    if t not in ex:
                        ex[t] = raw.decode("utf-8", "replace")[:2500]
                res[kind] = {"member": m.name, "size": m.size, "lines": n, "types": dict(types.most_common()), "fields_by_type": {t: dict(c.most_common()) for t, c in keys.items()},
                             "examples": ex}
                if kind == "edr":
                    res[kind]["example_all_types"] = {t: v[:600] for t, v in ex.items()}
            elif kind == "sysmon":
                text = f.read().decode("utf-8", "replace")
                ids = Counter(re.findall(r"<EventID>(\d+)</EventID>", text))
                evs = re.findall(r"<Event .*?</Event>", text, flags=re.S)
                exs = {}
                for e in evs:
                    i = re.search(r"<EventID>(\d+)</EventID>", e)
                    if i and i.group(1) in ("1", "3", "22") and i.group(1) not in exs:
                        exs[i.group(1)] = e[:3500]
                res[kind] = {"member": m.name, "size": m.size, "event_ids": dict(ids.most_common()), "examples": exs}
            elif kind == "sec":
                head = f.read(80_000_000).decode("utf-8", "replace")
                ids = Counter(re.findall(r"<EventID[^>]*>(\d+)</EventID>", head))
                evs = re.findall(r"<Event .*?</Event>", head, flags=re.S)
                exs = {}
                for e in evs:
                    i = re.search(r"<EventID[^>]*>(\d+)</EventID>", e)
                    if i and i.group(1) in ("5156", "4688", "5158", "5157") and i.group(1) not in exs:
                        exs[i.group(1)] = e[:3000]
                res[kind] = {"member": m.name, "size": m.size, "bytes_read": 80_000_000, "event_ids_first80MB": dict(ids.most_common(25)), "examples": exs, "head": head[:1200]}
            else:
                data = f.read(6000 if kind != "gt" else 5000).decode("utf-8", "replace")
                res[kind] = {"member": m.name, "size": m.size, "head": data}
            done.add(kind)
            if len(done) == len(want):
                break
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[xong]", sorted(done), flush=True)


if __name__ == "__main__":
    main()
