#!/usr/bin/env python3
"""S16c - Raw FiveDirections: tiến trình có đường dẫn ảnh (image path) không? Kiểm cmdLine, predicateObjectPath của EXECUTE/LOADLIBRARY, properties.

Chỉ đọc streaming. Cách dùng: python -I s16_fd_raw_paths.py <tar.gz> <json ra>"""
import json
import re
import sys
import tarfile
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8")
TYPE_RE = re.compile(r'^\{"datum":\{"(?:com\.bbn\.tc\.schema\.avro\.cdm18\.)?([A-Za-z]+)"')
EV_RE = re.compile(r'"type":"(EVENT_[A-Z_]+)"')


def datum(line):
    return next(iter(json.loads(line.rstrip().rstrip(","))["datum"].values()))


def val(u):
    return next(iter(u.values())) if isinstance(u, dict) and len(u) == 1 else u


def main():
    path, out = sys.argv[1], sys.argv[2]
    proc = Counter()
    cmd_examples = []
    ex = {"EVENT_EXECUTE": Counter(), "EVENT_LOADLIBRARY": Counter(), "EVENT_FORK": Counter()}
    ex_ex = {k: [] for k in ex}
    prop_keys = Counter()
    with tarfile.open(path, "r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            for raw in tf.extractfile(m):
                line = raw.decode("utf-8", "replace")
                mt = TYPE_RE.match(line)
                t = mt.group(1) if mt else "?"
                if t == "Subject":
                    r = datum(line)
                    if r.get("type") != "SUBJECT_PROCESS":
                        continue
                    proc["n"] += 1
                    c = val(r.get("cmdLine"))
                    if c:
                        proc["cmd"] += 1
                        first = c.strip().strip('"').split('"')[0] if c.strip().startswith('"') else c.split(" ")[0]
                        if "\\" in first or "/" in first:
                            proc["cmd_first_token_has_dir"] += 1
                        elif len(cmd_examples) < 12:
                            cmd_examples.append(c[:120])
                        if re.search(r"powershell|pass_mgr|drakon|nbtscan", c, re.I):
                            proc["suspect_tokens_in_cmd"] += 1
                elif t == "Event":
                    mm = EV_RE.search(line)
                    if mm and mm.group(1) in ex:
                        et = mm.group(1)
                        ex[et]["n"] += 1
                        if ex[et]["n"] > 20000:
                            continue
                        r = datum(line)
                        ex[et]["parsed"] += 1
                        p = val(r.get("predicateObjectPath"))
                        p2 = val(r.get("predicateObject2Path"))
                        pr = val(r.get("properties"))
                        if p:
                            ex[et]["path"] += 1
                        if p2:
                            ex[et]["path2"] += 1
                        if isinstance(pr, dict):
                            ex[et]["props"] += 1
                            for k in (pr.get("map") or pr):
                                prop_keys[(et, k)] += 1
                        if (p or p2) and len(ex_ex[et]) < 4:
                            ex_ex[et].append({"path": p, "path2": p2})
    res = {"file": path, "processes": dict(proc), "cmd_examples_without_dir": cmd_examples, "events": {k: dict(v) for k, v in ex.items()},
           "event_examples": ex_ex, "event_property_keys": {f"{a}:{b}": c for (a, b), c in prop_keys.most_common(30)}}
    json.dump(res, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(res, ensure_ascii=False, indent=1)[:5000])


if __name__ == "__main__":
    main()
