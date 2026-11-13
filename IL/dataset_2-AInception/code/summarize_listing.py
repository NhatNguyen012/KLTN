import collections
import glob
import re
import sys

WIN = ("hq", "dc.", "apps", "media", "ca.", "rootca", "mailrelay")
GB = 1e9
for f in sorted(glob.glob(sys.argv[1] + "/*.tsv")):
    z = f.rsplit("/", 1)[-1][:-4]
    c = collections.Counter()
    for line in open(f):
        _u, cz, n = line.rstrip("\n").split("\t", 2)
        cz = int(cz)
        base = n.rsplit("/", 1)[-1]
        if z.startswith("SL300"):
            if "suricata" in n:
                k = "suricata"
            elif base.startswith("mail."):
                k = "mail"
            elif "/labelled_logs/" in n:
                k = "labelled"
            elif "/logs/" in n and n.endswith(".ecslogs"):
                k = ("win_" if base.startswith(WIN) else "lin_") + ("benign" if "benign_days" in n else "attack")
            else:
                k = "other"
        elif z.startswith("SL700"):
            if re.search(r"log\.pcap\.\d+$", n):
                k = "pcap"
            elif "_labeled/" in n:
                k = "lab_audit" if "/audit/" in n else "lab_other"
            elif "/audit/audit.log" in n:
                k = "raw_audit"
            else:
                k = "raw_other"
        else:
            k = "all"
        c[k] += cz
        c["TOTAL"] += cz
    if z.startswith("SL300"):
        win = c["win_benign"] + c["win_attack"]
        lin = c["lin_benign"] + c["lin_attack"]
        print(f"{z:18s} total {c['TOTAL']/GB:6.2f} | suricata {c['suricata']/GB:5.2f} | mail {c['mail']/GB:4.2f} | "
              f"win {win/GB:4.2f} (attack {c['win_attack']/GB:.3f}) | linux {lin/GB:4.2f} | labelled {c['labelled']/GB:4.2f} | "
              f"other {c['other']/GB:4.2f} | host-only {(win + lin + c['labelled'] + c['other'])/GB:4.2f} GB")
    elif z.startswith("SL700"):
        print(f"{z:18s} total {c['TOTAL']/GB:6.2f} | pcap {c['pcap']/GB:4.2f} | raw other {c['raw_other']/GB:4.2f} | "
              f"raw audit {c['raw_audit']/1e6:6.1f} MB | labelled audit {c['lab_audit']/1e6:5.1f} MB | labelled other {c['lab_other']/1e6:5.1f} MB")
    else:
        print(f"{z:18s} total {c['TOTAL']/GB:6.3f} GB")
