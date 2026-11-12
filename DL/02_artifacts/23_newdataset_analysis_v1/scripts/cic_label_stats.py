import sys
sys.stdout.reconfigure(encoding="utf-8")
import duckdb
con = duckdb.connect()
con.execute("pragma memory_limit='3GB'")
for ph in ["phase1", "phase2"]:
    p = f"E:/NEWDATASET/CIC-APT-IIoT-2024/Network_Traffic/{ph}_NetworkData.csv"
    print("=====", ph)
    q = f"""select label, count(*) n, min(ts) t0, max(ts) t1,
            count(distinct "Source IP") sip, count(distinct "Destination IP") dip
            from read_csv('{p}', header=true, columns={{'ts':'DOUBLE','label':'VARCHAR'}}, ignore_errors=true, all_varchar=false, auto_detect=false) group by 1"""
    # simpler: use auto-detect but select only needed columns
    q = f"""select label, count(*) n, min(ts) t0, max(ts) t1, count(distinct "Source IP") sip, count(distinct "Destination IP") dip,
            count(distinct "Destination Port") dports
            from read_csv_auto('{p}', sample_size=20000) group by 1 order by 2 desc"""
    print(con.execute(q).fetchdf().to_string())
    q2 = f"""select subLabelCat, subLabel, count(*) n from read_csv_auto('{p}', sample_size=20000) where label<>'0' and label<>0 group by 1,2 order by 3 desc limit 15"""
    try:
        print(con.execute(q2).fetchdf().to_string())
    except Exception as e:
        print("q2 err", e)
