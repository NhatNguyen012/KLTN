import sys, time
sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
import duckdb
con = duckdb.connect()
con.execute("pragma memory_limit='8GB'")
base = "E:/NEWDATASET/"
gt = base + "research/code_references/NDSS/theseus-main/ground_truth/reapr-ground-truth/darpa-tc-engagement3/"
for ds, lab in [("DARPA-TC-E3-THEIA", "theia_labels.csv"), ("DARPA-TC-E3-CADETS", "cadets_labels.csv")]:
    t0 = time.time()
    print("=====", ds, flush=True)
    P = lambda t: f"read_parquet('{base}{ds}/Parquet/{t}.parquet')"
    print(con.execute(f"select operation, count(*) c from {P('event_table')} group by 1 order by 2 desc limit 12").fetchdf().to_string(), flush=True)
    print("time range:", con.execute(f"select strftime(make_timestamp(min(timestamp_rec)//1000), '%Y-%m-%d %H:%M'), strftime(make_timestamp(max(timestamp_rec)//1000), '%Y-%m-%d %H:%M') from {P('event_table')}").fetchone(), flush=True)
    print(con.execute(f"select src_addr,src_port,dst_addr,dst_port from {P('netflow_node_table')} using sample 8 rows").fetchdf().to_string(), flush=True)
    # events whose dst is a netflow node (process -> netflow) : hash join on dst_node
    con.execute(f"create or replace temp table nf as select hash_id, src_addr, src_port, dst_addr, dst_port from {P('netflow_node_table')}")
    con.execute(f"""create or replace temp table ev as
        select e.src_node as proc_hash, e.operation, e.timestamp_rec, n.dst_addr, n.dst_port
        from {P('event_table')} e join nf n on e.dst_node = n.hash_id""")
    print("events process->netflow:", con.execute("select count(*) from ev").fetchone(), flush=True)
    print(con.execute("select operation, count(*) c from ev group by 1 order by 2 desc limit 10").fetchdf().to_string(), flush=True)
    import pandas as pd
    ldf = pd.read_csv(gt + lab, skipinitialspace=True, usecols=["uuid", "process_name"], on_bad_lines="skip", engine="python")
    ldf["uuid"] = ldf["uuid"].astype(str).str.strip().str.upper()
    ldf = ldf.drop_duplicates("uuid")
    con.register("ldf", ldf)
    con.execute("create or replace temp table lab as select uuid, process_name pn from ldf")
    con.execute(f"""create or replace temp table pr as select hash_id, node_uuid, path, cmd from {P('process_node_table')}""")
    con.execute("""create or replace temp table evl as select ev.*, pr.path, pr.node_uuid, (lab.uuid is not null) as pos
        from ev left join pr on ev.proc_hash = pr.hash_id left join lab on upper(pr.node_uuid) = upper(lab.uuid)""")
    print(con.execute("select pos, count(*) n, count(distinct node_uuid) procs, count(distinct dst_addr) dips from evl group by 1").fetchdf().to_string(), flush=True)
    print(con.execute("select path, pos, count(*) c from evl group by 1,2 order by 3 desc limit 12").fetchdf().to_string(), flush=True)
    print(con.execute("select path, count(*) c, count(distinct dst_addr) ips from evl where pos group by 1 order by 2 desc limit 10").fetchdf().to_string(), flush=True)
    print(con.execute("select dst_port, pos, count(*) c from evl group by 1,2 order by 3 desc limit 10").fetchdf().to_string(), flush=True)
    print("label rows:", con.execute("select count(*) from lab").fetchone(), "secs", round(time.time() - t0), flush=True)
