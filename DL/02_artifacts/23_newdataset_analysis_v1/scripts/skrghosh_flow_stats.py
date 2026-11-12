import sys
sys.stdout.reconfigure(encoding="utf-8")
import duckdb
con = duckdb.connect()
con.execute("pragma memory_limit='6GB'")
b = "E:/NEWDATASET/skrghosh/"
for name, js, lb in [("fin6", "output_fin6.json", "output_fin6.json.labels.csv"), ("apt29", "apt29.json", "apt29.json.labels.csv")]:
    print("=====", name)
    con.execute(f"""
    create or replace temp table f as
    select j.id, j.action, j.hostname, j.pid, j.ppid, j.principal, j.timestamp,
           j.properties.image_path as image_path, j.properties.dest_ip as dest_ip, j.properties.dest_port as dest_port,
           j.properties.src_ip as src_ip, j.properties.l4_protocol as proto, j.properties.direction as direction,
           j.properties.size as size, j.actorID as actor
    from read_json('{b}{js}', format='newline_delimited', columns={{id:'VARCHAR',action:'VARCHAR',object:'VARCHAR',hostname:'VARCHAR',pid:'BIGINT',ppid:'BIGINT',principal:'VARCHAR',timestamp:'VARCHAR',actorID:'VARCHAR',properties:'STRUCT(image_path VARCHAR,dest_ip VARCHAR,dest_port VARCHAR,src_ip VARCHAR,l4_protocol VARCHAR,direction VARCHAR,size VARCHAR)'}}) j
    where j.object='FLOW'""")
    con.execute(f"create or replace temp table l as select id,label from read_csv_auto('{b}labeled/{lb}')")
    con.execute("create or replace temp table x as select f.*, l.label from f left join l using(id)")
    print(con.execute("select count(*) n, sum((label=1)::int) pos, count(distinct hostname) hosts, count(distinct src_ip) src_ips, count(distinct actor) actors from x").fetchdf().to_string())
    print(con.execute("select action,label,count(*) c from x group by 1,2 order by 3 desc").fetchdf().to_string())
    print(con.execute("select direction,proto,label,count(*) c from x group by 1,2,3 order by 4 desc limit 10").fetchdf().to_string())
    print(con.execute("select image_path,label,count(*) c from x group by 1,2 order by 3 desc limit 14").fetchdf().to_string())
    print(con.execute("select principal,label,count(*) c from x group by 1,2 order by 3 desc limit 6").fetchdf().to_string())
    print(con.execute("select dest_port,label,count(*) c from x group by 1,2 order by 3 desc limit 12").fetchdf().to_string())
    print(con.execute("select label, count(size) with_size, count(*) n from x group by 1").fetchdf().to_string())
    print(con.execute("select label, count(distinct dest_ip) ips from x where label=1 group by 1").fetchdf().to_string())
    print(con.execute("select min(timestamp), max(timestamp) from x").fetchdf().to_string())
