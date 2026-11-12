from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import sqlite3
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import orjson as _orjson
except ImportError:
    _orjson = None

try:
    from isal import igzip as _igzip
except ImportError:
    _igzip = None

SCRIPT_VERSION = "step04a-network-profile-fast-v2.0"
HOST_RE = re.compile(r"(?i)\b(sysclient\d{4})\b")


def now_iso() -> str:
    return datetime.now().isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def stable_hash64(text: str) -> int:
    return int.from_bytes(
        hashlib.blake2b(text.encode("utf-8", "ignore"), digest_size=8).digest(),
        "big",
    )


def sampled(uid: str, sample_mod: int) -> bool:
    return stable_hash64(uid) % sample_mod == 0


def json_loads(raw: bytes):
    return _orjson.loads(raw) if _orjson is not None else json.loads(raw)


def gz_binary(path: Path):
    return _igzip.open(path, "rb") if _igzip is not None else gzip.open(path, "rb")


def gz_text(path: Path):
    if _igzip is not None:
        return _igzip.open(path, "rt", encoding="utf-8", errors="replace")
    return gzip.open(path, "rt", encoding="utf-8", errors="replace")


def discover_gz(root: Path) -> list[Path]:
    files: list[Path] = []
    for folder, _, names in os.walk(root):
        for name in names:
            if name.lower().endswith(".gz"):
                files.append(Path(folder) / name)
    return sorted(files)


def norm_host(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    m = HOST_RE.search(text)
    return m.group(1).lower() if m else text


def norm_label(value: Any) -> str:
    if value is None:
        return "missing"
    if isinstance(value, bool):
        return "1" if value else "0"
    text = str(value).strip().lower()
    if text in {"1", "true", "attack", "malicious", "positive", "yes"}:
        return "1"
    if text in {"0", "false", "benign", "negative", "no"}:
        return "0"
    if text in {"", "-", "none", "null", "(empty)"}:
        return "missing"
    return text


def app_name(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().replace("/", "\\")
    return text.rsplit("\\", 1)[-1].lower() if text else ""


def date_from_path(path: Path) -> str:
    for part in path.parts:
        if re.fullmatch(r"20\d{2}-\d{2}-\d{2}", part):
            return part
    m = re.search(r"(20\d{2}-\d{2}-\d{2})", path.name)
    return m.group(1) if m else ""


def connect_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=60.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA busy_timeout=60000")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS split_hosts(
            hostname TEXT PRIMARY KEY,
            split TEXT NOT NULL,
            gt_positive INTEGER NOT NULL DEFAULT 0,
            gt_scenarios TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS sampled_uid(
            uid TEXT PRIMARY KEY,
            occurrence_count INTEGER NOT NULL,
            first_hostname TEXT NOT NULL,
            first_date TEXT NOT NULL,
            first_label TEXT NOT NULL,
            first_app TEXT NOT NULL,
            hostname_conflict INTEGER NOT NULL DEFAULT 0,
            label_conflict INTEGER NOT NULL DEFAULT 0,
            bro_occurrence_count INTEGER NOT NULL DEFAULT 0,
            bro_first_label TEXT NOT NULL DEFAULT 'missing',
            bro_label_conflict INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS file_stats(
            source TEXT NOT NULL,
            absolute_path TEXT PRIMARY KEY,
            file_index INTEGER NOT NULL,
            date TEXT NOT NULL,
            compressed_size_bytes INTEGER NOT NULL,
            records INTEGER NOT NULL,
            parse_errors INTEGER NOT NULL,
            uid_records INTEGER NOT NULL,
            sampled_or_matched_records INTEGER NOT NULL,
            elapsed_seconds REAL NOT NULL,
            completed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS counters(
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            key TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY(source, category, key)
        );
        """
    )
    conn.commit()
    return conn


def meta(conn: sqlite3.Connection) -> dict[str, str]:
    return dict(conn.execute("SELECT key,value FROM metadata").fetchall())


def set_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO metadata(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def inc(counter: Counter, source: str, category: str, value: Any) -> None:
    text = "missing" if value is None else str(value).strip()
    if not text:
        text = "missing"
    counter[(source, category, text)] += 1


def merge_counter(conn: sqlite3.Connection, counter: Counter) -> None:
    conn.executemany(
        """
        INSERT INTO counters(source,category,key,count)
        VALUES(?,?,?,?)
        ON CONFLICT(source,category,key) DO UPDATE SET
            count=count+excluded.count
        """,
        [(s, c, k, int(v)) for (s, c, k), v in counter.items()],
    )


def load_frozen_split(conn: sqlite3.Connection, manifest: Path, sha_file: Path) -> str:
    actual = sha256_file(manifest)
    expected = sha_file.read_text(encoding="utf-8").strip().split()[0].lower()
    if actual != expected:
        raise RuntimeError(
            f"Frozen manifest SHA mismatch\nexpected={expected}\nactual={actual}"
        )

    if conn.execute("SELECT COUNT(*) FROM split_hosts").fetchone()[0]:
        if meta(conn).get("split_manifest_sha256") != actual:
            raise RuntimeError("FAST V2 checkpoint belongs to another frozen split.")
        return actual

    hosts: dict[str, tuple[str, int, str]] = {}
    with manifest.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            host = norm_host(row.get("hostname"))
            split = str(row.get("split") or "").strip().lower()
            if not host:
                continue
            if split not in {"train", "val", "test"}:
                raise ValueError(f"Unexpected split {split!r} for {host}")
            positive = 1 if str(row.get("gt_positive_host_group") or "").strip().lower() in {"1","true","yes"} else 0
            scenarios = str(row.get("gt_scenarios") or "").strip()
            old = hosts.get(host)
            if old and old[0] != split:
                raise RuntimeError(f"Frozen split leakage for hostname: {host}")
            hosts[host] = (split, positive, scenarios)

    conn.executemany(
        "INSERT INTO split_hosts(hostname,split,gt_positive,gt_scenarios) VALUES(?,?,?,?)",
        [(h, s, p, sc) for h, (s, p, sc) in sorted(hosts.items())],
    )
    set_meta(conn, "split_manifest_sha256", actual)
    set_meta(conn, "split_host_count", len(hosts))
    conn.commit()
    return actual


def profile_ecar(
    path: Path,
    conn: sqlite3.Connection,
    index: int,
    progress_every: int,
    sample_mod: int,
) -> None:
    started = time.time()
    records = uid_records = sampled_records = parse_errors = 0
    local = Counter()
    date = date_from_path(path)
    sample_batch: list[tuple[str, str, str, str, str]] = []

    def flush_sample() -> None:
        nonlocal sample_batch
        if not sample_batch:
            return
        conn.executemany(
            """
            INSERT INTO sampled_uid(
                uid,occurrence_count,first_hostname,first_date,first_label,first_app,
                hostname_conflict,label_conflict
            ) VALUES(?,1,?,?,?,?,0,0)
            ON CONFLICT(uid) DO UPDATE SET
                occurrence_count=occurrence_count+1,
                hostname_conflict=hostname_conflict OR (
                    excluded.first_hostname<>'' AND sampled_uid.first_hostname<>'' AND
                    excluded.first_hostname<>sampled_uid.first_hostname
                ),
                label_conflict=label_conflict OR (
                    excluded.first_label<>'missing' AND sampled_uid.first_label<>'missing' AND
                    excluded.first_label<>sampled_uid.first_label
                )
            """,
            sample_batch,
        )
        sample_batch = []

    with gz_binary(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json_loads(raw)
            except Exception:
                parse_errors += 1
                continue
            if not isinstance(obj, dict):
                parse_errors += 1
                continue

            records += 1
            props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}

            for k in obj.keys():
                inc(local, "ecar_bro", "top_field", k)
            for k in props.keys():
                inc(local, "ecar_bro", "property_field", k)

            hostname = norm_host(obj.get("hostname"))
            label = norm_label(obj.get("label"))
            app = app_name(props.get("image_path"))

            inc(local, "ecar_bro", "action", obj.get("action"))
            inc(local, "ecar_bro", "object", obj.get("object"))
            inc(local, "ecar_bro", "label", label)
            if hostname:
                inc(local, "ecar_bro", "hostname", hostname)
            if app:
                inc(local, "ecar_bro", "app", app)
            if props.get("direction") is not None:
                inc(local, "ecar_bro", "direction", props.get("direction"))
            proto = props.get("l4protocol", props.get("protocol"))
            if proto is not None:
                inc(local, "ecar_bro", "protocol", proto)
            if props.get("service") is not None:
                inc(local, "ecar_bro", "service", props.get("service"))

            uid = str(props.get("bro_uid") or "").strip()
            if uid:
                uid_records += 1
                if sampled(uid, sample_mod):
                    sampled_records += 1
                    sample_batch.append((uid, hostname, date, label, app))
                    if len(sample_batch) >= 5000:
                        flush_sample()

            if progress_every and records % progress_every == 0:
                print(
                    f"      [eCAR FAST] records={records:,} uid={uid_records:,} "
                    f"sampled={sampled_records:,} elapsed={time.time()-started:.1f}s",
                    flush=True,
                )

    flush_sample()
    merge_counter(conn, local)
    conn.execute(
        """
        INSERT INTO file_stats(
            source,absolute_path,file_index,date,compressed_size_bytes,
            records,parse_errors,uid_records,sampled_or_matched_records,
            elapsed_seconds,completed_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "ecar_bro", str(path), index, date, int(path.stat().st_size),
            records, parse_errors, uid_records, sampled_records,
            time.time()-started, now_iso(),
        ),
    )
    conn.commit()


def parse_sep(line: str) -> str:
    value = line.split(" ", 1)[1].strip()
    if value == r"\x09":
        return "\t"
    return value


def profile_bro(
    path: Path,
    conn: sqlite3.Connection,
    index: int,
    progress_every: int,
    sampled_uid_set: set[str],
) -> None:
    started = time.time()
    records = uid_records = matched_records = parse_errors = 0
    local = Counter()
    date = date_from_path(path)
    sep = "\t"
    fields: list[str] = []
    first_data = True
    matched = Counter()
    matched_labels: dict[str, Counter] = {}

    with gz_text(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#separator"):
                sep = parse_sep(line)
                continue
            if line.startswith("#fields"):
                fields = line.split(sep)[1:]
                if len(fields) <= 1:
                    fields = line.split()[1:]
                for k in fields:
                    inc(local, "bro", "field", k)
                continue
            if line.startswith("#"):
                continue

            if first_data and not fields and "," in line:
                candidate = next(csv.reader([line]))
                if "uid" in candidate:
                    fields = candidate
                    sep = ","
                    for k in fields:
                        inc(local, "bro", "field", k)
                    first_data = False
                    continue
            first_data = False

            try:
                values = next(csv.reader([line])) if sep == "," else line.split(sep)
                if not fields or len(values) != len(fields):
                    parse_errors += 1
                    continue
                row = dict(zip(fields, values))
            except Exception:
                parse_errors += 1
                continue

            records += 1
            uid = str(row.get("uid") or "").strip()
            label = norm_label(row.get("label"))
            if uid:
                uid_records += 1
                if uid in sampled_uid_set:
                    matched_records += 1
                    matched[uid] += 1
                    matched_labels.setdefault(uid, Counter())[label] += 1

            for field in ("proto", "service", "conn_state", "local_orig", "local_resp"):
                if field in row:
                    inc(local, "bro", field, row.get(field))
            inc(local, "bro", "label", label)

            if progress_every and records % progress_every == 0:
                print(
                    f"      [Bro FAST] records={records:,} uid={uid_records:,} "
                    f"sample_matches={matched_records:,} errors={parse_errors:,} "
                    f"elapsed={time.time()-started:.1f}s",
                    flush=True,
                )

    merge_counter(conn, local)

    updates = []
    for uid, count in matched.items():
        labels = matched_labels.get(uid, Counter())
        non_missing = [k for k, v in labels.items() if k != "missing" and v > 0]
        first_label = labels.most_common(1)[0][0] if labels else "missing"
        updates.append((int(count), first_label, 1 if len(non_missing) > 1 else 0, uid))

    conn.executemany(
        """
        UPDATE sampled_uid
        SET bro_occurrence_count=bro_occurrence_count+?,
            bro_first_label=CASE WHEN bro_first_label='missing' THEN ? ELSE bro_first_label END,
            bro_label_conflict=bro_label_conflict OR ?
        WHERE uid=?
        """,
        updates,
    )

    conn.execute(
        """
        INSERT INTO file_stats(
            source,absolute_path,file_index,date,compressed_size_bytes,
            records,parse_errors,uid_records,sampled_or_matched_records,
            elapsed_seconds,completed_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "bro", str(path), index, date, int(path.stat().st_size),
            records, parse_errors, uid_records, matched_records,
            time.time()-started, now_iso(),
        ),
    )
    conn.commit()


def source_totals(conn: sqlite3.Connection, source: str) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT COUNT(*),COALESCE(SUM(compressed_size_bytes),0),COALESCE(SUM(records),0),
               COALESCE(SUM(parse_errors),0),COALESCE(SUM(uid_records),0),
               COALESCE(SUM(sampled_or_matched_records),0),COALESCE(SUM(elapsed_seconds),0)
        FROM file_stats WHERE source=?
        """,
        (source,),
    ).fetchone()
    keys = [
        "files_completed","compressed_size_bytes","records","parse_errors",
        "uid_records","sampled_or_matched_records","elapsed_seconds"
    ]
    vals = [int(row[0]), int(row[1]), int(row[2]), int(row[3]), int(row[4]), int(row[5]), float(row[6])]
    return dict(zip(keys, vals))


def top_values(conn: sqlite3.Connection, source: str, category: str, limit: int = 100):
    return [
        {"value": str(k), "count": int(c)}
        for k, c in conn.execute(
            "SELECT key,count FROM counters WHERE source=? AND category=? ORDER BY count DESC,key LIMIT ?",
            (source, category, limit),
        )
    ]


def build_report(
    conn: sqlite3.Connection,
    *,
    manifest: Path,
    manifest_sha: str,
    ecar_files: int,
    bro_files: int,
    sample_mod: int,
) -> dict[str, Any]:
    ecar = source_totals(conn, "ecar_bro")
    bro = source_totals(conn, "bro")

    sample_unique = int(conn.execute("SELECT COUNT(*) FROM sampled_uid").fetchone()[0])
    sample_matched = int(conn.execute("SELECT COUNT(*) FROM sampled_uid WHERE bro_occurrence_count>0").fetchone()[0])
    host_known = int(conn.execute("SELECT COUNT(*) FROM sampled_uid WHERE first_hostname<>''").fetchone()[0])
    split_known = int(conn.execute(
        "SELECT COUNT(*) FROM sampled_uid e JOIN split_hosts s ON s.hostname=e.first_hostname"
    ).fetchone()[0])

    split_counts = {
        str(split): int(count)
        for split, count in conn.execute(
            "SELECT s.split,COUNT(*) FROM sampled_uid e JOIN split_hosts s ON s.hostname=e.first_hostname GROUP BY s.split ORDER BY s.split"
        )
    }
    labels_by_split: dict[str, dict[str, int]] = {}
    for split, label, count in conn.execute(
        "SELECT s.split,e.first_label,COUNT(*) FROM sampled_uid e JOIN split_hosts s ON s.hostname=e.first_hostname GROUP BY s.split,e.first_label ORDER BY s.split,e.first_label"
    ):
        labels_by_split.setdefault(str(split), {})[str(label)] = int(count)

    sampled_join = {
        "sample_mod": sample_mod,
        "expected_sample_fraction": 1.0 / sample_mod,
        "sampled_unique_ecar_uid": sample_unique,
        "sampled_unique_uid_seen_in_bro": sample_matched,
        "estimated_match_rate_over_ecar_uid": sample_matched / sample_unique if sample_unique else 0.0,
        "sampled_uid_with_hostname": host_known,
        "sampled_hostname_coverage": host_known / sample_unique if sample_unique else 0.0,
        "sampled_uid_mapped_to_frozen_split": split_known,
        "sampled_split_coverage": split_known / sample_unique if sample_unique else 0.0,
        "sampled_split_counts": split_counts,
        "sampled_label_counts_by_split": labels_by_split,
        "sampled_uid_duplicate_in_ecar": int(conn.execute("SELECT COUNT(*) FROM sampled_uid WHERE occurrence_count>1").fetchone()[0]),
        "sampled_uid_hostname_conflicts": int(conn.execute("SELECT COUNT(*) FROM sampled_uid WHERE hostname_conflict<>0").fetchone()[0]),
        "sampled_uid_ecar_label_conflicts": int(conn.execute("SELECT COUNT(*) FROM sampled_uid WHERE label_conflict<>0").fetchone()[0]),
        "sampled_uid_bro_label_conflicts": int(conn.execute("SELECT COUNT(*) FROM sampled_uid WHERE bro_label_conflict<>0").fetchone()[0]),
    }

    all_done = ecar["files_completed"] == ecar_files and bro["files_completed"] == bro_files
    ready = all_done and sample_unique >= 1000 and sample_matched > 0 and split_known > 0

    return {
        "generated_at": now_iso(),
        "script_version": SCRIPT_VERSION,
        "profiling_policy": {
            "full_scan_all_files": True,
            "full_uid_index": False,
            "uid_join_method": "deterministic_hash_sample",
            "sample_rule": f"blake2b64(uid) % {sample_mod} == 0",
            "reason": "Avoid tens of GB of temporary UID index in STEP 04A. Exact all-record join is deferred to STEP 04B where the joined table is materialized once.",
        },
        "backends": {
            "json": "orjson" if _orjson is not None else "stdlib-json",
            "gzip": "isal.igzip" if _igzip is not None else "stdlib-gzip",
        },
        "inputs": {
            "frozen_manifest": str(manifest),
            "frozen_manifest_sha256": manifest_sha,
            "ecar_bro_files_discovered": ecar_files,
            "bro_files_discovered": bro_files,
        },
        "ecar_bro": ecar,
        "bro": bro,
        "sampled_join": sampled_join,
        "top_values": {
            "ecar_action": top_values(conn, "ecar_bro", "action"),
            "ecar_object": top_values(conn, "ecar_bro", "object"),
            "ecar_label": top_values(conn, "ecar_bro", "label"),
            "ecar_app": top_values(conn, "ecar_bro", "app"),
            "ecar_direction": top_values(conn, "ecar_bro", "direction"),
            "ecar_protocol": top_values(conn, "ecar_bro", "protocol"),
            "ecar_top_fields": top_values(conn, "ecar_bro", "top_field", 200),
            "ecar_property_fields": top_values(conn, "ecar_bro", "property_field", 300),
            "bro_fields": top_values(conn, "bro", "field", 200),
            "bro_proto": top_values(conn, "bro", "proto"),
            "bro_service": top_values(conn, "bro", "service"),
            "bro_conn_state": top_values(conn, "bro", "conn_state"),
            "bro_label": top_values(conn, "bro", "label"),
        },
        "decision_gate": {
            "status": "READY_FOR_REVIEW" if ready else "NOT_READY",
            "note": "Join rate in STEP 04A FAST V2 is a deterministic-sample estimate. Exact full join is intentionally performed once in STEP 04B.",
        },
    }


def write_md(path: Path, report: dict[str, Any], db_path: Path) -> None:
    e = report["ecar_bro"]
    b = report["bro"]
    j = report["sampled_join"]
    pct = lambda x: f"{100*x:.3f}%"
    lines = [
        "# STEP 04A FAST V2 — Profile dữ liệu Network (Bro + eCAR-Bro)", "",
        "## Trạng thái", "", f"**{report['decision_gate']['status']}**", "",
        "## Mục tiêu", "",
        "Quét toàn bộ Bro và eCAR-Bro để hiểu schema, label, hostname và khả năng join trước khi tạo Network DL dataset.", "",
        "STEP 04A chỉ là profiling gate. Exact full join được thực hiện ở STEP 04B để tránh làm công việc nặng hai lần.", "",
        "## Vì sao dùng FAST V2", "",
        "- V1 lưu mọi `bro_uid`/`uid` vào SQLite nên DB tăng rất nhanh.",
        "- FAST V2 vẫn đọc **toàn bộ raw files**, nhưng chỉ lưu deterministic sample của UID.",
        f"- Sampling rule: `{report['profiling_policy']['sample_rule']}` (~{100/report['sampled_join']['sample_mod']:.3f}%).",
        "- Exact all-record join được để sang STEP 04B, khi joined event table được materialize và dùng trực tiếp cho DL.", "",
        "## Leakage boundary", "",
        "- Frozen STEP 02 manifest được verify bằng SHA-256.",
        "- Không random split event.",
        "- STEP 04A chưa fit category map, scaler hay model.",
        "- TRAIN-only preprocessing statistics sẽ fit ở STEP 04C.", "",
        "## Full scan", "",
        f"- eCAR-Bro files: **{e['files_completed']:,}/{report['inputs']['ecar_bro_files_discovered']:,}**",
        f"- eCAR-Bro records: **{e['records']:,}**; parse errors: **{e['parse_errors']:,}**",
        f"- Bro files: **{b['files_completed']:,}/{report['inputs']['bro_files_discovered']:,}**",
        f"- Bro records: **{b['records']:,}**; parse errors: **{b['parse_errors']:,}**", "",
        "## Deterministic sampled UID join", "",
        f"- Sampled unique eCAR-Bro UID: **{j['sampled_unique_ecar_uid']:,}**",
        f"- Sampled UID seen in Bro: **{j['sampled_unique_uid_seen_in_bro']:,}**",
        f"- Estimated match rate: **{pct(j['estimated_match_rate_over_ecar_uid'])}**",
        f"- Sampled hostname coverage: **{pct(j['sampled_hostname_coverage'])}**",
        f"- Sampled frozen-split coverage: **{pct(j['sampled_split_coverage'])}**",
        f"- Sampled split counts: `{json.dumps(j['sampled_split_counts'], ensure_ascii=False)}`",
        f"- Sampled labels by split: `{json.dumps(j['sampled_label_counts_by_split'], ensure_ascii=False)}`", "",
        "## Conflict diagnostics trên UID sample", "",
        f"- Duplicate sampled UID trong eCAR-Bro: **{j['sampled_uid_duplicate_in_ecar']:,}**",
        f"- Hostname conflict: **{j['sampled_uid_hostname_conflicts']:,}**",
        f"- eCAR label conflict: **{j['sampled_uid_ecar_label_conflicts']:,}**",
        f"- Bro label conflict: **{j['sampled_uid_bro_label_conflicts']:,}**", "",
        "## Runtime artifact", "",
        f"- Compact checkpoint DB: `{db_path}`",
        "- `network_join_profile_fast_v2.json` chứa report machine-readable.", "",
        "## Decision gate", "",
        "Review match rate, split coverage, label distribution, actual fields và conflict diagnostics trước STEP 04B.", "",
        "## Next step", "",
        "STEP 04B — build exact joined Network event table một lần và freeze Network feature contract.", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ecar-bro-root", required=True)
    ap.add_argument("--bro-root", required=True)
    ap.add_argument("--output-root", required=True)
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--manifest-sha256", default=None)
    ap.add_argument("--sample-mod", type=int, default=1000)
    ap.add_argument("--progress-every-records", type=int, default=1_000_000)
    ap.add_argument("--print-every-files", type=int, default=1)
    args = ap.parse_args()

    if args.sample_mod < 10:
        raise ValueError("--sample-mod must be >= 10")

    ecar_root = Path(args.ecar_bro_root)
    bro_root = Path(args.bro_root)
    output_root = Path(args.output_root)
    manifest = Path(args.manifest) if args.manifest else output_root / "02_artifacts" / "00_label_split_v1_1" / "split_manifest_frozen.csv"
    sha_file = Path(args.manifest_sha256) if args.manifest_sha256 else manifest.with_suffix(".sha256")

    for p in (ecar_root, bro_root, manifest, sha_file):
        if not p.exists():
            raise FileNotFoundError(p)

    artifact = output_root / "02_artifacts" / "01_network_profile_v2"
    artifact.mkdir(parents=True, exist_ok=True)
    db_path = artifact / "network_profile_fast_v2.sqlite3"
    json_path = artifact / "network_join_profile_fast_v2.json"
    md_path = artifact / "STEP_01_NETWORK_PROFILE.md"

    ecar_files = discover_gz(ecar_root)
    bro_files = discover_gz(bro_root)

    print("=" * 92)
    print("STEP 04A FAST V2 — Full scan + compact sampled UID profiling")
    print("=" * 92)
    print(f"[DISCOVER] eCAR-Bro={len(ecar_files):,} .gz | Bro={len(bro_files):,} .gz")
    print(f"[BACKENDS] json={'orjson' if _orjson else 'stdlib-json'} | gzip={'isal.igzip' if _igzip else 'stdlib-gzip'}")
    print(f"[UID SAMPLE] blake2b64(uid) % {args.sample_mod} == 0 (~{100/args.sample_mod:.3f}%)")
    print("[DB POLICY] No full UID index -> artifact stays small.")

    conn = connect_db(db_path)
    try:
        manifest_sha = load_frozen_split(conn, manifest, sha_file)
        md = meta(conn)
        old_version = md.get("script_version")
        old_mod = md.get("sample_mod")
        if old_version and old_version != SCRIPT_VERSION:
            raise RuntimeError(f"Checkpoint version mismatch DB={old_version} current={SCRIPT_VERSION}")
        if old_mod and int(old_mod) != args.sample_mod:
            raise RuntimeError(f"Checkpoint sample_mod={old_mod}, command sample_mod={args.sample_mod}")
        set_meta(conn, "script_version", SCRIPT_VERSION)
        set_meta(conn, "sample_mod", args.sample_mod)
        set_meta(conn, "updated_at", now_iso())
        conn.commit()

        completed = {str(r[0]) for r in conn.execute("SELECT absolute_path FROM file_stats")}

        print("[1/3] eCAR-Bro full scan")
        for i, path in enumerate(ecar_files, 1):
            if str(path) in completed:
                continue
            if args.print_every_files:
                print(f"  [ECAR {i:,}/{len(ecar_files):,}] {path}")
            profile_ecar(path, conn, i, args.progress_every_records, args.sample_mod)
            completed.add(str(path))

        sample_set = {str(r[0]) for r in conn.execute("SELECT uid FROM sampled_uid")}
        print(f"[SAMPLE IN RAM] {len(sample_set):,} unique sampled eCAR-Bro UID")

        print("[2/3] Bro/Zeek full scan")
        for i, path in enumerate(bro_files, 1):
            if str(path) in completed:
                continue
            if args.print_every_files:
                print(f"  [BRO {i:,}/{len(bro_files):,}] {path}")
            profile_bro(path, conn, i, args.progress_every_records, sample_set)
            completed.add(str(path))

        print("[3/3] Build compact report")
        report = build_report(
            conn,
            manifest=manifest,
            manifest_sha=manifest_sha,
            ecar_files=len(ecar_files),
            bro_files=len(bro_files),
            sample_mod=args.sample_mod,
        )
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        write_md(md_path, report, db_path)

        j = report["sampled_join"]
        print("=" * 92)
        print(f"[STATUS] {report['decision_gate']['status']}")
        print(f"[eCAR records] {report['ecar_bro']['records']:,}")
        print(f"[Bro records]  {report['bro']['records']:,}")
        print(f"[UID SAMPLE]   {j['sampled_unique_ecar_uid']:,}")
        print(f"[MATCHED]      {j['sampled_unique_uid_seen_in_bro']:,}")
        print(f"[MATCH RATE]   {100*j['estimated_match_rate_over_ecar_uid']:.3f}% (sample estimate)")
        print(f"[SPLIT COVER]  {100*j['sampled_split_coverage']:.3f}%")
        print(f"[DB]   {db_path}")
        print(f"[JSON] {json_path}")
        print(f"[MD]   {md_path}")
        print("=" * 92)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
