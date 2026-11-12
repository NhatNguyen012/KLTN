from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    import orjson as _orjson
except ImportError:
    _orjson = None

try:
    from isal import igzip as _igzip
except ImportError:
    _igzip = None


SCRIPT_VERSION = "step04b-network-exact-join-v1.0"
HOST_RE = re.compile(r"(?i)\b(sysclient\d{4})\b")

ECAR_SCHEMA_FIELDS = (
    "uid",
    "hostname",
    "split",
    "ecar_ts",
    "app_family",
    "direction",
    "ecar_l4protocol",
)

BRO_SCHEMA_FIELDS = (
    "uid",
    "bro_ts",
    "date",
    "orig_h",
    "orig_p",
    "resp_h",
    "resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "label",
)


def now_iso() -> str:
    return datetime.now().isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_loads(raw: bytes):
    if _orjson is not None:
        return _orjson.loads(raw)
    return json.loads(raw)


def open_gzip_binary(path: Path):
    if _igzip is not None:
        return _igzip.open(path, "rb")
    return gzip.open(path, "rb")


def open_gzip_text(path: Path):
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


def normalize_hostname(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    match = HOST_RE.search(text)
    return match.group(1).lower() if match else text


def app_basename(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().replace("/", "\\")
    return text.rsplit("\\", 1)[-1].lower() if text else ""


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in {"", "-", "(empty)", "null", "None"}:
        return None
    try:
        return int(text)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return None


def parse_float(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if text in {"", "-", "(empty)", "null", "None"}:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_label(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "attack", "malicious", "positive", "yes"}:
        return 1
    if text in {"0", "false", "benign", "negative", "no"}:
        return 0
    return None


def date_from_path(path: Path) -> str:
    for part in path.parts:
        if re.fullmatch(r"20\d{2}-\d{2}-\d{2}", part):
            return part
    match = re.search(r"(20\d{2}-\d{2}-\d{2})", path.name)
    return match.group(1) if match else ""


def parse_zeek_separator(line: str) -> str:
    value = line.split(" ", 1)[1].strip()
    if value == r"\x09":
        return "\t"
    if value.startswith(r"\x") and len(value) == 4:
        try:
            return bytes.fromhex(value[2:]).decode("latin1")
        except Exception:
            pass
    return value


def sql_path(path: Path) -> str:
    return str(path).replace("\\", "/").replace("'", "''")


def require_optional_packages():
    missing = []
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        missing.append("pyarrow")
    try:
        import duckdb  # noqa: F401
    except ImportError:
        missing.append("duckdb")

    if missing:
        joined = " ".join(missing)
        raise RuntimeError(
            "STEP 04B cần package để ghi Parquet và exact join.\n"
            f"Thiếu: {', '.join(missing)}\n"
            f"Chạy: python -m pip install {joined}"
        )


def load_split_map(manifest: Path, sha_file: Path) -> tuple[dict[str, str], str]:
    actual = sha256_file(manifest)
    expected = sha_file.read_text(encoding="utf-8").strip().split()[0].lower()
    if actual != expected:
        raise RuntimeError(
            "Frozen STEP 02 manifest SHA mismatch.\n"
            f"expected={expected}\nactual={actual}"
        )

    split_map: dict[str, str] = {}

    with manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            host = normalize_hostname(row.get("hostname"))
            split = (row.get("split") or "").strip().lower()

            if not host:
                continue
            if split not in {"train", "val", "test"}:
                raise RuntimeError(f"Unexpected split={split!r} for {host}")

            previous = split_map.get(host)
            if previous and previous != split:
                raise RuntimeError(f"Hostname leakage in frozen split: {host}")

            split_map[host] = split

    return split_map, actual


def load_04a_profile(profile_json: Path) -> dict[str, Any]:
    report = json.loads(profile_json.read_text(encoding="utf-8"))
    status = report.get("decision_gate", {}).get("status")

    if status != "READY_FOR_REVIEW":
        raise RuntimeError(
            f"STEP 04A report is not READY_FOR_REVIEW: {status!r}"
        )

    return report


def discover_conn_files_from_profile_db(profile_db: Path) -> list[Path]:
    conn = sqlite3.connect(str(profile_db))
    try:
        rows = conn.execute(
            """
            SELECT absolute_path
            FROM file_stats
            WHERE source='bro'
            ORDER BY absolute_path
            """
        ).fetchall()
    finally:
        conn.close()

    result: list[Path] = []

    for (raw_path,) in rows:
        path = Path(str(raw_path))
        if path.name.lower().startswith("conn."):
            result.append(path)

    if not result:
        raise RuntimeError("Không tìm thấy canonical Bro conn logs trong STEP 04A DB.")

    return result


def state_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=60.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=60000")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS metadata(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_files(
            source TEXT NOT NULL,
            absolute_path TEXT PRIMARY KEY,
            output_path TEXT NOT NULL,
            records INTEGER NOT NULL,
            parse_errors INTEGER NOT NULL,
            completed_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS phase_state(
            phase TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            detail TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn


def state_metadata(conn: sqlite3.Connection) -> dict[str, str]:
    return dict(conn.execute("SELECT key,value FROM metadata").fetchall())


def set_state_metadata(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO metadata(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def set_phase(conn: sqlite3.Connection, phase: str, status: str, detail: str = "") -> None:
    conn.execute(
        """
        INSERT INTO phase_state(phase,status,detail,updated_at)
        VALUES(?,?,?,?)
        ON CONFLICT(phase) DO UPDATE SET
            status=excluded.status,
            detail=excluded.detail,
            updated_at=excluded.updated_at
        """,
        (phase, status, detail, now_iso()),
    )
    conn.commit()


def get_phase(conn: sqlite3.Connection, phase: str) -> str | None:
    row = conn.execute(
        "SELECT status FROM phase_state WHERE phase=?",
        (phase,),
    ).fetchone()
    return str(row[0]) if row else None


def processed_paths(conn: sqlite3.Connection, source: str) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT absolute_path FROM processed_files WHERE source=?",
            (source,),
        )
    }


def mark_processed(
    conn: sqlite3.Connection,
    *,
    source: str,
    raw_path: Path,
    output_path: Path,
    records: int,
    parse_errors: int,
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO processed_files(
            source,absolute_path,output_path,records,parse_errors,completed_at
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            source,
            str(raw_path),
            str(output_path),
            int(records),
            int(parse_errors),
            now_iso(),
        ),
    )
    conn.commit()


def write_table_batch(writer, schema, columns: dict[str, list[Any]]) -> int:
    import pyarrow as pa

    if not columns:
        return 0

    first = next(iter(columns.values()))
    n = len(first)
    if n == 0:
        return 0

    arrays = []
    for field in schema:
        arrays.append(pa.array(columns[field.name], type=field.type))

    table = pa.Table.from_arrays(arrays, schema=schema)
    writer.write_table(table)
    return n


def ecar_schema():
    import pyarrow as pa

    return pa.schema([
        ("uid", pa.string()),
        ("hostname", pa.string()),
        ("split", pa.string()),
        ("ecar_ts", pa.int64()),
        ("app_family", pa.string()),
        ("direction", pa.string()),
        ("ecar_l4protocol", pa.string()),
    ])


def bro_schema():
    import pyarrow as pa

    return pa.schema([
        ("uid", pa.string()),
        ("bro_ts", pa.float64()),
        ("date", pa.string()),
        ("orig_h", pa.string()),
        ("orig_p", pa.int32()),
        ("resp_h", pa.string()),
        ("resp_p", pa.int32()),
        ("proto", pa.string()),
        ("service", pa.string()),
        ("duration", pa.float64()),
        ("orig_bytes", pa.int64()),
        ("resp_bytes", pa.int64()),
        ("conn_state", pa.string()),
        ("local_orig", pa.string()),
        ("local_resp", pa.string()),
        ("missed_bytes", pa.int64()),
        ("history", pa.string()),
        ("orig_pkts", pa.int64()),
        ("orig_ip_bytes", pa.int64()),
        ("resp_pkts", pa.int64()),
        ("resp_ip_bytes", pa.int64()),
        ("label", pa.int8()),
    ])


def scan_ecar_to_parquet(
    raw_path: Path,
    output_path: Path,
    split_map: dict[str, str],
    *,
    batch_rows: int,
    compression: str,
) -> tuple[int, int]:
    import pyarrow.parquet as pq

    schema = ecar_schema()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = output_path.with_suffix(output_path.suffix + ".building")
    if tmp_path.exists():
        tmp_path.unlink()

    columns = {name: [] for name in ECAR_SCHEMA_FIELDS}
    records = 0
    errors = 0

    writer = pq.ParquetWriter(
        tmp_path,
        schema,
        compression=compression,
        use_dictionary=["hostname", "split", "app_family", "direction", "ecar_l4protocol"],
        write_statistics=True,
    )

    try:
        with open_gzip_binary(raw_path) as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue

                try:
                    obj = json_loads(raw)
                except Exception:
                    errors += 1
                    continue

                if not isinstance(obj, dict):
                    errors += 1
                    continue

                props = obj.get("properties")
                if not isinstance(props, dict):
                    props = {}

                uid = str(props.get("bro_uid") or "").strip()
                if not uid:
                    continue

                hostname = normalize_hostname(obj.get("hostname"))
                split = split_map.get(hostname, "unmatched_split")
                app = app_basename(props.get("image_path"))
                direction = str(props.get("direction") or "").strip().lower()
                l4 = str(props.get("l4protocol") or props.get("protocol") or "").strip().lower()

                columns["uid"].append(uid)
                columns["hostname"].append(hostname)
                columns["split"].append(split)
                columns["ecar_ts"].append(parse_int(obj.get("timestamp")))
                columns["app_family"].append(app)
                columns["direction"].append(direction)
                columns["ecar_l4protocol"].append(l4)

                records += 1

                if len(columns["uid"]) >= batch_rows:
                    write_table_batch(writer, schema, columns)
                    columns = {name: [] for name in ECAR_SCHEMA_FIELDS}

        write_table_batch(writer, schema, columns)

    finally:
        writer.close()

    tmp_path.replace(output_path)
    return records, errors


def scan_bro_conn_to_parquet(
    raw_path: Path,
    output_path: Path,
    *,
    batch_rows: int,
    compression: str,
) -> tuple[int, int]:
    import pyarrow.parquet as pq

    schema = bro_schema()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = output_path.with_suffix(output_path.suffix + ".building")
    if tmp_path.exists():
        tmp_path.unlink()

    columns = {name: [] for name in BRO_SCHEMA_FIELDS}
    records = 0
    errors = 0
    date = date_from_path(raw_path)

    separator = "\t"
    fields: list[str] = []

    writer = pq.ParquetWriter(
        tmp_path,
        schema,
        compression=compression,
        use_dictionary=[
            "date", "proto", "service", "conn_state",
            "local_orig", "local_resp", "history",
        ],
        write_statistics=True,
    )

    try:
        with open_gzip_text(raw_path) as handle:
            for line in handle:
                line = line.rstrip("\r\n")
                if not line:
                    continue

                if line.startswith("#separator"):
                    separator = parse_zeek_separator(line)
                    continue

                if line.startswith("#fields"):
                    fields = line.split(separator)[1:]
                    if len(fields) <= 1:
                        fields = line.split()[1:]
                    continue

                if line.startswith("#"):
                    continue

                values = line.split(separator)

                if not fields or len(values) != len(fields):
                    errors += 1
                    continue

                row = dict(zip(fields, values))
                uid = str(row.get("uid") or "").strip()

                if not uid:
                    errors += 1
                    continue

                columns["uid"].append(uid)
                columns["bro_ts"].append(parse_float(row.get("ts")))
                columns["date"].append(date)
                columns["orig_h"].append(str(row.get("id.orig_h") or "").strip())
                columns["orig_p"].append(parse_int(row.get("id.orig_p")))
                columns["resp_h"].append(str(row.get("id.resp_h") or "").strip())
                columns["resp_p"].append(parse_int(row.get("id.resp_p")))
                columns["proto"].append(str(row.get("proto") or "").strip().lower())
                columns["service"].append(str(row.get("service") or "").strip().lower())
                columns["duration"].append(parse_float(row.get("duration")))
                columns["orig_bytes"].append(parse_int(row.get("orig_bytes")))
                columns["resp_bytes"].append(parse_int(row.get("resp_bytes")))
                columns["conn_state"].append(str(row.get("conn_state") or "").strip())
                columns["local_orig"].append(str(row.get("local_orig") or "").strip())
                columns["local_resp"].append(str(row.get("local_resp") or "").strip())
                columns["missed_bytes"].append(parse_int(row.get("missed_bytes")))
                columns["history"].append(str(row.get("history") or "").strip())
                columns["orig_pkts"].append(parse_int(row.get("orig_pkts")))
                columns["orig_ip_bytes"].append(parse_int(row.get("orig_ip_bytes")))
                columns["resp_pkts"].append(parse_int(row.get("resp_pkts")))
                columns["resp_ip_bytes"].append(parse_int(row.get("resp_ip_bytes")))
                columns["label"].append(parse_label(row.get("label")))

                records += 1

                if len(columns["uid"]) >= batch_rows:
                    write_table_batch(writer, schema, columns)
                    columns = {name: [] for name in BRO_SCHEMA_FIELDS}

        write_table_batch(writer, schema, columns)

    finally:
        writer.close()

    tmp_path.replace(output_path)
    return records, errors


def duckdb_connect(
    *,
    threads: int,
    memory_limit: str,
    temp_directory: Path,
):
    import duckdb

    temp_directory.mkdir(parents=True, exist_ok=True)
    db = duckdb.connect(database=":memory:")

    db.execute(f"PRAGMA threads={int(threads)}")
    db.execute(f"PRAGMA memory_limit='{memory_limit}'")
    db.execute(
        "SET temp_directory='{}'".format(sql_path(temp_directory))
    )
    db.execute("SET preserve_insertion_order=false")
    return db


def build_ecar_dedup(
    *,
    ecar_raw_glob: str,
    output_file: Path,
    threads: int,
    memory_limit: str,
    spill_dir: Path,
) -> dict[str, int]:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_output = output_file.with_suffix(".building.parquet")
    if tmp_output.exists():
        tmp_output.unlink()

    db = duckdb_connect(
        threads=threads,
        memory_limit=memory_limit,
        temp_directory=spill_dir,
    )

    try:
        source = ecar_raw_glob.replace("\\", "/").replace("'", "''")

        # One row per bro_uid. exact hostname conflict is preserved for validation.
        query = f"""
        COPY (
            SELECT
                uid,
                arg_min(hostname, COALESCE(ecar_ts, 9223372036854775807)) AS hostname,
                arg_min(split, COALESCE(ecar_ts, 9223372036854775807)) AS split,
                min(ecar_ts) AS ecar_ts,
                arg_min(app_family, COALESCE(ecar_ts, 9223372036854775807)) AS app_family,
                arg_min(direction, COALESCE(ecar_ts, 9223372036854775807)) AS direction,
                arg_min(ecar_l4protocol, COALESCE(ecar_ts, 9223372036854775807)) AS ecar_l4protocol,
                count(*)::BIGINT AS ecar_occurrence_count,
                (min(hostname) <> max(hostname)) AS hostname_conflict
            FROM read_parquet('{source}')
            GROUP BY uid
        )
        TO '{sql_path(tmp_output)}'
        (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 250000)
        """
        db.execute(query)

        stats = db.execute(
            f"""
            SELECT
                count(*)::BIGINT AS unique_uid,
                COALESCE(sum(ecar_occurrence_count),0)::BIGINT AS raw_rows,
                COALESCE(sum(CASE WHEN ecar_occurrence_count>1 THEN 1 ELSE 0 END),0)::BIGINT AS duplicate_uid,
                COALESCE(sum(CASE WHEN hostname_conflict THEN 1 ELSE 0 END),0)::BIGINT AS hostname_conflict_uid,
                COALESCE(sum(CASE WHEN split='unmatched_split' THEN 1 ELSE 0 END),0)::BIGINT AS unmatched_split_uid
            FROM read_parquet('{sql_path(tmp_output)}')
            """
        ).fetchone()

    finally:
        db.close()

    tmp_output.replace(output_file)

    return {
        "unique_uid": int(stats[0]),
        "raw_rows": int(stats[1]),
        "duplicate_uid": int(stats[2]),
        "hostname_conflict_uid": int(stats[3]),
        "unmatched_split_uid": int(stats[4]),
    }


def materialize_exact_join(
    *,
    bro_glob: str,
    ecar_dedup: Path,
    output_dir: Path,
    threads: int,
    memory_limit: str,
    spill_dir: Path,
) -> None:
    building = output_dir.parent / (output_dir.name + ".__building__")

    if building.exists():
        shutil.rmtree(building)

    building.mkdir(parents=True, exist_ok=True)

    db = duckdb_connect(
        threads=threads,
        memory_limit=memory_limit,
        temp_directory=spill_dir,
    )

    try:
        bro_source = bro_glob.replace("\\", "/").replace("'", "''")
        ecar_source = sql_path(ecar_dedup)

        query = f"""
        COPY (
            SELECT
                b.uid,
                b.bro_ts AS ts,
                b.date,
                e.hostname,
                e.split,
                b.label,

                e.app_family,
                e.direction,
                e.ecar_l4protocol,

                b.orig_h,
                b.orig_p,
                b.resp_h,
                b.resp_p,
                b.proto,
                b.service,
                b.duration,
                b.orig_bytes,
                b.resp_bytes,
                b.conn_state,
                b.local_orig,
                b.local_resp,
                b.missed_bytes,
                b.history,
                b.orig_pkts,
                b.orig_ip_bytes,
                b.resp_pkts,
                b.resp_ip_bytes,

                e.ecar_occurrence_count

            FROM read_parquet('{bro_source}') AS b
            INNER JOIN read_parquet('{ecar_source}') AS e
                ON b.uid = e.uid

            WHERE NOT e.hostname_conflict

            QUALIFY
                row_number() OVER (
                    PARTITION BY b.uid
                    ORDER BY b.bro_ts NULLS LAST, b.date
                ) = 1
        )
        TO '{sql_path(building)}'
        (
            FORMAT PARQUET,
            PARTITION_BY (split, date),
            COMPRESSION ZSTD,
            ROW_GROUP_SIZE 250000
        )
        """
        db.execute(query)

    finally:
        db.close()

    if output_dir.exists():
        shutil.rmtree(output_dir)

    building.replace(output_dir)


def summarize_joined(
    *,
    output_dir: Path,
    ecar_stats: dict[str, int],
    threads: int,
    memory_limit: str,
    spill_dir: Path,
) -> dict[str, Any]:
    db = duckdb_connect(
        threads=threads,
        memory_limit=memory_limit,
        temp_directory=spill_dir,
    )

    joined_glob = sql_path(output_dir / "**" / "*.parquet")

    try:
        total = int(
            db.execute(
                f"SELECT count(*) FROM read_parquet('{joined_glob}', hive_partitioning=true)"
            ).fetchone()[0]
        )

        split_rows = db.execute(
            f"""
            SELECT split,count(*)::BIGINT
            FROM read_parquet('{joined_glob}', hive_partitioning=true)
            GROUP BY split
            ORDER BY split
            """
        ).fetchall()

        label_rows = db.execute(
            f"""
            SELECT split,label,count(*)::BIGINT
            FROM read_parquet('{joined_glob}', hive_partitioning=true)
            GROUP BY split,label
            ORDER BY split,label
            """
        ).fetchall()

        app_rows = db.execute(
            f"""
            SELECT app_family,count(*)::BIGINT AS n
            FROM read_parquet('{joined_glob}', hive_partitioning=true)
            GROUP BY app_family
            ORDER BY n DESC
            LIMIT 50
            """
        ).fetchall()

        missing_label = int(
            db.execute(
                f"""
                SELECT count(*)
                FROM read_parquet('{joined_glob}', hive_partitioning=true)
                WHERE label IS NULL
                """
            ).fetchone()[0]
        )

    finally:
        db.close()

    by_split = {str(split): int(count) for split, count in split_rows}

    by_split_label: dict[str, dict[str, int]] = {}
    for split, label, count in label_rows:
        key = "missing" if label is None else str(int(label))
        by_split_label.setdefault(str(split), {})[key] = int(count)

    return {
        "joined_unique_uid_rows": total,
        "exact_join_rate_over_ecar_unique_uid": (
            total / ecar_stats["unique_uid"]
            if ecar_stats["unique_uid"]
            else 0.0
        ),
        "rows_by_split": by_split,
        "labels_by_split": by_split_label,
        "missing_label_rows": missing_label,
        "top_app_family": [
            {"value": str(app), "count": int(count)}
            for app, count in app_rows
        ],
    }


def feature_contract() -> dict[str, Any]:
    return {
        "version": "network-feature-contract-v1.0",
        "join_only_or_audit": [
            "uid",
            "hostname",
            "ts",
            "date",
            "split",
            "ecar_occurrence_count",
        ],
        "target_only": [
            "label",
        ],
        "categorical_candidates": [
            "app_family",
            "direction",
            "proto",
            "service",
            "conn_state",
            "local_orig",
            "local_resp",
        ],
        "numerical_candidates": [
            "duration",
            "orig_bytes",
            "resp_bytes",
            "missed_bytes",
            "orig_pkts",
            "orig_ip_bytes",
            "resp_pkts",
            "resp_ip_bytes",
        ],
        "graph_construction_only_initial": [
            "orig_h",
            "orig_p",
            "resp_h",
            "resp_p",
        ],
        "cross_source_validation_or_optional": [
            "ecar_l4protocol",
        ],
        "never_predictive_directly": [
            "uid",
            "hostname",
            "split",
            "label",
            "raw exact timestamp",
            "raw global IP identity as learned category",
        ],
        "next_step": {
            "step04c": (
                "Derive IP scope/port buckets and fit categorical maps + "
                "numeric log/scale statistics on TRAIN only."
            ),
            "step04d": (
                "Build shared (hostname,15-minute-window,chunk) graph/sequence samples."
            ),
        },
    }


def write_md(
    path: Path,
    *,
    status: str,
    report: dict[str, Any] | None,
    manifest: Path,
    manifest_sha: str,
    profile_json: Path,
    profile_db: Path,
    output_dir: Path,
    note: str,
) -> None:
    lines = [
        "# STEP 04B — Exact join Network (Bro conn + eCAR-Bro)",
        "",
        "## Trạng thái",
        "",
        f"**{status}**",
        "",
        "## Mục tiêu",
        "",
        "Tạo exact joined Network event table một lần để làm nguồn dữ liệu chuẩn cho Network DL.",
        "",
        "## Join là gì trong STEP này?",
        "",
        "`join` là ghép hai record từ hai nguồn khác nhau khi chúng cùng mô tả một network connection.",
        "",
        "Khóa join:",
        "",
        "```text",
        "eCAR-Bro.properties.bro_uid == Bro conn.uid",
        "```",
        "",
        "Bro cung cấp network statistics + target label; eCAR-Bro bổ sung hostname/application context.",
        "",
        "## Leakage boundary",
        "",
        "- Frozen STEP 02 hostname split được SHA-256 verify.",
        "- Không random split event.",
        "- Hostname không có trong frozen split được gán `unmatched_split`.",
        "- STEP 04B chưa fit category map/scaler.",
        "- `label` là target-only và không được dùng làm predictive feature.",
        "",
        "## Input",
        "",
        f"- Frozen manifest: `{manifest}`",
        f"- Manifest SHA-256: `{manifest_sha}`",
        f"- STEP 04A report: `{profile_json}`",
        f"- STEP 04A checkpoint DB: `{profile_db}`",
        "",
        "## Canonical Network event",
        "",
        "Chỉ dùng Bro `conn.*.log.gz` làm base connection table để tránh một UID bị nhân lên khi xuất hiện ở `ssl/http/dns/...`.",
        "",
        "## Output",
        "",
        f"- Joined dataset: `{output_dir}`",
        "- Parquet được partition theo `split/date`.",
        "- `unmatched_split` được giữ riêng để audit, không dùng baseline supervised training.",
        "",
    ]

    if report is not None:
        ecar = report["ecar_exact"]
        joined = report["joined"]
        lines.extend([
            "## Kết quả exact join",
            "",
            f"- eCAR raw rows: **{ecar['raw_rows']:,}**",
            f"- Unique eCAR `bro_uid`: **{ecar['unique_uid']:,}**",
            f"- Duplicate UID: **{ecar['duplicate_uid']:,}**",
            f"- Hostname-conflict UID: **{ecar['hostname_conflict_uid']:,}**",
            f"- Unmatched-split UID: **{ecar['unmatched_split_uid']:,}**",
            f"- Joined unique UID rows: **{joined['joined_unique_uid_rows']:,}**",
            f"- Exact join rate: **{100*joined['exact_join_rate_over_ecar_unique_uid']:.3f}%**",
            f"- Missing-label joined rows: **{joined['missing_label_rows']:,}**",
            f"- Rows by split: `{json.dumps(joined['rows_by_split'], ensure_ascii=False)}`",
            f"- Labels by split: `{json.dumps(joined['labels_by_split'], ensure_ascii=False)}`",
            "",
        ])

    lines.extend([
        "## Feature contract",
        "",
        "Predictive candidates:",
        "",
        "```text",
        "categorical: app_family, direction, proto, service, conn_state, local_orig, local_resp",
        "numerical: duration, orig_bytes, resp_bytes, missed_bytes,",
        "           orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes",
        "```",
        "",
        "Join/audit only:",
        "",
        "```text",
        "uid, hostname, ts, date, split",
        "```",
        "",
        "Graph construction only ban đầu:",
        "",
        "```text",
        "orig_h, orig_p, resp_h, resp_p",
        "```",
        "",
        "## Note",
        "",
        note,
        "",
        "## Next step",
        "",
        "STEP 04C — derive semantic network categories và fit category maps/numeric scaler trên TRAIN only.",
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ecar-bro-root", required=True)
    parser.add_argument("--output-root", required=True)

    parser.add_argument("--manifest", default=None)
    parser.add_argument("--manifest-sha256", default=None)

    parser.add_argument("--profile-json", default=None)
    parser.add_argument("--profile-db", default=None)

    parser.add_argument("--batch-rows", type=int, default=250_000)
    parser.add_argument("--parquet-compression", default="zstd")
    parser.add_argument("--threads", type=int, default=max(2, min(8, os.cpu_count() or 4)))
    parser.add_argument("--duckdb-memory-limit", default="8GB")
    parser.add_argument("--min-free-gib", type=float, default=35.0)
    parser.add_argument("--allow-low-disk", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")

    args = parser.parse_args()

    require_optional_packages()

    if args.batch_rows < 10_000:
        raise ValueError("--batch-rows should be >= 10000")

    output_root = Path(args.output_root)
    ecar_root = Path(args.ecar_bro_root)

    manifest = (
        Path(args.manifest)
        if args.manifest
        else output_root / "02_artifacts" / "00_label_split_v1_1" / "split_manifest_frozen.csv"
    )
    sha_file = (
        Path(args.manifest_sha256)
        if args.manifest_sha256
        else manifest.with_suffix(".sha256")
    )

    profile_json = (
        Path(args.profile_json)
        if args.profile_json
        else output_root / "02_artifacts" / "01_network_profile_v2" / "network_join_profile_fast_v2.json"
    )
    profile_db = (
        Path(args.profile_db)
        if args.profile_db
        else output_root / "02_artifacts" / "01_network_profile_v2" / "network_profile_fast_v2.sqlite3"
    )

    artifact_dir = output_root / "02_artifacts" / "02_network_joined_v1"
    temp_dir = artifact_dir / "_temp"
    ecar_raw_dir = temp_dir / "ecar_raw"
    bro_raw_dir = temp_dir / "bro_conn_raw"
    spill_dir = temp_dir / "duckdb_spill"

    state_path = artifact_dir / "step04b_state.sqlite3"
    ecar_dedup_path = temp_dir / "ecar_dedup.parquet"

    joined_dir = artifact_dir / "joined"
    report_path = artifact_dir / "network_join_exact_report.json"
    contract_path = artifact_dir / "network_feature_contract.json"
    md_path = artifact_dir / "STEP_02_NETWORK_EXACT_JOIN.md"

    artifact_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    free_gib = shutil.disk_usage(output_root).free / (1024 ** 3)

    print("=" * 96)
    print("STEP 04B — Exact Network join")
    print("=" * 96)
    print(f"[FREE DISK] {free_gib:.2f} GiB")
    print(f"[ARTIFACT]  {artifact_dir}")
    print(f"[THREADS]   {args.threads}")
    print(f"[DUCKDB]    memory_limit={args.duckdb_memory_limit}")
    print()

    if free_gib < args.min_free_gib and not args.allow_low_disk:
        raise RuntimeError(
            f"Chỉ còn {free_gib:.2f} GiB free trên output drive. "
            f"STEP 04B yêu cầu ít nhất {args.min_free_gib:.2f} GiB theo policy hiện tại.\n"
            "Nếu bạn đã kiểm tra dung lượng và vẫn muốn chạy, thêm --allow-low-disk."
        )

    split_map, manifest_sha = load_split_map(manifest, sha_file)
    profile = load_04a_profile(profile_json)

    ecar_files = discover_gz(ecar_root)
    conn_files = discover_conn_files_from_profile_db(profile_db)

    print(f"[DISCOVER] eCAR-Bro files: {len(ecar_files):,}")
    print(f"[DISCOVER] Bro conn files: {len(conn_files):,}")
    print("[JOIN KEY] eCAR-Bro.properties.bro_uid == Bro conn.uid")
    print("[SPLIT]    inherited from frozen hostname split")
    print()

    state = state_db(state_path)

    try:
        old_meta = state_metadata(state)
        required_meta = {
            "script_version": SCRIPT_VERSION,
            "manifest_sha256": manifest_sha,
            "profile_json_sha256": sha256_file(profile_json),
            "profile_db_sha256": sha256_file(profile_db),
        }

        if old_meta:
            for key, value in required_meta.items():
                old = old_meta.get(key)
                if old and old != str(value):
                    raise RuntimeError(
                        f"STEP 04B checkpoint mismatch for {key}: "
                        f"DB={old!r}, current={str(value)!r}"
                    )

        for key, value in required_meta.items():
            set_state_metadata(state, key, value)

        set_state_metadata(state, "ecar_bro_root", str(ecar_root))
        set_state_metadata(state, "updated_at", now_iso())
        state.commit()

        write_md(
            md_path,
            status="RUNNING",
            report=None,
            manifest=manifest,
            manifest_sha=manifest_sha,
            profile_json=profile_json,
            profile_db=profile_db,
            output_dir=joined_dir,
            note="STEP 04B đang chạy. Có thể rerun cùng command để resume file-level materialization.",
        )

        # ------------------------------------------------------------------
        # Phase A1: eCAR-Bro -> compact Parquet
        # ------------------------------------------------------------------
        set_phase(state, "ecar_materialize", "RUNNING")
        completed_ecar = processed_paths(state, "ecar")

        for index, raw_path in enumerate(ecar_files, start=1):
            if str(raw_path) in completed_ecar:
                continue

            output_path = ecar_raw_dir / f"ecar_{index:04d}.parquet"
            print(f"[A1 ECAR {index:,}/{len(ecar_files):,}] {raw_path}")

            started = time.time()
            records, errors = scan_ecar_to_parquet(
                raw_path,
                output_path,
                split_map,
                batch_rows=args.batch_rows,
                compression=args.parquet_compression,
            )

            mark_processed(
                state,
                source="ecar",
                raw_path=raw_path,
                output_path=output_path,
                records=records,
                parse_errors=errors,
            )

            print(
                f"    [DONE] rows={records:,} errors={errors:,} "
                f"elapsed={time.time()-started:.1f}s"
            )

        set_phase(state, "ecar_materialize", "COMPLETED")

        # ------------------------------------------------------------------
        # Phase A2: exact global dedup by bro_uid
        # ------------------------------------------------------------------
        if get_phase(state, "ecar_dedup") != "COMPLETED":
            print()
            print("[A2] Exact global eCAR UID dedup...")

            set_phase(state, "ecar_dedup", "RUNNING")
            ecar_stats = build_ecar_dedup(
                ecar_raw_glob=str(ecar_raw_dir / "*.parquet"),
                output_file=ecar_dedup_path,
                threads=args.threads,
                memory_limit=args.duckdb_memory_limit,
                spill_dir=spill_dir,
            )

            if ecar_stats["hostname_conflict_uid"] > 0:
                set_phase(
                    state,
                    "ecar_dedup",
                    "FAILED_HOSTNAME_CONFLICT",
                    json.dumps(ecar_stats),
                )
                raise RuntimeError(
                    "Phát hiện exact bro_uid map sang nhiều hostname. "
                    "Không tiếp tục join tự động. Xem STEP 04B report/state."
                )

            set_phase(
                state,
                "ecar_dedup",
                "COMPLETED",
                json.dumps(ecar_stats),
            )

            if not args.keep_temp and ecar_raw_dir.exists():
                shutil.rmtree(ecar_raw_dir)

        else:
            detail = state.execute(
                "SELECT detail FROM phase_state WHERE phase='ecar_dedup'"
            ).fetchone()[0]
            ecar_stats = json.loads(detail)

        print(
            f"[A2 DONE] unique_uid={ecar_stats['unique_uid']:,} | "
            f"duplicate_uid={ecar_stats['duplicate_uid']:,} | "
            f"unmatched_split_uid={ecar_stats['unmatched_split_uid']:,}"
        )

        # ------------------------------------------------------------------
        # Phase B: Bro canonical conn -> compact Parquet
        # ------------------------------------------------------------------
        set_phase(state, "bro_conn_materialize", "RUNNING")
        completed_bro = processed_paths(state, "bro_conn")

        print()
        print("[B] Materialize canonical Bro conn rows...")

        for index, raw_path in enumerate(conn_files, start=1):
            if str(raw_path) in completed_bro:
                continue

            output_path = bro_raw_dir / f"conn_{index:04d}.parquet"
            print(f"[B CONN {index:,}/{len(conn_files):,}] {raw_path}")

            started = time.time()
            records, errors = scan_bro_conn_to_parquet(
                raw_path,
                output_path,
                batch_rows=args.batch_rows,
                compression=args.parquet_compression,
            )

            if errors:
                raise RuntimeError(
                    f"Canonical conn parser error in {raw_path}: {errors:,}. "
                    "STEP 04A had 0 conn errors, so stop for review."
                )

            mark_processed(
                state,
                source="bro_conn",
                raw_path=raw_path,
                output_path=output_path,
                records=records,
                parse_errors=errors,
            )

            print(
                f"    [DONE] rows={records:,} errors={errors:,} "
                f"elapsed={time.time()-started:.1f}s"
            )

        set_phase(state, "bro_conn_materialize", "COMPLETED")

        # ------------------------------------------------------------------
        # Phase C: exact join once
        # ------------------------------------------------------------------
        if get_phase(state, "exact_join") != "COMPLETED":
            print()
            print("[C] DuckDB exact UID join -> partitioned Parquet...")
            set_phase(state, "exact_join", "RUNNING")

            materialize_exact_join(
                bro_glob=str(bro_raw_dir / "*.parquet"),
                ecar_dedup=ecar_dedup_path,
                output_dir=joined_dir,
                threads=args.threads,
                memory_limit=args.duckdb_memory_limit,
                spill_dir=spill_dir,
            )

            set_phase(state, "exact_join", "COMPLETED")

        # ------------------------------------------------------------------
        # Phase D: exact report / feature contract
        # ------------------------------------------------------------------
        print()
        print("[D] Summarize exact joined dataset...")

        joined_stats = summarize_joined(
            output_dir=joined_dir,
            ecar_stats=ecar_stats,
            threads=args.threads,
            memory_limit=args.duckdb_memory_limit,
            spill_dir=spill_dir,
        )

        report = {
            "generated_at": now_iso(),
            "script_version": SCRIPT_VERSION,
            "inputs": {
                "frozen_manifest": str(manifest),
                "frozen_manifest_sha256": manifest_sha,
                "step04a_profile_json": str(profile_json),
                "step04a_profile_json_sha256": sha256_file(profile_json),
                "step04a_profile_db": str(profile_db),
                "ecar_bro_files": len(ecar_files),
                "bro_conn_files": len(conn_files),
            },
            "join_policy": {
                "key": "ecar_bro.properties.bro_uid == bro_conn.uid",
                "bro_source": "canonical conn logs only",
                "ecar_global_dedup": "one row per bro_uid; abort on hostname conflict",
                "bro_duplicate_policy": "keep earliest conn row per uid after exact join",
                "split_policy": "inherit frozen STEP 02 hostname split",
                "unknown_hostname_policy": "unmatched_split; excluded from baseline supervised training",
                "label_source": "Bro conn label",
            },
            "ecar_exact": ecar_stats,
            "joined": joined_stats,
            "feature_contract": feature_contract(),
            "output": {
                "joined_parquet_root": str(joined_dir),
                "partitioning": ["split", "date"],
            },
        }

        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        contract_path.write_text(
            json.dumps(feature_contract(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        write_md(
            md_path,
            status="COMPLETED — READY FOR REVIEW",
            report=report,
            manifest=manifest,
            manifest_sha=manifest_sha,
            profile_json=profile_json,
            profile_db=profile_db,
            output_dir=joined_dir,
            note=(
                "Exact joined Network event table đã được materialize. "
                "Chưa fit category map/scaler; chờ review STEP 04B trước STEP 04C."
            ),
        )

        set_phase(state, "report", "COMPLETED")

        if not args.keep_temp:
            if bro_raw_dir.exists():
                shutil.rmtree(bro_raw_dir)
            if ecar_dedup_path.exists():
                ecar_dedup_path.unlink()
            if spill_dir.exists():
                shutil.rmtree(spill_dir, ignore_errors=True)

        print()
        print("=" * 96)
        print("[SUCCESS] STEP 04B complete")
        print(f"[JOINED]      {joined_stats['joined_unique_uid_rows']:,}")
        print(
            f"[JOIN RATE]   "
            f"{100*joined_stats['exact_join_rate_over_ecar_unique_uid']:.3f}%"
        )
        print(f"[BY SPLIT]    {joined_stats['rows_by_split']}")
        print(f"[LABELS]      {joined_stats['labels_by_split']}")
        print(f"[MISSING LAB] {joined_stats['missing_label_rows']:,}")
        print(f"[REPORT]      {report_path}")
        print(f"[CONTRACT]    {contract_path}")
        print(f"[MD]          {md_path}")
        print("=" * 96)

    except KeyboardInterrupt:
        set_phase(
            state,
            "interrupted",
            "SAFE_TO_RESUME",
            "Rerun the same command. Completed raw files remain checkpointed.",
        )
        print("\n[INTERRUPTED] STEP 04B checkpoint preserved. Re-run same command.")
        raise SystemExit(130)

    finally:
        state.close()


if __name__ == "__main__":
    main()
