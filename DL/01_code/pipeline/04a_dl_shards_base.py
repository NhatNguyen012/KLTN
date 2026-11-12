from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import network_schema  # noqa: E402


SCRIPT_VERSION = "step04d-network-dl-shards-v1.0"
DATASET_VERSION = "network-dl-v1-15m"

DEFAULT_WINDOW_MINUTES = 15
DEFAULT_MAX_EVENTS = 512
DEFAULT_SHARD_MAX_EVENTS = 250_000

SUPERVISED_SPLITS = ("train", "val", "test")


def now_iso() -> str:
    return datetime.now().isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def sql_path(path: Path) -> str:
    return str(path).replace("\\", "/").replace("'", "''")


def sql_literal(text: str) -> str:
    return "'" + str(text).replace("'", "''") + "'"


def require_packages():
    missing = []
    try:
        import duckdb  # noqa
    except ImportError:
        missing.append("duckdb")
    try:
        import pyarrow  # noqa
    except ImportError:
        missing.append("pyarrow")

    if missing:
        raise RuntimeError(
            "STEP 04D thiếu package: "
            + ", ".join(missing)
            + "\nChạy: python -m pip install duckdb pyarrow numpy"
        )


def connect_duckdb(*, threads: int, memory_limit: str, temp_dir: Path):
    import duckdb

    temp_dir.mkdir(parents=True, exist_ok=True)

    db = duckdb.connect(database=":memory:")
    db.execute(f"PRAGMA threads={int(threads)}")
    db.execute(f"PRAGMA memory_limit='{memory_limit}'")
    db.execute(f"SET temp_directory='{sql_path(temp_dir)}'")
    db.execute("SET preserve_insertion_order=false")
    return db


def validate_frozen_preprocess(preprocess_dir: Path):
    maps_path = preprocess_dir / "network_category_maps.json"
    numeric_path = preprocess_dir / "network_numeric_stats.json"
    spec_path = preprocess_dir / "network_preprocess_spec.json"
    fp_path = preprocess_dir / "network_preprocess_fingerprint.json"

    for path in (maps_path, numeric_path, spec_path, fp_path):
        if not path.exists():
            raise FileNotFoundError(
                f"Thiếu frozen STEP 04C artifact: {path}"
            )

    maps = load_json(maps_path)
    numeric = load_json(numeric_path)
    spec = load_json(spec_path)
    fp = load_json(fp_path)

    checks = {
        "category_maps_sha256": sha256_file(maps_path),
        "numeric_stats_sha256": sha256_file(numeric_path),
        "preprocess_spec_sha256": sha256_file(spec_path),
    }

    for key, actual in checks.items():
        expected = fp.get(key)
        if expected != actual:
            raise RuntimeError(
                f"STEP 04C fingerprint mismatch for {key}:\n"
                f"expected={expected}\nactual={actual}"
            )

    if fp.get("fit_split") != "train":
        raise RuntimeError("Frozen STEP 04C is not TRAIN-only.")

    if fp.get("val_used_for_fit") is not False:
        raise RuntimeError("Frozen STEP 04C says VAL was used for fit.")

    if fp.get("test_used_for_fit") is not False:
        raise RuntimeError("Frozen STEP 04C says TEST was used for fit.")

    return maps, numeric, spec, fp, {
        "maps": maps_path,
        "numeric": numeric_path,
        "spec": spec_path,
        "fingerprint": fp_path,
    }


def normalize_cat_sql(column: str) -> str:
    return f"""
        CASE
            WHEN {column} IS NULL THEN '<MISSING>'
            WHEN trim(CAST({column} AS VARCHAR)) = '' THEN '<MISSING>'
            WHEN lower(trim(CAST({column} AS VARCHAR))) IN
                 ('-', '(empty)', 'null', 'none', 'nan') THEN '<MISSING>'
            ELSE lower(trim(CAST({column} AS VARCHAR)))
        END
    """.strip()


# Bang cong lay tu network_event_schema_v1.json (trung voi 08b, tranh hai ban sao lech nhau)
COMMON_PORTS = network_schema.common_ports(network_schema.load_schema())


def port_class_sql(column: str) -> str:
    parts = [
        f"WHEN {column} = {port} THEN 'PORT_{port}_{name}'"
        for port, name in sorted(COMMON_PORTS.items())
    ]

    return f"""
        CASE
            WHEN {column} IS NULL THEN '<MISSING>'
            {' '.join(parts)}
            WHEN {column} BETWEEN 0 AND 1023 THEN 'WELL_KNOWN_OTHER'
            WHEN {column} BETWEEN 1024 AND 49151 THEN 'REGISTERED'
            WHEN {column} BETWEEN 49152 AND 65535 THEN 'EPHEMERAL'
            ELSE 'OTHER'
        END
    """.strip()


def category_source_expr(field: str) -> str:
    if field == "resp_port_class":
        return port_class_sql("resp_p")

    if field in {
        "app_family",
        "direction",
        "proto",
        "service",
        "conn_state",
        "local_orig",
        "local_resp",
    }:
        return normalize_cat_sql(field)

    raise RuntimeError(
        f"STEP 04D v1.0 does not implement active categorical field {field!r}. "
        "Create a new version rather than silently changing semantics."
    )


def category_id_expr(field: str, mapping: dict[str, int]) -> str:
    src = category_source_expr(field)

    cases = []
    for value, idx in sorted(mapping.items(), key=lambda item: item[1]):
        cases.append(
            f"WHEN {sql_literal(value)} THEN {int(idx)}"
        )

    return f"""
        CASE ({src})
            {' '.join(cases)}
            ELSE 0
        END
    """.strip()


def numeric_value_expr(
    field: str,
    *,
    mean: float,
    scale: float,
    clip_abs: float,
) -> str:
    if scale <= 0:
        raise RuntimeError(f"Invalid scale for {field}: {scale}")

    return f"""
        CASE
            WHEN {field} IS NULL OR {field} < 0 THEN 0.0
            ELSE least(
                {float(clip_abs)},
                greatest(
                    {-float(clip_abs)},
                    (
                        ln(1.0 + CAST({field} AS DOUBLE))
                        - ({float(mean)})
                    ) / ({float(scale)})
                )
            )
        END
    """.strip()


def numeric_missing_expr(field: str) -> str:
    return f"""
        CASE
            WHEN {field} IS NULL OR {field} < 0 THEN 1
            ELSE 0
        END
    """.strip()


def partition_dirs(joined_root: Path, split: str) -> list[tuple[str, Path]]:
    split_dir = joined_root / f"split={split}"

    if not split_dir.exists():
        raise FileNotFoundError(split_dir)

    result = []

    for path in sorted(split_dir.glob("date=*")):
        if not path.is_dir():
            continue

        date = path.name.split("=", 1)[1]
        if not list(path.glob("*.parquet")):
            continue

        result.append((date, path))

    if not result:
        raise RuntimeError(f"No date partitions found for split={split}")

    return result


def build_partition_query(
    *,
    parquet_glob: Path,
    active_cat: list[str],
    active_num: list[str],
    maps: dict[str, Any],
    numeric: dict[str, Any],
    window_seconds: int,
    max_events: int,
) -> str:
    cat_select = []
    for field in active_cat:
        mapping = maps["fields"][field]["mapping"]
        cat_select.append(
            f"{category_id_expr(field, mapping)}::USMALLINT AS cat_{field}"
        )

    clip_abs = float(
        numeric.get(
            "zscore_clip_abs",
            10.0,
        )
    )

    num_select = []
    miss_select = []

    for field in active_num:
        info = numeric["features"][field]
        num_select.append(
            f"""
            {numeric_value_expr(
                field,
                mean=float(info["log1p_mean"]),
                scale=float(info["scale_used"]),
                clip_abs=clip_abs,
            )}::FLOAT AS num_{field}
            """.strip()
        )
        miss_select.append(
            f"{numeric_missing_expr(field)}::UTINYINT AS miss_{field}"
        )

    source = sql_path(parquet_glob)

    app_field = "app_family"
    if app_field not in active_cat:
        raise RuntimeError(
            "`app_family` must remain active because graph APP nodes "
            "need a frozen application category."
        )

    app_id_col = "cat_app_family"

    query = f"""
    WITH base AS (
        SELECT
            hostname,
            CAST(ts AS DOUBLE) AS ts,
            uid,
            CAST(label AS UTINYINT) AS label,
            resp_h,
            resp_p,
            missed_bytes,

            {", ".join(cat_select)},

            {", ".join(num_select)},

            {", ".join(miss_select)},

            CASE
                WHEN missed_bytes IS NOT NULL AND missed_bytes > 0
                    THEN 1
                ELSE 0
            END::UTINYINT AS bin_has_missed_bytes

        FROM read_parquet('{source}')
        WHERE
            hostname IS NOT NULL
            AND trim(hostname) <> ''
            AND ts IS NOT NULL
            AND label IS NOT NULL
    ),

    windowed AS (
        SELECT
            *,
            CAST(
                floor(ts / {int(window_seconds)}) * {int(window_seconds)}
                AS BIGINT
            ) AS window_start
        FROM base
    ),

    numbered AS (
        SELECT
            *,
            (
                row_number() OVER (
                    PARTITION BY hostname, window_start
                    ORDER BY ts, uid
                ) - 1
            )::BIGINT AS rn
        FROM windowed
    ),

    chunked AS (
        SELECT
            *,
            CAST(floor(rn / {int(max_events)}) AS INTEGER) AS chunk_index,
            CAST(rn % {int(max_events)} AS INTEGER) AS event_pos
        FROM numbered
    ),

    local_ids AS (
        SELECT
            *,
            (
                dense_rank() OVER (
                    PARTITION BY hostname, window_start, chunk_index
                    ORDER BY {app_id_col}
                ) - 1
            )::USMALLINT AS app_local_id,

            (
                dense_rank() OVER (
                    PARTITION BY hostname, window_start, chunk_index
                    ORDER BY COALESCE(resp_h, '<MISSING>')
                ) - 1
            )::USMALLINT AS remote_local_id
        FROM chunked
    ),

    timed AS (
        SELECT
            *,
            lag(ts) OVER (
                PARTITION BY hostname, window_start, chunk_index
                ORDER BY event_pos
            ) AS prev_ts
        FROM local_ids
    ),

    grouped AS (
        SELECT
            *,
            dense_rank() OVER (
                ORDER BY hostname, window_start, chunk_index
            )::BIGINT AS group_id,

            CASE
                WHEN prev_ts IS NULL THEN 0.0
                ELSE ln(
                    1.0 + greatest(
                        0.0,
                        ts - prev_ts
                    )
                )
            END::FLOAT AS delta_t_log1p

        FROM timed
    )

    SELECT
        group_id,
        hostname,
        window_start,
        chunk_index,
        event_pos,
        label,

        {", ".join(f"cat_{f}" for f in active_cat)},

        {", ".join(f"num_{f}" for f in active_num)},

        {", ".join(f"miss_{f}" for f in active_num)},

        bin_has_missed_bytes,
        delta_t_log1p,
        app_local_id,
        remote_local_id

    FROM grouped
    ORDER BY group_id, event_pos
    """

    return query


def arrow_to_numpy(batch, name: str, dtype):
    arr = batch.column(batch.schema.get_field_index(name))
    return np.asarray(arr.to_numpy(zero_copy_only=False), dtype=dtype)


def sample_id(
    *,
    split: str,
    hostname: str,
    window_start: int,
    chunk_index: int,
) -> str:
    raw = f"{split}|{hostname}|{window_start}|{chunk_index}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def quantile_from_hist(hist: list[int], q: float) -> int:
    total = sum(hist)
    if total <= 0:
        return 0

    target = max(1, math.ceil(total * q))
    running = 0

    for value, count in enumerate(hist):
        running += count
        if running >= target:
            return value

    return len(hist) - 1


class ShardWriter:
    def __init__(
        self,
        *,
        build_dir: Path,
        final_relative_prefix: str,
        split: str,
        date: str,
        active_cat: list[str],
        active_num: list[str],
        max_events_per_shard: int,
        compressed: bool,
    ):
        self.build_dir = build_dir
        self.final_relative_prefix = final_relative_prefix.replace("\\", "/")
        self.split = split
        self.date = date
        self.active_cat = active_cat
        self.active_num = active_num
        self.max_events_per_shard = max_events_per_shard
        self.compressed = compressed

        self.build_dir.mkdir(parents=True, exist_ok=True)

        self.shard_index = 0
        self.reset()

        self.manifest_path = self.build_dir / "partition_manifest.csv"
        self.manifest_handle = self.manifest_path.open(
            "w",
            newline="",
            encoding="utf-8",
        )

        self.manifest_fields = [
            "sample_id",
            "split",
            "date",
            "hostname",
            "window_start_epoch",
            "window_start_utc",
            "chunk_index",
            "label",
            "event_count",
            "positive_event_count",
            "app_node_count",
            "remote_node_count",
            "shard_file",
            "shard_sample_index",
        ]

        self.manifest_writer = csv.DictWriter(
            self.manifest_handle,
            fieldnames=self.manifest_fields,
        )
        self.manifest_writer.writeheader()

        self.sha_rows: list[tuple[str, str, int]] = []

        self.stats = {
            "samples": 0,
            "positive_samples": 0,
            "negative_samples": 0,
            "events": 0,
            "positive_events": 0,
            "windows": 0,
            "event_count_hist": [0] * 513,
            "app_nodes_total": 0,
            "remote_nodes_total": 0,
            "shards": 0,
        }

    def reset(self):
        self.x_cat: list[np.ndarray] = []
        self.x_num: list[np.ndarray] = []
        self.x_missing: list[np.ndarray] = []
        self.x_bin: list[np.ndarray] = []
        self.delta: list[np.ndarray] = []
        self.app_local: list[np.ndarray] = []
        self.remote_local: list[np.ndarray] = []

        self.sample_labels: list[int] = []
        self.sample_event_counts: list[int] = []
        self.sample_positive_event_counts: list[int] = []
        self.sample_app_counts: list[int] = []
        self.sample_remote_counts: list[int] = []
        self.sample_window_start: list[int] = []
        self.sample_chunk_index: list[int] = []

        self.pending_manifest_rows: list[dict[str, Any]] = []
        self.events_in_shard = 0

    def add_sample(self, sample: dict[str, Any]):
        n = int(sample["event_count"])

        if self.events_in_shard > 0 and (
            self.events_in_shard + n > self.max_events_per_shard
        ):
            self.flush()

        local_sample_index = len(self.sample_labels)

        self.x_cat.append(sample["x_cat"])
        self.x_num.append(sample["x_num"])
        self.x_missing.append(sample["x_missing"])
        self.x_bin.append(sample["x_bin"])
        self.delta.append(sample["delta_t_log1p"])
        self.app_local.append(sample["app_local_id"])
        self.remote_local.append(sample["remote_local_id"])

        self.sample_labels.append(int(sample["label"]))
        self.sample_event_counts.append(n)
        self.sample_positive_event_counts.append(
            int(sample["positive_event_count"])
        )
        self.sample_app_counts.append(int(sample["app_node_count"]))
        self.sample_remote_counts.append(int(sample["remote_node_count"]))
        self.sample_window_start.append(int(sample["window_start"]))
        self.sample_chunk_index.append(int(sample["chunk_index"]))

        shard_name = (
            f"{self.split}_{self.date}_"
            f"{self.shard_index:04d}.npz"
        )

        relative = (
            f"{self.final_relative_prefix}/{shard_name}"
        )

        try:
            dt = datetime.fromtimestamp(
                int(sample["window_start"]),
                tz=timezone.utc,
            ).isoformat()
        except Exception:
            dt = ""

        self.pending_manifest_rows.append({
            "sample_id": sample_id(
                split=self.split,
                hostname=sample["hostname"],
                window_start=int(sample["window_start"]),
                chunk_index=int(sample["chunk_index"]),
            ),
            "split": self.split,
            "date": self.date,
            "hostname": sample["hostname"],
            "window_start_epoch": int(sample["window_start"]),
            "window_start_utc": dt,
            "chunk_index": int(sample["chunk_index"]),
            "label": int(sample["label"]),
            "event_count": n,
            "positive_event_count": int(sample["positive_event_count"]),
            "app_node_count": int(sample["app_node_count"]),
            "remote_node_count": int(sample["remote_node_count"]),
            "shard_file": relative,
            "shard_sample_index": local_sample_index,
        })

        self.events_in_shard += n

        self.stats["samples"] += 1
        self.stats["events"] += n
        self.stats["positive_events"] += int(
            sample["positive_event_count"]
        )
        self.stats["app_nodes_total"] += int(sample["app_node_count"])
        self.stats["remote_nodes_total"] += int(sample["remote_node_count"])

        if int(sample["label"]) == 1:
            self.stats["positive_samples"] += 1
        else:
            self.stats["negative_samples"] += 1

        if int(sample["chunk_index"]) == 0:
            self.stats["windows"] += 1

        hist_index = min(512, n)
        self.stats["event_count_hist"][hist_index] += 1

    def flush(self):
        if not self.sample_labels:
            return

        shard_name = (
            f"{self.split}_{self.date}_"
            f"{self.shard_index:04d}.npz"
        )
        path = self.build_dir / shard_name

        event_counts = np.asarray(
            self.sample_event_counts,
            dtype=np.uint16,
        )

        offsets = np.empty(
            len(event_counts) + 1,
            dtype=np.int64,
        )
        offsets[0] = 0
        np.cumsum(
            event_counts.astype(np.int64),
            out=offsets[1:],
        )

        payload = {
            "x_cat": np.concatenate(self.x_cat, axis=0).astype(
                np.uint16, copy=False
            ),
            "x_num": np.concatenate(self.x_num, axis=0).astype(
                np.float32, copy=False
            ),
            "x_num_missing": np.concatenate(
                self.x_missing, axis=0
            ).astype(np.uint8, copy=False),
            "x_bin": np.concatenate(self.x_bin, axis=0).astype(
                np.uint8, copy=False
            ),
            "delta_t_log1p": np.concatenate(
                self.delta, axis=0
            ).astype(np.float32, copy=False),
            "edge_app_local": np.concatenate(
                self.app_local, axis=0
            ).astype(np.uint16, copy=False),
            "edge_remote_local": np.concatenate(
                self.remote_local, axis=0
            ).astype(np.uint16, copy=False),

            "sample_offsets": offsets,
            "sample_labels": np.asarray(
                self.sample_labels,
                dtype=np.uint8,
            ),
            "sample_event_counts": event_counts,
            "sample_positive_event_counts": np.asarray(
                self.sample_positive_event_counts,
                dtype=np.uint16,
            ),
            "sample_app_node_counts": np.asarray(
                self.sample_app_counts,
                dtype=np.uint16,
            ),
            "sample_remote_node_counts": np.asarray(
                self.sample_remote_counts,
                dtype=np.uint16,
            ),
            "sample_window_start": np.asarray(
                self.sample_window_start,
                dtype=np.int64,
            ),
            "sample_chunk_index": np.asarray(
                self.sample_chunk_index,
                dtype=np.uint16,
            ),

            "categorical_feature_names": np.asarray(
                self.active_cat,
                dtype="U64",
            ),
            "numerical_feature_names": np.asarray(
                self.active_num,
                dtype="U64",
            ),
            "binary_feature_names": np.asarray(
                ["has_missed_bytes"],
                dtype="U64",
            ),
        }

        if self.compressed:
            np.savez_compressed(path, **payload)
        else:
            np.savez(path, **payload)

        digest = sha256_file(path)
        self.sha_rows.append(
            (
                str(path.name),
                digest,
                path.stat().st_size,
            )
        )

        for row in self.pending_manifest_rows:
            self.manifest_writer.writerow(row)

        self.manifest_handle.flush()

        self.stats["shards"] += 1
        self.shard_index += 1
        self.reset()

    def close(self):
        self.flush()
        self.manifest_handle.close()

        hist = self.stats["event_count_hist"]
        samples = max(1, int(self.stats["samples"]))

        self.stats["event_count_mean"] = (
            self.stats["events"] / samples
        )
        self.stats["event_count_p50"] = quantile_from_hist(hist, 0.50)
        self.stats["event_count_p90"] = quantile_from_hist(hist, 0.90)
        self.stats["event_count_p95"] = quantile_from_hist(hist, 0.95)
        self.stats["event_count_p99"] = quantile_from_hist(hist, 0.99)
        self.stats["app_nodes_mean"] = (
            self.stats["app_nodes_total"] / samples
        )
        self.stats["remote_nodes_mean"] = (
            self.stats["remote_nodes_total"] / samples
        )

        return self.stats, self.sha_rows


def piece_from_batch(
    batch,
    start: int,
    end: int,
    active_cat: list[str],
    active_num: list[str],
) -> dict[str, Any]:
    def col(name: str):
        return batch.column(
            batch.schema.get_field_index(name)
        ).slice(start, end - start)

    hostname = str(col("hostname")[0].as_py())
    window_start = int(col("window_start")[0].as_py())
    chunk_index = int(col("chunk_index")[0].as_py())
    group_id = int(col("group_id")[0].as_py())

    labels = np.asarray(
        col("label").to_numpy(zero_copy_only=False),
        dtype=np.uint8,
    )

    x_cat = np.column_stack([
        np.asarray(
            col(f"cat_{field}").to_numpy(zero_copy_only=False),
            dtype=np.uint16,
        )
        for field in active_cat
    ])

    x_num = np.column_stack([
        np.asarray(
            col(f"num_{field}").to_numpy(zero_copy_only=False),
            dtype=np.float32,
        )
        for field in active_num
    ])

    x_missing = np.column_stack([
        np.asarray(
            col(f"miss_{field}").to_numpy(zero_copy_only=False),
            dtype=np.uint8,
        )
        for field in active_num
    ])

    x_bin = np.asarray(
        col("bin_has_missed_bytes").to_numpy(
            zero_copy_only=False
        ),
        dtype=np.uint8,
    ).reshape(-1, 1)

    delta = np.asarray(
        col("delta_t_log1p").to_numpy(
            zero_copy_only=False
        ),
        dtype=np.float32,
    )

    app_local = np.asarray(
        col("app_local_id").to_numpy(
            zero_copy_only=False
        ),
        dtype=np.uint16,
    )

    remote_local = np.asarray(
        col("remote_local_id").to_numpy(
            zero_copy_only=False
        ),
        dtype=np.uint16,
    )

    return {
        "group_id": group_id,
        "hostname": hostname,
        "window_start": window_start,
        "chunk_index": chunk_index,
        "labels": labels,
        "x_cat": x_cat,
        "x_num": x_num,
        "x_missing": x_missing,
        "x_bin": x_bin,
        "delta": delta,
        "app_local": app_local,
        "remote_local": remote_local,
    }


def merge_pieces(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    if (
        a["group_id"] != b["group_id"]
        or a["hostname"] != b["hostname"]
        or a["window_start"] != b["window_start"]
        or a["chunk_index"] != b["chunk_index"]
    ):
        raise RuntimeError("Attempted to merge different sample groups.")

    for key in (
        "labels",
        "x_cat",
        "x_num",
        "x_missing",
        "x_bin",
        "delta",
        "app_local",
        "remote_local",
    ):
        a[key] = np.concatenate([a[key], b[key]], axis=0)

    return a


def finalize_piece(piece: dict[str, Any]) -> dict[str, Any]:
    n = int(len(piece["labels"]))

    return {
        "hostname": piece["hostname"],
        "window_start": int(piece["window_start"]),
        "chunk_index": int(piece["chunk_index"]),
        "event_count": n,
        "positive_event_count": int(piece["labels"].sum()),
        "label": int(piece["labels"].max()) if n else 0,

        "x_cat": piece["x_cat"],
        "x_num": piece["x_num"],
        "x_missing": piece["x_missing"],
        "x_bin": piece["x_bin"],
        "delta_t_log1p": piece["delta"],

        "app_local_id": piece["app_local"],
        "remote_local_id": piece["remote_local"],

        "app_node_count": (
            int(piece["app_local"].max()) + 1
            if n else 0
        ),
        "remote_node_count": (
            int(piece["remote_local"].max()) + 1
            if n else 0
        ),
    }


def process_partition(
    *,
    split: str,
    date: str,
    partition_dir: Path,
    final_partition_dir: Path,
    active_cat: list[str],
    active_num: list[str],
    maps: dict[str, Any],
    numeric: dict[str, Any],
    window_seconds: int,
    max_events: int,
    shard_max_events: int,
    compressed_npz: bool,
    threads: int,
    memory_limit: str,
    arrow_batch_rows: int,
    spill_dir: Path,
) -> dict[str, Any]:
    success_file = final_partition_dir / "_SUCCESS.json"

    if success_file.exists():
        print(
            f"[SKIP] split={split} date={date} already completed."
        )
        return load_json(success_file)

    building = final_partition_dir.parent / (
        final_partition_dir.name + ".__building__"
    )

    if building.exists():
        shutil.rmtree(building)

    building.mkdir(parents=True, exist_ok=True)

    relative_prefix = (
        f"shards/{split}/date={date}"
    )

    writer = ShardWriter(
        build_dir=building,
        final_relative_prefix=relative_prefix,
        split=split,
        date=date,
        active_cat=active_cat,
        active_num=active_num,
        max_events_per_shard=shard_max_events,
        compressed=compressed_npz,
    )

    db = connect_duckdb(
        threads=threads,
        memory_limit=memory_limit,
        temp_dir=spill_dir / f"{split}_{date}",
    )

    parquet_glob = partition_dir / "*.parquet"

    query = build_partition_query(
        parquet_glob=parquet_glob,
        active_cat=active_cat,
        active_num=active_num,
        maps=maps,
        numeric=numeric,
        window_seconds=window_seconds,
        max_events=max_events,
    )

    pending: dict[str, Any] | None = None

    try:
        cursor = db.execute(query)

        reader = cursor.fetch_record_batch(
            rows_per_batch=arrow_batch_rows
        )

        for batch in reader:
            gids = arrow_to_numpy(
                batch,
                "group_id",
                np.int64,
            )

            if len(gids) == 0:
                continue

            boundaries = np.flatnonzero(
                gids[1:] != gids[:-1]
            ) + 1

            starts = np.concatenate(
                [np.asarray([0]), boundaries]
            )
            ends = np.concatenate(
                [boundaries, np.asarray([len(gids)])]
            )

            for start, end in zip(starts, ends):
                piece = piece_from_batch(
                    batch,
                    int(start),
                    int(end),
                    active_cat,
                    active_num,
                )

                if pending is None:
                    pending = piece
                    continue

                if pending["group_id"] == piece["group_id"]:
                    pending = merge_pieces(pending, piece)
                    continue

                sample = finalize_piece(pending)

                if sample["event_count"] > max_events:
                    raise RuntimeError(
                        f"Chunk > MAX_EVENTS: {sample['event_count']}"
                    )

                writer.add_sample(sample)
                pending = piece

        if pending is not None:
            sample = finalize_piece(pending)

            if sample["event_count"] > max_events:
                raise RuntimeError(
                    f"Chunk > MAX_EVENTS: {sample['event_count']}"
                )

            writer.add_sample(sample)

    finally:
        db.close()
        shutil.rmtree(
            spill_dir / f"{split}_{date}",
            ignore_errors=True,
        )

    stats, sha_rows = writer.close()

    partition_report = {
        "completed_at": now_iso(),
        "split": split,
        "date": date,
        "source": str(partition_dir),
        "window_seconds": window_seconds,
        "max_events_per_sample": max_events,
        "compressed_npz": compressed_npz,
        "active_categorical_features": active_cat,
        "active_numerical_features": active_num,
        "binary_features": ["has_missed_bytes"],
        "stats": stats,
        "shards": [
            {
                "file": f"{relative_prefix}/{name}",
                "sha256": digest,
                "size_bytes": size,
            }
            for name, digest, size in sha_rows
        ],
    }

    dump_json(
        building / "_SUCCESS.json",
        partition_report,
    )

    if final_partition_dir.exists():
        shutil.rmtree(final_partition_dir)

    building.replace(final_partition_dir)

    return partition_report


def merge_partition_manifests(
    *,
    dataset_root: Path,
    partition_reports: list[dict[str, Any]],
) -> Path:
    output_dir = dataset_root / "split"
    output_dir.mkdir(parents=True, exist_ok=True)

    output = output_dir / "network_sample_manifest.csv"

    fieldnames = [
        "sample_id",
        "split",
        "date",
        "hostname",
        "window_start_epoch",
        "window_start_utc",
        "chunk_index",
        "label",
        "event_count",
        "positive_event_count",
        "app_node_count",
        "remote_node_count",
        "shard_file",
        "shard_sample_index",
    ]

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as out:
        writer = csv.DictWriter(
            out,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for report in sorted(
            partition_reports,
            key=lambda r: (r["split"], r["date"]),
        ):
            path = (
                dataset_root
                / "shards"
                / report["split"]
                / f"date={report['date']}"
                / "partition_manifest.csv"
            )

            with path.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as inp:
                for row in csv.DictReader(inp):
                    writer.writerow(row)

    return output


def aggregate_stats(
    partition_reports: list[dict[str, Any]],
) -> dict[str, Any]:
    split_stats: dict[str, Any] = {}

    for split in SUPERVISED_SPLITS:
        reports = [
            r
            for r in partition_reports
            if r["split"] == split
        ]

        hist = [0] * 513
        totals = Counter()

        for report in reports:
            stats = report["stats"]

            for key in (
                "samples",
                "positive_samples",
                "negative_samples",
                "events",
                "positive_events",
                "windows",
                "app_nodes_total",
                "remote_nodes_total",
                "shards",
            ):
                totals[key] += int(stats[key])

            for i, count in enumerate(
                stats["event_count_hist"]
            ):
                hist[i] += int(count)

        samples = int(totals["samples"])
        positive = int(totals["positive_samples"])
        negative = int(totals["negative_samples"])

        split_stats[split] = {
            **dict(totals),
            "event_count_hist": hist,
            "positive_sample_rate": (
                positive / samples
                if samples else 0.0
            ),
            "pos_weight_neg_over_pos": (
                negative / positive
                if positive else None
            ),
            "event_count_mean": (
                totals["events"] / samples
                if samples else 0.0
            ),
            "event_count_p50": quantile_from_hist(hist, 0.50),
            "event_count_p90": quantile_from_hist(hist, 0.90),
            "event_count_p95": quantile_from_hist(hist, 0.95),
            "event_count_p99": quantile_from_hist(hist, 0.99),
            "app_nodes_mean": (
                totals["app_nodes_total"] / samples
                if samples else 0.0
            ),
            "remote_nodes_mean": (
                totals["remote_nodes_total"] / samples
                if samples else 0.0
            ),
        }

    return split_stats


def write_integrity(
    *,
    dataset_root: Path,
    partition_reports: list[dict[str, Any]],
    additional_paths: list[Path],
) -> Path:
    integrity_dir = dataset_root / "integrity"
    integrity_dir.mkdir(parents=True, exist_ok=True)

    rows = []

    for report in partition_reports:
        for shard in report["shards"]:
            rows.append(
                (
                    shard["sha256"],
                    shard["file"],
                    shard["size_bytes"],
                )
            )

    for path in additional_paths:
        rows.append(
            (
                sha256_file(path),
                str(path.relative_to(dataset_root)).replace("\\", "/"),
                path.stat().st_size,
            )
        )

    rows.sort(key=lambda x: x[1])

    path = integrity_dir / "sha256sums.txt"

    with path.open("w", encoding="utf-8") as f:
        for digest, relative, size in rows:
            f.write(
                f"{digest}  {relative}  {int(size)}\n"
            )

    return path


def copy_preprocess(
    *,
    dataset_root: Path,
    source_paths: dict[str, Path],
) -> list[Path]:
    out = dataset_root / "preprocessing"
    out.mkdir(parents=True, exist_ok=True)

    result = []

    name_map = {
        "maps": "network_category_maps.json",
        "numeric": "network_numeric_stats.json",
        "spec": "network_preprocess_spec.json",
        "fingerprint": "network_preprocess_fingerprint.json",
    }

    for key, dest_name in name_map.items():
        dest = out / dest_name
        shutil.copy2(source_paths[key], dest)
        result.append(dest)

    return result


def write_dataset_readme(
    *,
    path: Path,
    window_minutes: int,
    max_events: int,
    active_cat: list[str],
    active_num: list[str],
) -> None:
    content = f"""# Network DL Dataset v1 — {window_minutes}-minute windows

## Mục đích

Derived dataset dùng chung cho:

```text
GraphSAGE
GAT
BiLSTM
Mixed-Type Self-Attention
```

Raw DARPA OpTC không được upload trong package này.

## Sample unit

```text
(hostname, {window_minutes}-minute window, chunk_index)
```

Nếu một window có hơn `{max_events}` events, events được sort theo timestamp rồi chia thành chunk tối đa `{max_events}`.

Sample label:

```text
1 nếu chunk có >= 1 positive Bro network event
0 ngược lại
```

## Leakage policy

- TRAIN/VAL/TEST kế thừa frozen hostname split.
- Không random event split.
- Category maps/numeric statistics fit TRAIN only.
- `hostname` chỉ nằm trong manifest để audit/future fusion, không phải model feature.
- Raw global IP không nằm trong tensor model.
- Raw IP chỉ được dùng transiently để tạo `remote_local_id` bên trong từng sample.

## Sequence representation

Mỗi shard có packed arrays:

```text
x_cat
x_num
x_num_missing
x_bin
delta_t_log1p
sample_offsets
sample_labels
```

Active categorical:

```text
{chr(10).join(active_cat)}
```

Active numerical:

```text
{chr(10).join(active_num)}
```

Binary:

```text
has_missed_bytes
```

## Graph representation

Cùng events của sequence view được dùng cho graph view.

Shard có:

```text
edge_app_local
edge_remote_local
sample_app_node_counts
sample_remote_node_counts
```

Mỗi event tạo một APP -> REMOTE_ENDPOINT local edge.

Khi train GraphSAGE/GAT có thể thêm reverse edge.

## Kaggle

Upload folder này dưới dạng private Kaggle Dataset.

Training notebook không cần raw 1 TB source.
"""
    path.write_text(content, encoding="utf-8")


def write_step_md(
    *,
    path: Path,
    dataset_root: Path,
    split_stats: dict[str, Any],
    window_minutes: int,
    max_events: int,
    manifest_path: Path,
    preprocess_fingerprint: str,
) -> None:
    train = split_stats["train"]

    lines = [
        "# STEP 04D — Build shared Network DL samples",
        "",
        "## Trạng thái",
        "",
        "**COMPLETED — READY FOR KAGGLE VALIDATION**",
        "",
        "## Window baseline",
        "",
        f"- Window: **{window_minutes} phút**",
        f"- MAX_EVENTS/chunk: **{max_events}**",
        "- Window được align theo Unix timestamp.",
        "- Event trong mỗi host/window được sort theo `ts, uid`.",
        "- Window quá dài được chia chronological chunk.",
        "",
        "## Vì sao dùng 15 phút làm baseline?",
        "",
        "- Giữ attack locality tốt hơn 30 phút.",
        "- Ít trộn benign context không liên quan vào positive sample.",
        "- Sequence/attention ngắn hơn, giảm compute.",
        "- Có thể dùng 30 phút làm ablation sau khi baseline ổn.",
        "- Thiết kế này cũng nhất quán với 15-minute graph intervals đã dùng trong nghiên cứu OpTC/Kairos.",
        "",
        "## Shared representation",
        "",
        "Cùng một sample sinh ra cả:",
        "",
        "```text",
        "sequence view -> BiLSTM / Mixed-Type Self-Attention",
        "graph view    -> GraphSAGE / GAT",
        "```",
        "",
        "Do đó các model được so sánh trên cùng event population.",
        "",
        "## Split statistics",
        "",
    ]

    for split in SUPERVISED_SPLITS:
        s = split_stats[split]
        lines.extend([
            f"### {split.upper()}",
            "",
            f"- Samples: **{s['samples']:,}**",
            f"- Positive samples: **{s['positive_samples']:,}**",
            f"- Negative samples: **{s['negative_samples']:,}**",
            f"- Positive sample rate: **{s['positive_sample_rate']:.6%}**",
            f"- Events: **{s['events']:,}**",
            f"- Windows: **{s['windows']:,}**",
            f"- Mean events/sample: **{s['event_count_mean']:.2f}**",
            f"- P50/P95/P99 events: **{s['event_count_p50']} / {s['event_count_p95']} / {s['event_count_p99']}**",
            "",
        ])

    lines.extend([
        "## Class weight",
        "",
        "Final DL `pos_weight` phải tính ở sample level.",
        "",
        f"TRAIN candidate `negative / positive`: **{train['pos_weight_neg_over_pos']}**",
        "",
        "Không dùng event-level 04B ratio làm final DL class weight.",
        "",
        "## Leakage",
        "",
        "- Không dùng `unmatched_split` trong baseline supervised shards.",
        "- Không dùng hostname làm model feature.",
        "- Không lưu raw global IP trong model tensors.",
        "- Frozen STEP 04C preprocessing fingerprint đã được verify.",
        "",
        "## Output",
        "",
        f"- Kaggle dataset root: `{dataset_root}`",
        f"- Sample manifest: `{manifest_path}`",
        f"- Preprocess fingerprint: `{preprocess_fingerprint}`",
        "",
        "## Next step",
        "",
        "Validate Dataset/Dataloader locally hoặc trên Kaggle, sau đó train BiLSTM baseline trước.",
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--output-root", required=True)
    parser.add_argument("--joined-root", default=None)
    parser.add_argument("--preprocess-dir", default=None)
    parser.add_argument("--report04b", default=None)

    parser.add_argument(
        "--window-minutes",
        type=int,
        default=DEFAULT_WINDOW_MINUTES,
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=DEFAULT_MAX_EVENTS,
    )
    parser.add_argument(
        "--shard-max-events",
        type=int,
        default=DEFAULT_SHARD_MAX_EVENTS,
    )

    parser.add_argument(
        "--arrow-batch-rows",
        type=int,
        default=100_000,
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=max(2, min(8, os.cpu_count() or 4)),
    )
    parser.add_argument(
        "--duckdb-memory-limit",
        default="8GB",
    )

    parser.add_argument(
        "--compressed-npz",
        action="store_true",
        help=(
            "Use np.savez_compressed. Smaller files but slower CPU. "
            "Default uses uncompressed NPZ for faster materialization."
        ),
    )

    parser.add_argument(
        "--min-free-gib",
        type=float,
        default=20.0,
    )
    parser.add_argument(
        "--allow-low-disk",
        action="store_true",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
    )

    args = parser.parse_args()

    require_packages()

    if args.window_minutes <= 0:
        raise ValueError("--window-minutes must be > 0")

    if not (1 <= args.max_events <= 65535):
        raise ValueError("--max-events must be between 1 and 65535")

    output_root = Path(args.output_root)

    joined_root = (
        Path(args.joined_root)
        if args.joined_root
        else output_root
        / "02_artifacts"
        / "02_network_joined_v1"
        / "joined"
    )

    preprocess_dir = (
        Path(args.preprocess_dir)
        if args.preprocess_dir
        else output_root
        / "02_artifacts"
        / "03_network_preprocess_v1_1"
    )

    report04b_path = (
        Path(args.report04b)
        if args.report04b
        else output_root
        / "02_artifacts"
        / "02_network_joined_v1"
        / "network_join_exact_report.json"
    )

    dataset_root = (
        output_root
        / "03_datasets"
        / f"network_dl_v1_{args.window_minutes}m"
    )

    artifact_dir = (
        output_root
        / "02_artifacts"
        / f"step04d_network_dl_{args.window_minutes}m"
    )

    if args.reset:
        shutil.rmtree(dataset_root, ignore_errors=True)
        shutil.rmtree(artifact_dir, ignore_errors=True)

    dataset_root.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    if not joined_root.exists():
        raise FileNotFoundError(joined_root)

    if not report04b_path.exists():
        raise FileNotFoundError(report04b_path)

    free_gib = shutil.disk_usage(output_root).free / (1024 ** 3)

    if (
        free_gib < args.min_free_gib
        and not args.allow_low_disk
    ):
        raise RuntimeError(
            f"Only {free_gib:.2f} GiB free. "
            f"Need >= {args.min_free_gib:.2f} GiB by current policy. "
            "Use --allow-low-disk only after checking space."
        )

    maps, numeric, spec, preprocess_fp, preprocess_paths = (
        validate_frozen_preprocess(preprocess_dir)
    )

    active_cat = list(
        spec.get(
            "active_categorical_features",
            spec.get("categorical_features", []),
        )
    )

    active_num = list(
        spec.get(
            "active_numerical_features",
            spec.get("numerical_features", []),
        )
    )

    if not active_cat:
        raise RuntimeError("No active categorical features.")

    if not active_num:
        raise RuntimeError("No active numerical features.")

    if "app_family" not in active_cat:
        raise RuntimeError(
            "app_family must be active for APP graph nodes."
        )

    for field in active_cat:
        if field not in maps["fields"]:
            raise RuntimeError(
                f"Missing category map for {field}"
            )

        max_id = max(
            int(x)
            for x in maps["fields"][field]["mapping"].values()
        )

        if max_id > 65535:
            raise RuntimeError(
                f"{field} category id exceeds uint16."
            )

    report04b_sha = sha256_file(report04b_path)
    report04b = load_json(report04b_path)

    window_seconds = int(args.window_minutes * 60)

    build_config = {
        "script_version": SCRIPT_VERSION,
        "dataset_version": (
            DATASET_VERSION
            if args.window_minutes == 15
            else f"network-dl-v1-{args.window_minutes}m"
        ),
        "joined_root": str(joined_root),
        "report04b_sha256": report04b_sha,
        "preprocess_frozen_fingerprint":
            preprocess_fp["frozen_fingerprint_sha256"],
        "window_minutes": int(args.window_minutes),
        "window_seconds": window_seconds,
        "max_events": int(args.max_events),
        "shard_max_events": int(args.shard_max_events),
        "compressed_npz": bool(args.compressed_npz),
        "active_categorical_features": active_cat,
        "active_numerical_features": active_num,
        "binary_features": ["has_missed_bytes"],
        "label_rule": "chunk positive iff >=1 positive event",
        "split_policy": "frozen hostname split; supervised train/val/test only",
        "raw_ip_policy": (
            "Used transiently only for local remote-node IDs; "
            "raw IP is not written into model tensors."
        ),
    }

    config_path = dataset_root / "build_config.json"

    if config_path.exists():
        existing = load_json(config_path)

        if existing != build_config:
            raise RuntimeError(
                "Existing STEP 04D dataset has a different build config. "
                "Use a different --window-minutes/output or explicitly --reset."
            )
    else:
        dump_json(config_path, build_config)

    print("=" * 100)
    print("STEP 04D — Shared Network DL shards")
    print("=" * 100)
    print(f"[WINDOW] {args.window_minutes} min")
    print(f"[MAX EVENTS] {args.max_events}")
    print(f"[SHARD MAX] {args.shard_max_events:,} events")
    print(f"[NPZ] {'compressed' if args.compressed_npz else 'fast/uncompressed'}")
    print(f"[DATASET] {dataset_root}")
    print(f"[FREE DISK] {free_gib:.2f} GiB")
    print()
    print(f"[CAT] {active_cat}")
    print(f"[NUM] {active_num}")
    print("[BIN] ['has_missed_bytes']")
    print()

    shard_root = dataset_root / "shards"
    spill_root = artifact_dir / "_duckdb_spill"

    partition_reports = []

    for split in SUPERVISED_SPLITS:
        parts = partition_dirs(joined_root, split)

        for index, (date, partition_dir) in enumerate(parts, start=1):
            print(
                f"[{split.upper()} {index}/{len(parts)}] date={date}"
            )

            final_dir = (
                shard_root
                / split
                / f"date={date}"
            )

            report = process_partition(
                split=split,
                date=date,
                partition_dir=partition_dir,
                final_partition_dir=final_dir,
                active_cat=active_cat,
                active_num=active_num,
                maps=maps,
                numeric=numeric,
                window_seconds=window_seconds,
                max_events=args.max_events,
                shard_max_events=args.shard_max_events,
                compressed_npz=args.compressed_npz,
                threads=args.threads,
                memory_limit=args.duckdb_memory_limit,
                arrow_batch_rows=args.arrow_batch_rows,
                spill_dir=spill_root,
            )

            partition_reports.append(report)

            s = report["stats"]
            print(
                f"    [DONE] samples={s['samples']:,} | "
                f"positive={s['positive_samples']:,} | "
                f"events={s['events']:,} | "
                f"shards={s['shards']:,}"
            )

    shutil.rmtree(spill_root, ignore_errors=True)

    print()
    print("[FINALIZE] Merge manifests/statistics...")

    manifest_path = merge_partition_manifests(
        dataset_root=dataset_root,
        partition_reports=partition_reports,
    )

    split_stats = aggregate_stats(partition_reports)

    preprocessing_copies = copy_preprocess(
        dataset_root=dataset_root,
        source_paths=preprocess_paths,
    )

    readme_path = dataset_root / "README_DATASET.md"
    write_dataset_readme(
        path=readme_path,
        window_minutes=args.window_minutes,
        max_events=args.max_events,
        active_cat=active_cat,
        active_num=active_num,
    )

    dataset_manifest = {
        "generated_at": now_iso(),
        "script_version": SCRIPT_VERSION,
        "build_config_sha256": sha256_obj(build_config),
        "build_config": build_config,
        "source": {
            "step04b_report": str(report04b_path),
            "step04b_report_sha256": report04b_sha,
            "step04b_joined_rows": int(
                report04b["joined"]["joined_unique_uid_rows"]
            ),
            "step04c_preprocess_fingerprint":
                preprocess_fp["frozen_fingerprint_sha256"],
        },
        "split_stats": split_stats,
        "sample_manifest": "split/network_sample_manifest.csv",
        "shard_format": {
            "type": "packed_npz",
            "ragged_sequence": "sample_offsets",
            "x_cat_dtype": "uint16",
            "x_num_dtype": "float32",
            "x_num_missing_dtype": "uint8",
            "x_bin_dtype": "uint8",
            "edge_local_id_dtype": "uint16",
            "sample_label_dtype": "uint8",
        },
        "graph_contract": {
            "node_types": ["APP", "REMOTE_ENDPOINT"],
            "per_event_edge": "APP -> REMOTE_ENDPOINT",
            "reverse_edge_for_gnn": "add in dataloader/training",
            "raw_remote_identity_exported": False,
            "local_remote_id_scope": "within one sample only",
        },
        "sequence_contract": {
            "chronological_order": True,
            "delta_time": "log1p seconds within chunk; first event=0",
            "padding": "performed by dataloader, not stored",
        },
        "label_contract": {
            "sample_label": "1 iff chunk has >=1 positive event",
            "final_pos_weight_source":
                "TRAIN sample-level negative/positive count",
        },
    }

    dataset_manifest_path = (
        dataset_root / "dataset_manifest.json"
    )
    dump_json(
        dataset_manifest_path,
        dataset_manifest,
    )

    extra_integrity = [
        config_path,
        manifest_path,
        readme_path,
        dataset_manifest_path,
        *preprocessing_copies,
    ]

    integrity_path = write_integrity(
        dataset_root=dataset_root,
        partition_reports=partition_reports,
        additional_paths=extra_integrity,
    )

    step_report = {
        "generated_at": now_iso(),
        "script_version": SCRIPT_VERSION,
        "status": "READY_FOR_KAGGLE_VALIDATION",
        "decision": {
            "baseline_window_minutes": int(args.window_minutes),
            "max_events": int(args.max_events),
            "thirty_minute_policy": (
                "Do not replace baseline now. Run 30-minute as later ablation "
                "using the same script with --window-minutes 30."
            ),
        },
        "split_stats": split_stats,
        "dataset_root": str(dataset_root),
        "sample_manifest": str(manifest_path),
        "dataset_manifest": str(dataset_manifest_path),
        "integrity": str(integrity_path),
        "preprocess_fingerprint":
            preprocess_fp["frozen_fingerprint_sha256"],
    }

    step_report_path = (
        artifact_dir
        / "network_dl_shard_report.json"
    )
    dump_json(
        step_report_path,
        step_report,
    )

    md_path = (
        artifact_dir
        / "STEP_04_NETWORK_DL_SHARDS.md"
    )
    write_step_md(
        path=md_path,
        dataset_root=dataset_root,
        split_stats=split_stats,
        window_minutes=args.window_minutes,
        max_events=args.max_events,
        manifest_path=manifest_path,
        preprocess_fingerprint=
            preprocess_fp["frozen_fingerprint_sha256"],
    )

    print()
    print("=" * 100)
    print("[SUCCESS] STEP 04D complete")
    print(f"[WINDOW] {args.window_minutes} minutes")
    print(f"[DATASET] {dataset_root}")
    print(f"[MANIFEST] {manifest_path}")
    print(f"[REPORT] {step_report_path}")
    print(f"[MD] {md_path}")

    for split in SUPERVISED_SPLITS:
        s = split_stats[split]
        print(
            f"[{split.upper()}] "
            f"samples={s['samples']:,} | "
            f"positive={s['positive_samples']:,} | "
            f"rate={100*s['positive_sample_rate']:.4f}% | "
            f"events={s['events']:,} | "
            f"pos_weight={s['pos_weight_neg_over_pos']}"
        )

    print("=" * 100)


if __name__ == "__main__":
    main()
