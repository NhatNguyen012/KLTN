from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np


SCRIPT_VERSION = "step04d-network-dl-shards-v1.1-logical-day-fix"
DATASET_VERSION = "network-dl-v1.1-15m"

SUPERVISED_SPLITS = ("train", "val", "test")


def load_base_module():
    path = Path(__file__).with_name(
        "04a_dl_shards_base.py"
    )

    if not path.exists():
        raise FileNotFoundError(
            "Thiếu base module 04a_dl_shards_base.py "
            f"bên cạnh script v1.1: {path}"
        )

    spec = importlib.util.spec_from_file_location(
        "step04d_v1_base",
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Cannot import STEP 04D v1.0 base module: {path}"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base_module()


def sql_path(path: Path) -> str:
    return str(path).replace("\\", "/").replace("'", "''")


def discover_logical_days(
    *,
    joined_root: Path,
    split: str,
    threads: int,
    memory_limit: str,
    spill_dir: Path,
) -> list[tuple[int, str]]:
    """
    Discover UTC logical days from event timestamp, NOT from source
    date partition path.

    This is the key v1.1 fix.
    """

    split_glob = (
        joined_root
        / f"split={split}"
        / "date=*"
        / "*.parquet"
    )

    db = base.connect_duckdb(
        threads=threads,
        memory_limit=memory_limit,
        temp_dir=spill_dir / f"discover_{split}",
    )

    try:
        rows = db.execute(
            f"""
            SELECT DISTINCT
                CAST(floor(CAST(ts AS DOUBLE) / 86400.0) AS BIGINT) AS day_index
            FROM read_parquet(
                '{sql_path(split_glob)}',
                hive_partitioning=true
            )
            WHERE ts IS NOT NULL
            ORDER BY day_index
            """
        ).fetchall()
    finally:
        db.close()
        shutil.rmtree(
            spill_dir / f"discover_{split}",
            ignore_errors=True,
        )

    result = []

    for (day_index,) in rows:
        day_index = int(day_index)
        dt = datetime.fromtimestamp(
            day_index * 86400,
            tz=timezone.utc,
        )
        result.append(
            (day_index, dt.strftime("%Y-%m-%d"))
        )

    if not result:
        raise RuntimeError(
            f"No timestamp-derived logical days for split={split}"
        )

    return result


def build_logical_day_query(
    *,
    split_glob: Path,
    day_start_epoch: int,
    day_end_epoch: int,
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
            f"{base.category_id_expr(field, mapping)}"
            f"::USMALLINT AS cat_{field}"
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
            {base.numeric_value_expr(
                field,
                mean=float(info["log1p_mean"]),
                scale=float(info["scale_used"]),
                clip_abs=clip_abs,
            )}::FLOAT AS num_{field}
            """.strip()
        )

        miss_select.append(
            f"{base.numeric_missing_expr(field)}"
            f"::UTINYINT AS miss_{field}"
        )

    if "app_family" not in active_cat:
        raise RuntimeError(
            "app_family must remain active for APP graph nodes."
        )

    source = sql_path(split_glob)

    return f"""
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

        FROM read_parquet(
            '{source}',
            hive_partitioning=true
        )

        WHERE
            hostname IS NOT NULL
            AND trim(hostname) <> ''
            AND ts IS NOT NULL
            AND label IS NOT NULL
            AND CAST(ts AS DOUBLE) >= {int(day_start_epoch)}
            AND CAST(ts AS DOUBLE) < {int(day_end_epoch)}
    ),

    windowed AS (
        SELECT
            *,
            CAST(
                floor(ts / {int(window_seconds)})
                * {int(window_seconds)}
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
            CAST(
                floor(rn / {int(max_events)})
                AS INTEGER
            ) AS chunk_index,
            CAST(
                rn % {int(max_events)}
                AS INTEGER
            ) AS event_pos
        FROM numbered
    ),

    local_ids AS (
        SELECT
            *,
            (
                dense_rank() OVER (
                    PARTITION BY
                        hostname,
                        window_start,
                        chunk_index
                    ORDER BY cat_app_family
                ) - 1
            )::USMALLINT AS app_local_id,

            (
                dense_rank() OVER (
                    PARTITION BY
                        hostname,
                        window_start,
                        chunk_index
                    ORDER BY
                        COALESCE(resp_h, '<MISSING>')
                ) - 1
            )::USMALLINT AS remote_local_id
        FROM chunked
    ),

    timed AS (
        SELECT
            *,
            lag(ts) OVER (
                PARTITION BY
                    hostname,
                    window_start,
                    chunk_index
                ORDER BY event_pos
            ) AS prev_ts
        FROM local_ids
    ),

    grouped AS (
        SELECT
            *,
            dense_rank() OVER (
                ORDER BY
                    hostname,
                    window_start,
                    chunk_index
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


def process_logical_day(
    *,
    split: str,
    logical_date: str,
    day_start_epoch: int,
    joined_root: Path,
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
    success_file = (
        final_partition_dir
        / "_SUCCESS.json"
    )

    if success_file.exists():
        print(
            f"[SKIP] split={split} logical_date={logical_date} "
            "already completed."
        )
        return base.load_json(success_file)

    building = final_partition_dir.parent / (
        final_partition_dir.name
        + ".__building__"
    )

    if building.exists():
        shutil.rmtree(building)

    building.mkdir(
        parents=True,
        exist_ok=True,
    )

    relative_prefix = (
        f"shards/{split}/date={logical_date}"
    )

    writer = base.ShardWriter(
        build_dir=building,
        final_relative_prefix=relative_prefix,
        split=split,
        date=logical_date,
        active_cat=active_cat,
        active_num=active_num,
        max_events_per_shard=shard_max_events,
        compressed=compressed_npz,
    )

    db = base.connect_duckdb(
        threads=threads,
        memory_limit=memory_limit,
        temp_dir=(
            spill_dir
            / f"{split}_{logical_date}"
        ),
    )

    split_glob = (
        joined_root
        / f"split={split}"
        / "date=*"
        / "*.parquet"
    )

    query = build_logical_day_query(
        split_glob=split_glob,
        day_start_epoch=day_start_epoch,
        day_end_epoch=day_start_epoch + 86400,
        active_cat=active_cat,
        active_num=active_num,
        maps=maps,
        numeric=numeric,
        window_seconds=window_seconds,
        max_events=max_events,
    )

    pending = None

    try:
        cursor = db.execute(query)

        reader = cursor.fetch_record_batch(
            rows_per_batch=arrow_batch_rows
        )

        for batch in reader:
            gids = base.arrow_to_numpy(
                batch,
                "group_id",
                np.int64,
            )

            if len(gids) == 0:
                continue

            boundaries = (
                np.flatnonzero(
                    gids[1:] != gids[:-1]
                )
                + 1
            )

            starts = np.concatenate([
                np.asarray([0]),
                boundaries,
            ])

            ends = np.concatenate([
                boundaries,
                np.asarray([len(gids)]),
            ])

            for start, end in zip(
                starts,
                ends,
            ):
                piece = base.piece_from_batch(
                    batch,
                    int(start),
                    int(end),
                    active_cat,
                    active_num,
                )

                if pending is None:
                    pending = piece
                    continue

                if (
                    pending["group_id"]
                    == piece["group_id"]
                ):
                    pending = base.merge_pieces(
                        pending,
                        piece,
                    )
                    continue

                sample = base.finalize_piece(
                    pending
                )

                if (
                    sample["event_count"]
                    > max_events
                ):
                    raise RuntimeError(
                        "Chunk > MAX_EVENTS: "
                        f"{sample['event_count']}"
                    )

                writer.add_sample(sample)
                pending = piece

        if pending is not None:
            sample = base.finalize_piece(
                pending
            )

            if (
                sample["event_count"]
                > max_events
            ):
                raise RuntimeError(
                    "Chunk > MAX_EVENTS: "
                    f"{sample['event_count']}"
                )

            writer.add_sample(sample)

    finally:
        db.close()
        shutil.rmtree(
            spill_dir
            / f"{split}_{logical_date}",
            ignore_errors=True,
        )

    stats, sha_rows = writer.close()

    partition_report = {
        "completed_at": base.now_iso(),
        "script_version": SCRIPT_VERSION,
        "split": split,
        "date": logical_date,
        "logical_date_source":
            "UTC day derived from ts",
        "day_start_epoch": int(
            day_start_epoch
        ),
        "day_end_epoch": int(
            day_start_epoch + 86400
        ),
        "source": str(
            joined_root
            / f"split={split}"
            / "date=*"
            / "*.parquet"
        ),
        "window_seconds":
            window_seconds,
        "max_events_per_sample":
            max_events,
        "compressed_npz":
            compressed_npz,
        "active_categorical_features":
            active_cat,
        "active_numerical_features":
            active_num,
        "binary_features":
            ["has_missed_bytes"],
        "stats": stats,
        "shards": [
            {
                "file":
                    f"{relative_prefix}/{name}",
                "sha256": digest,
                "size_bytes": size,
            }
            for name, digest, size
            in sha_rows
        ],
    }

    base.dump_json(
        building / "_SUCCESS.json",
        partition_report,
    )

    if final_partition_dir.exists():
        shutil.rmtree(
            final_partition_dir
        )

    building.replace(
        final_partition_dir
    )

    return partition_report


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--output-root",
        required=True,
    )
    parser.add_argument(
        "--joined-root",
        default=None,
    )
    parser.add_argument(
        "--preprocess-dir",
        default=None,
    )
    parser.add_argument(
        "--report04b",
        default=None,
    )

    parser.add_argument(
        "--window-minutes",
        type=int,
        default=15,
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=512,
    )
    parser.add_argument(
        "--shard-max-events",
        type=int,
        default=250_000,
    )
    parser.add_argument(
        "--arrow-batch-rows",
        type=int,
        default=100_000,
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=max(
            2,
            min(
                8,
                os.cpu_count()
                or 4,
            ),
        ),
    )
    parser.add_argument(
        "--duckdb-memory-limit",
        default="8GB",
    )
    parser.add_argument(
        "--compressed-npz",
        action="store_true",
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

    base.require_packages()

    output_root = Path(
        args.output_root
    )

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
        / "network_dl_v1_1_15m"
    )

    artifact_dir = (
        output_root
        / "02_artifacts"
        / "04_network_dl_shards_v1_1_15m"
    )

    if args.reset:
        shutil.rmtree(
            dataset_root,
            ignore_errors=True,
        )
        shutil.rmtree(
            artifact_dir,
            ignore_errors=True,
        )

    dataset_root.mkdir(
        parents=True,
        exist_ok=True,
    )
    artifact_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    free_gib = (
        shutil.disk_usage(
            output_root
        ).free
        / (1024 ** 3)
    )

    if (
        free_gib
        < args.min_free_gib
        and not args.allow_low_disk
    ):
        raise RuntimeError(
            f"Only {free_gib:.2f} GiB free. "
            f"Need >= {args.min_free_gib:.2f} GiB."
        )

    (
        maps,
        numeric,
        spec,
        preprocess_fp,
        preprocess_paths,
    ) = base.validate_frozen_preprocess(
        preprocess_dir
    )

    active_cat = list(
        spec.get(
            "active_categorical_features",
            spec.get(
                "categorical_features",
                [],
            ),
        )
    )

    active_num = list(
        spec.get(
            "active_numerical_features",
            spec.get(
                "numerical_features",
                [],
            ),
        )
    )

    report04b = base.load_json(
        report04b_path
    )

    report04b_sha = base.sha256_file(
        report04b_path
    )

    window_seconds = (
        int(args.window_minutes)
        * 60
    )

    build_config = {
        "script_version":
            SCRIPT_VERSION,
        "dataset_version":
            DATASET_VERSION,
        "joined_root":
            str(joined_root),
        "report04b_sha256":
            report04b_sha,
        "preprocess_frozen_fingerprint":
            preprocess_fp[
                "frozen_fingerprint_sha256"
            ],
        "window_minutes":
            int(args.window_minutes),
        "window_seconds":
            int(window_seconds),
        "max_events":
            int(args.max_events),
        "shard_max_events":
            int(args.shard_max_events),
        "compressed_npz":
            bool(
                args.compressed_npz
            ),
        "active_categorical_features":
            active_cat,
        "active_numerical_features":
            active_num,
        "binary_features":
            ["has_missed_bytes"],
        "label_rule":
            "chunk positive iff >=1 positive event",
        "split_policy":
            "frozen hostname split; supervised train/val/test only",
        "logical_partition_policy":
            (
                "group globally by hostname/window_start within "
                "UTC day derived from ts; source path date is "
                "NOT a sample boundary"
            ),
        "raw_ip_policy":
            (
                "Used transiently only for local remote-node IDs; "
                "raw IP is not written into model tensors."
            ),
    }

    config_path = (
        dataset_root
        / "build_config.json"
    )

    if config_path.exists():
        existing = base.load_json(
            config_path
        )

        if existing != build_config:
            raise RuntimeError(
                "Existing v1.1 dataset has different config. "
                "Use --reset only if you intentionally want to rebuild."
            )
    else:
        base.dump_json(
            config_path,
            build_config,
        )

    print("=" * 100)
    print(
        "STEP 04D v1.1 — Logical-window boundary fix"
    )
    print("=" * 100)
    print(
        "[FIX] Source path date is no longer "
        "a sample/chunk boundary."
    )
    print(
        "[GROUP] split + hostname + "
        "timestamp-derived 15-minute window"
    )
    print(
        f"[DATASET] {dataset_root}"
    )
    print(
        f"[FREE DISK] {free_gib:.2f} GiB"
    )
    print()

    shard_root = (
        dataset_root
        / "shards"
    )

    spill_root = (
        artifact_dir
        / "_duckdb_spill"
    )

    partition_reports = []

    for split in SUPERVISED_SPLITS:
        days = discover_logical_days(
            joined_root=joined_root,
            split=split,
            threads=args.threads,
            memory_limit=
                args.duckdb_memory_limit,
            spill_dir=spill_root,
        )

        for index, (
            day_index,
            logical_date,
        ) in enumerate(
            days,
            start=1,
        ):
            print(
                f"[{split.upper()} "
                f"{index}/{len(days)}] "
                f"logical_date={logical_date}"
            )

            final_dir = (
                shard_root
                / split
                / f"date={logical_date}"
            )

            report = process_logical_day(
                split=split,
                logical_date=logical_date,
                day_start_epoch=
                    int(day_index * 86400),
                joined_root=joined_root,
                final_partition_dir=
                    final_dir,
                active_cat=active_cat,
                active_num=active_num,
                maps=maps,
                numeric=numeric,
                window_seconds=
                    window_seconds,
                max_events=
                    args.max_events,
                shard_max_events=
                    args.shard_max_events,
                compressed_npz=
                    args.compressed_npz,
                threads=
                    args.threads,
                memory_limit=
                    args.duckdb_memory_limit,
                arrow_batch_rows=
                    args.arrow_batch_rows,
                spill_dir=
                    spill_root,
            )

            partition_reports.append(
                report
            )

            s = report["stats"]

            print(
                f"    [DONE] "
                f"samples={s['samples']:,} | "
                f"positive={s['positive_samples']:,} | "
                f"events={s['events']:,} | "
                f"shards={s['shards']:,}"
            )

    shutil.rmtree(
        spill_root,
        ignore_errors=True,
    )

    split_stats = base.aggregate_stats(
        partition_reports
    )

    expected_rows = (
        report04b["joined"][
            "rows_by_split"
        ]
    )

    for split in SUPERVISED_SPLITS:
        expected = int(
            expected_rows[split]
        )
        actual = int(
            split_stats[split][
                "events"
            ]
        )

        if actual != expected:
            raise RuntimeError(
                f"EVENT CONSERVATION FAIL for {split}: "
                f"expected={expected:,}, actual={actual:,}"
            )

    print()
    print(
        "[CHECK] Event conservation PASS "
        "for TRAIN/VAL/TEST."
    )

    manifest_path = (
        base.merge_partition_manifests(
            dataset_root=dataset_root,
            partition_reports=
                partition_reports,
        )
    )

    preprocessing_copies = (
        base.copy_preprocess(
            dataset_root=dataset_root,
            source_paths=
                preprocess_paths,
        )
    )

    readme_path = (
        dataset_root
        / "README_DATASET.md"
    )

    base.write_dataset_readme(
        path=readme_path,
        window_minutes=
            args.window_minutes,
        max_events=
            args.max_events,
        active_cat=
            active_cat,
        active_num=
            active_num,
    )

    dataset_manifest = {
        "generated_at":
            base.now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "build_config_sha256":
            base.sha256_obj(
                build_config
            ),
        "build_config":
            build_config,
        "source": {
            "step04b_report":
                str(
                    report04b_path
                ),
            "step04b_report_sha256":
                report04b_sha,
            "step04b_joined_rows":
                int(
                    report04b[
                        "joined"
                    ][
                        "joined_unique_uid_rows"
                    ]
                ),
            "step04c_preprocess_fingerprint":
                preprocess_fp[
                    "frozen_fingerprint_sha256"
                ],
        },
        "split_stats":
            split_stats,
        "sample_manifest":
            "split/network_sample_manifest.csv",
        "shard_format": {
            "type":
                "packed_npz",
            "ragged_sequence":
                "sample_offsets",
            "x_cat_dtype":
                "uint16",
            "x_num_dtype":
                "float32",
            "x_num_missing_dtype":
                "uint8",
            "x_bin_dtype":
                "uint8",
            "edge_local_id_dtype":
                "uint16",
            "sample_label_dtype":
                "uint8",
        },
        "graph_contract": {
            "node_types": [
                "APP",
                "REMOTE_ENDPOINT",
            ],
            "per_event_edge":
                "APP -> REMOTE_ENDPOINT",
            "reverse_edge_for_gnn":
                "add in dataloader/training",
            "raw_remote_identity_exported":
                False,
            "local_remote_id_scope":
                "within one sample only",
        },
        "sequence_contract": {
            "chronological_order":
                True,
            "delta_time":
                (
                    "log1p seconds within chunk; "
                    "first event=0"
                ),
            "padding":
                (
                    "performed by dataloader, "
                    "not stored"
                ),
        },
        "label_contract": {
            "sample_label":
                (
                    "1 iff chunk has >=1 "
                    "positive event"
                ),
            "final_pos_weight_source":
                (
                    "TRAIN sample-level "
                    "negative/positive count"
                ),
        },
        "v1_1_fix": {
            "problem_in_v1_0":
                (
                    "Same logical 15-minute window could be "
                    "processed in multiple source date partitions, "
                    "resetting chunk_index and producing duplicate sample IDs."
                ),
            "fix":
                (
                    "UTC logical day derived from ts is now the "
                    "processing partition; all source date files are "
                    "queried together for that logical day before "
                    "row_number/chunk_index assignment."
                ),
        },
    }

    dataset_manifest_path = (
        dataset_root
        / "dataset_manifest.json"
    )

    base.dump_json(
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

    integrity_path = (
        base.write_integrity(
            dataset_root=
                dataset_root,
            partition_reports=
                partition_reports,
            additional_paths=
                extra_integrity,
        )
    )

    step_report = {
        "generated_at":
            base.now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "status":
            "READY_FOR_STEP05A_REVALIDATION",
        "problem_fixed":
            "duplicate logical window/chunk across source date partitions",
        "split_stats":
            split_stats,
        "dataset_root":
            str(dataset_root),
        "sample_manifest":
            str(manifest_path),
        "dataset_manifest":
            str(
                dataset_manifest_path
            ),
        "integrity":
            str(integrity_path),
        "preprocess_fingerprint":
            preprocess_fp[
                "frozen_fingerprint_sha256"
            ],
    }

    step_report_path = (
        artifact_dir
        / "network_dl_shard_report_v1_1.json"
    )

    base.dump_json(
        step_report_path,
        step_report,
    )

    print()
    print("=" * 100)
    print(
        "[SUCCESS] STEP 04D v1.1 rebuild complete"
    )
    print(
        f"[DATASET] {dataset_root}"
    )
    print(
        f"[MANIFEST] {manifest_path}"
    )
    print(
        f"[REPORT] {step_report_path}"
    )

    for split in SUPERVISED_SPLITS:
        s = split_stats[split]
        print(
            f"[{split.upper()}] "
            f"samples={s['samples']:,} | "
            f"positive={s['positive_samples']:,} | "
            f"events={s['events']:,} | "
            f"pos_weight={s['pos_weight_neg_over_pos']}"
        )

    print()
    print(
        "[NEXT] Re-run STEP 05A validator against "
        "network_dl_v1_1_15m."
    )
    print("=" * 100)


if __name__ == "__main__":
    main()
