from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np


SCRIPT_VERSION = "step05f-d-loso-network-dl-shards-v1.1-one-scan-per-day"
DATASET_VERSION = "loso-network-dl-v1.1-15m"

SUPERVISED_SPLITS = (
    "train",
    "val",
    "test",
)

SCENARIOS = (
    "scenario_1",
    "scenario_2",
    "scenario_3",
)

# STEP 10C: dùng lại cho split ngẫu nhiên (--mode random). Mặc định giữ hành vi LOSO cũ.
LOSO_CONTRACT_VERSION = "step05f-b-loso-remap-audit-v1.1-zero-row-safe"
RANDOM_CONTRACT_VERSION = "step10a-random-scenario-split-v1.0"
MAPPING_MODE = "loso"  # đặt trong main() theo --mode


EXCLUDE_RESP_IPS: tuple[str, ...] = ()  # STEP 11: doc tu contract["excluded_resp_ips"]; rong = khong loai gi


def exclusion_sql(prefix: str = "") -> str:
    """Dieu kien SQL loai event co resp_h thuoc EXCLUDE_RESP_IPS (rong neu khong co)."""
    if not EXCLUDE_RESP_IPS:
        return ""

    ips = ", ".join(
        "'" + ip.replace("'", "''") + "'"
        for ip in EXCLUDE_RESP_IPS
    )

    return (
        f"AND ({prefix}resp_h IS NULL "
        f"OR {prefix}resp_h NOT IN ({ips}))"
    )


def fold_label_fields(fold: str) -> dict[str, Any]:
    """loso: heldout_scenario = tên fold (như cũ). random: không có held-out scenario."""
    if MAPPING_MODE == "random":
        return {"heldout_scenario": None, "fold_name": fold}

    return {"heldout_scenario": fold}


def fold_identity(report: dict[str, Any]) -> Any:
    if MAPPING_MODE == "random":
        return report.get("fold_name")

    return report.get("heldout_scenario")


def load_base_module():
    path = Path(__file__).with_name(
        "04a_dl_shards_base.py"
    )

    if not path.exists():
        raise FileNotFoundError(
            "Thiếu 04a_dl_shards_base.py "
            f"bên cạnh script STEP 05F-D: {path}"
        )

    spec = importlib.util.spec_from_file_location(
        "step04d_base",
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Cannot import base module: {path}"
        )

    module = importlib.util.module_from_spec(
        spec
    )
    spec.loader.exec_module(
        module
    )

    return module


base = load_base_module()


def sql_path(path: Path) -> str:
    return (
        str(path)
        .replace("\\", "/")
        .replace("'", "''")
    )


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


RANDOM_NAMING = False  # True o --mode random: artifact khong chua ten "loso"
SPLIT_COL = "loso_split"  # random: "assigned_split" (doc tu CSV mapping)


def neutral_text(text: str) -> str:
    if not RANDOM_NAMING:
        return text

    text = text.replace("STEP 05F-B frozen LOSO", "STEP 10A frozen")
    text = text.replace("loso_split", "assigned_split")
    return text.replace("loso", "split").replace("LOSO", "random-split")


def neutral(obj: Any) -> Any:
    """Tra ban sao (khong sua obj goc) da bo ten loso khi o mode random."""
    if not RANDOM_NAMING:
        return obj

    if isinstance(obj, dict):
        return {
            (neutral_text(k) if isinstance(k, str) else k): neutral(v)
            for k, v in obj.items()
        }

    if isinstance(obj, (list, tuple)):
        return [neutral(v) for v in obj]

    if isinstance(obj, str):
        return neutral_text(obj)

    return obj


def dump_json(
    path: Path,
    obj: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            neutral(obj),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(
            lambda: f.read(
                1024 * 1024
            ),
            b"",
        ):
            h.update(
                block
            )

    return h.hexdigest()


def verify_loso_contract(
    frozen_dir: Path,
    contract_name: str = "loso_fold_contract.json",
    expected_version: str = LOSO_CONTRACT_VERSION,
    expected_folds: tuple[str, ...] | None = SCENARIOS,
) -> tuple[
    dict[str, Any],
    dict[str, Path],
]:
    contract_path = (
        frozen_dir
        / contract_name
    )

    if not contract_path.exists():
        raise FileNotFoundError(
            contract_path
        )

    contract = load_json(
        contract_path
    )

    if (
        contract.get(
            "script_version"
        )
        != expected_version
    ):
        raise RuntimeError(
            "Unexpected frozen contract version: "
            f"{contract.get('script_version')!r}"
        )

    mappings: dict[
        str,
        Path,
    ] = {}

    for scenario in (
        expected_folds
        if expected_folds is not None
        else tuple(
            contract.get(
                "folds",
                {},
            )
        )
    ):
        info = (
            contract.get(
                "folds",
                {},
            ).get(
                scenario
            )
        )

        if not info:
            raise RuntimeError(
                f"Missing frozen fold: {scenario}"
            )

        path = (
            frozen_dir
            / info["file"]
        )

        if not path.exists():
            raise FileNotFoundError(
                path
            )

        actual = sha256_file(
            path
        )

        if (
            actual
            != info["sha256"]
        ):
            raise RuntimeError(
                "Frozen LOSO mapping SHA mismatch:\n"
                f"{path}\n"
                f"expected={info['sha256']}\n"
                f"actual={actual}"
            )

        mappings[
            scenario
        ] = path

    return (
        contract,
        mappings,
    )


def mapping_expected_stats(
    mapping_path: Path,
) -> dict[str, Any]:
    import pandas as pd

    df = pd.read_csv(
        mapping_path
    )

    required = {
        "hostname",
        SPLIT_COL,
        "event_rows",
        "positive_event_rows",
        "heldout_scenario",
    }

    missing = (
        required
        - set(
            df.columns
        )
    )

    if missing:
        raise RuntimeError(
            f"{mapping_path}: missing columns "
            f"{sorted(missing)}"
        )

    if (
        df[
            "hostname"
        ].duplicated().any()
    ):
        raise RuntimeError(
            f"{mapping_path}: duplicate hostname."
        )

    invalid = (
        set(
            df[
                SPLIT_COL
            ].dropna().unique()
        )
        - set(
            SUPERVISED_SPLITS
        )
    )

    if invalid:
        raise RuntimeError(
            f"{mapping_path}: invalid splits "
            f"{sorted(invalid)}"
        )

    result = {}

    for split in (
        SUPERVISED_SPLITS
    ):
        sub = df[
            df[
                SPLIT_COL
            ] == split
        ]

        result[
            split
        ] = {
            "hosts":
                int(
                    sub[
                        "hostname"
                    ].nunique()
                ),
            "events":
                int(
                    sub[
                        "event_rows"
                    ].sum()
                ),
            "positive_events":
                int(
                    sub[
                        "positive_event_rows"
                    ].sum()
                ),
        }

    return result


def discover_fold_logical_days(
    *,
    joined_root: Path,
    mapping_path: Path,
    threads: int,
    memory_limit: str,
    spill_dir: Path,
) -> list[tuple[int, str]]:
    """
    Discover all UTC logical days in one LOSO fold.

    All physical STEP 04B train/val/test partitions are read because their
    original split is NOT the LOSO split.
    """

    source_glob = (
        joined_root
        / "split=*"
        / "date=*"
        / "*.parquet"
    )

    db = base.connect_duckdb(
        threads=threads,
        memory_limit=memory_limit,
        temp_dir=(
            spill_dir
            / "discover_days"
        ),
    )

    try:
        rows = db.execute(
            f"""
            SELECT DISTINCT
                CAST(
                    floor(
                        CAST(j.ts AS DOUBLE)
                        / 86400.0
                    )
                    AS BIGINT
                ) AS day_index

            FROM read_parquet(
                '{sql_path(source_glob)}',
                hive_partitioning=true
            ) AS j

            INNER JOIN read_csv_auto(
                '{sql_path(mapping_path)}',
                header=true
            ) AS m
                ON j.hostname = m.hostname

            WHERE
                m.{SPLIT_COL}
                    IN ('train', 'val', 'test')
                AND j.ts IS NOT NULL

            ORDER BY day_index
            """
        ).fetchall()

    finally:
        db.close()

        shutil.rmtree(
            spill_dir
            / "discover_days",
            ignore_errors=True,
        )

    result = []

    for (day_index,) in rows:
        day_index = int(
            day_index
        )

        dt = datetime.fromtimestamp(
            day_index * 86400,
            tz=timezone.utc,
        )

        result.append(
            (
                day_index,
                dt.strftime(
                    "%Y-%m-%d"
                ),
            )
        )

    if not result:
        raise RuntimeError(
            "No timestamp-derived logical days."
        )

    return result


def build_fold_day_query(
    *,
    joined_root: Path,
    mapping_path: Path,
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
        mapping = (
            maps[
                "fields"
            ][field][
                "mapping"
            ]
        )

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
        info = (
            numeric[
                "features"
            ][field]
        )

        num_select.append(
            f"""
            {base.numeric_value_expr(
                field,
                mean=float(
                    info[
                        "log1p_mean"
                    ]
                ),
                scale=float(
                    info[
                        "scale_used"
                    ]
                ),
                clip_abs=
                    clip_abs,
            )}::FLOAT AS num_{field}
            """.strip()
        )

        miss_select.append(
            f"{base.numeric_missing_expr(field)}"
            f"::UTINYINT AS miss_{field}"
        )

    if (
        "app_family"
        not in active_cat
    ):
        raise RuntimeError(
            "app_family must remain active "
            "for APP graph nodes."
        )

    source_glob = (
        joined_root
        / "split=*"
        / "date=*"
        / "*.parquet"
    )

    return f"""
    WITH remapped AS (
        SELECT
            CAST(
                m.{SPLIT_COL}
                AS VARCHAR
            ) AS logical_split,

            j.hostname,

            CAST(
                j.ts AS DOUBLE
            ) AS ts,

            j.uid,

            CAST(
                j.label AS UTINYINT
            ) AS label,

            j.resp_h,
            j.resp_p,
            j.missed_bytes,

            {", ".join(cat_select)},

            {", ".join(num_select)},

            {", ".join(miss_select)},

            CASE
                WHEN
                    j.missed_bytes
                        IS NOT NULL
                    AND j.missed_bytes > 0
                    THEN 1
                ELSE 0
            END::UTINYINT
                AS bin_has_missed_bytes

        FROM read_parquet(
            '{sql_path(source_glob)}',
            hive_partitioning=true
        ) AS j

        INNER JOIN read_csv_auto(
            '{sql_path(mapping_path)}',
            header=true
        ) AS m
            ON j.hostname = m.hostname

        WHERE
            m.{SPLIT_COL}
                IN ('train', 'val', 'test')
            AND j.hostname IS NOT NULL
            {exclusion_sql("j.")}
            AND trim(
                j.hostname
            ) <> ''
            AND j.ts IS NOT NULL
            AND j.label IS NOT NULL
            AND CAST(
                j.ts AS DOUBLE
            ) >= {int(day_start_epoch)}
            AND CAST(
                j.ts AS DOUBLE
            ) < {int(day_end_epoch)}
    ),

    windowed AS (
        SELECT
            *,
            CAST(
                floor(
                    ts
                    / {int(window_seconds)}
                )
                * {int(window_seconds)}
                AS BIGINT
            ) AS window_start
        FROM remapped
    ),

    numbered AS (
        SELECT
            *,
            (
                row_number() OVER (
                    PARTITION BY
                        logical_split,
                        hostname,
                        window_start
                    ORDER BY
                        ts,
                        uid
                ) - 1
            )::BIGINT AS rn
        FROM windowed
    ),

    chunked AS (
        SELECT
            *,
            CAST(
                floor(
                    rn
                    / {int(max_events)}
                )
                AS INTEGER
            ) AS chunk_index,

            CAST(
                rn
                % {int(max_events)}
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
                        logical_split,
                        hostname,
                        window_start,
                        chunk_index
                    ORDER BY
                        cat_app_family
                ) - 1
            )::USMALLINT
                AS app_local_id,

            (
                dense_rank() OVER (
                    PARTITION BY
                        logical_split,
                        hostname,
                        window_start,
                        chunk_index
                    ORDER BY
                        COALESCE(
                            resp_h,
                            '<MISSING>'
                        )
                ) - 1
            )::USMALLINT
                AS remote_local_id

        FROM chunked
    ),

    timed AS (
        SELECT
            *,
            lag(ts) OVER (
                PARTITION BY
                    logical_split,
                    hostname,
                    window_start,
                    chunk_index
                ORDER BY
                    event_pos
            ) AS prev_ts
        FROM local_ids
    ),

    grouped AS (
        SELECT
            *,
            dense_rank() OVER (
                ORDER BY
                    logical_split,
                    hostname,
                    window_start,
                    chunk_index
            )::BIGINT AS group_id,

            CASE
                WHEN prev_ts IS NULL
                    THEN 0.0
                ELSE ln(
                    1.0
                    + greatest(
                        0.0,
                        ts - prev_ts
                    )
                )
            END::FLOAT
                AS delta_t_log1p

        FROM timed
    )

    SELECT
        group_id,
        logical_split,
        hostname,
        window_start,
        chunk_index,
        event_pos,
        label,

        {", ".join(
            f"cat_{f}"
            for f in active_cat
        )},

        {", ".join(
            f"num_{f}"
            for f in active_num
        )},

        {", ".join(
            f"miss_{f}"
            for f in active_num
        )},

        bin_has_missed_bytes,
        delta_t_log1p,
        app_local_id,
        remote_local_id

    FROM grouped

    ORDER BY
        logical_split,
        group_id,
        event_pos
    """


def piece_from_batch_loso(
    batch,
    start: int,
    end: int,
    active_cat: list[str],
    active_num: list[str],
) -> dict[str, Any]:
    piece = (
        base.piece_from_batch(
            batch,
            start,
            end,
            active_cat,
            active_num,
        )
    )

    arr = batch.column(
        batch.schema.get_field_index(
            "logical_split"
        )
    ).slice(
        start,
        end - start,
    )

    logical_split = str(
        arr[0].as_py()
    )

    if (
        logical_split
        not in SUPERVISED_SPLITS
    ):
        raise RuntimeError(
            "Invalid logical split "
            f"in query result: "
            f"{logical_split!r}"
        )

    piece[
        "logical_split"
    ] = logical_split

    return piece


def merge_pieces_loso(
    a: dict[str, Any],
    b: dict[str, Any],
) -> dict[str, Any]:
    if (
        a[
            "logical_split"
        ]
        != b[
            "logical_split"
        ]
    ):
        raise RuntimeError(
            "Attempted to merge pieces "
            "from different LOSO splits."
        )

    split = a[
        "logical_split"
    ]

    merged = (
        base.merge_pieces(
            a,
            b,
        )
    )

    merged[
        "logical_split"
    ] = split

    return merged


def finalize_piece_loso(
    piece: dict[str, Any],
) -> dict[str, Any]:
    logical_split = (
        piece[
            "logical_split"
        ]
    )

    sample = (
        base.finalize_piece(
            piece
        )
    )

    sample[
        "logical_split"
    ] = logical_split

    return sample


def day_complete(
    *,
    shard_root: Path,
    logical_date: str,
    scenario: str,
) -> tuple[
    bool,
    list[dict[str, Any]],
]:
    reports = []
    existing = []

    for split in (
        SUPERVISED_SPLITS
    ):
        success = (
            shard_root
            / split
            / f"date={logical_date}"
            / "_SUCCESS.json"
        )

        existing.append(
            success.exists()
        )

        if success.exists():
            report = (
                base.load_json(
                    success
                )
            )

            if (
                fold_identity(
                    report
                )
                != scenario
            ):
                raise RuntimeError(
                    "Existing partition belongs "
                    "to another fold."
                )

            reports.append(
                report
            )

    if all(
        existing
    ):
        return (
            True,
            reports,
        )

    # Partial day is intentionally rebuilt as a whole because this optimized
    # implementation scans the source only once and emits all three splits.
    if any(
        existing
    ):
        for split in (
            SUPERVISED_SPLITS
        ):
            path = (
                shard_root
                / split
                / f"date={logical_date}"
            )

            shutil.rmtree(
                path,
                ignore_errors=True,
            )

    return (
        False,
        [],
    )


def process_fold_day(
    *,
    scenario: str,
    logical_date: str,
    day_start_epoch: int,
    joined_root: Path,
    mapping_path: Path,
    shard_root: Path,
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
) -> list[dict[str, Any]]:
    completed, reports = (
        day_complete(
            shard_root=
                shard_root,
            logical_date=
                logical_date,
            scenario=
                scenario,
        )
    )

    if completed:
        print(
            f"[SKIP] fold={scenario} "
            f"logical_date={logical_date} "
            "all TRAIN/VAL/TEST outputs "
            "already complete."
        )

        return reports

    building_dirs = {}
    writers = {}

    for split in (
        SUPERVISED_SPLITS
    ):
        final_dir = (
            shard_root
            / split
            / f"date={logical_date}"
        )

        building = (
            final_dir.parent
            / (
                final_dir.name
                + ".__building__"
            )
        )

        if building.exists():
            shutil.rmtree(
                building
            )

        building.mkdir(
            parents=True,
            exist_ok=True,
        )

        building_dirs[
            split
        ] = (
            final_dir,
            building,
        )

        writers[
            split
        ] = base.ShardWriter(
            build_dir=
                building,
            final_relative_prefix=(
                f"shards/{split}/"
                f"date={logical_date}"
            ),
            split=
                split,
            date=
                logical_date,
            active_cat=
                active_cat,
            active_num=
                active_num,
            max_events_per_shard=
                shard_max_events,
            compressed=
                compressed_npz,
        )

    db = base.connect_duckdb(
        threads=threads,
        memory_limit=memory_limit,
        temp_dir=(
            spill_dir
            / f"day_{logical_date}"
        ),
    )

    query = build_fold_day_query(
        joined_root=
            joined_root,
        mapping_path=
            mapping_path,
        day_start_epoch=
            day_start_epoch,
        day_end_epoch=
            day_start_epoch
            + 86400,
        active_cat=
            active_cat,
        active_num=
            active_num,
        maps=maps,
        numeric=numeric,
        window_seconds=
            window_seconds,
        max_events=
            max_events,
    )

    pending = None

    try:
        cursor = db.execute(
            query
        )

        reader = (
            cursor.fetch_record_batch(
                rows_per_batch=
                    arrow_batch_rows
            )
        )

        for batch in reader:
            gids = (
                base.arrow_to_numpy(
                    batch,
                    "group_id",
                    np.int64,
                )
            )

            if len(
                gids
            ) == 0:
                continue

            boundaries = (
                np.flatnonzero(
                    gids[1:]
                    != gids[:-1]
                )
                + 1
            )

            starts = np.concatenate([
                np.asarray([0]),
                boundaries,
            ])

            ends = np.concatenate([
                boundaries,
                np.asarray(
                    [len(gids)]
                ),
            ])

            for start, end in zip(
                starts,
                ends,
            ):
                piece = (
                    piece_from_batch_loso(
                        batch,
                        int(
                            start
                        ),
                        int(
                            end
                        ),
                        active_cat,
                        active_num,
                    )
                )

                if pending is None:
                    pending = piece
                    continue

                if (
                    pending[
                        "group_id"
                    ]
                    == piece[
                        "group_id"
                    ]
                ):
                    pending = (
                        merge_pieces_loso(
                            pending,
                            piece,
                        )
                    )
                    continue

                sample = (
                    finalize_piece_loso(
                        pending
                    )
                )

                if (
                    sample[
                        "event_count"
                    ]
                    > max_events
                ):
                    raise RuntimeError(
                        "Chunk > MAX_EVENTS: "
                        f"{sample['event_count']}"
                    )

                writers[
                    sample[
                        "logical_split"
                    ]
                ].add_sample(
                    sample
                )

                pending = piece

        if pending is not None:
            sample = (
                finalize_piece_loso(
                    pending
                )
            )

            if (
                sample[
                    "event_count"
                ]
                > max_events
            ):
                raise RuntimeError(
                    "Chunk > MAX_EVENTS: "
                    f"{sample['event_count']}"
                )

            writers[
                sample[
                    "logical_split"
                ]
            ].add_sample(
                sample
            )

    finally:
        db.close()

        shutil.rmtree(
            spill_dir
            / f"day_{logical_date}",
            ignore_errors=True,
        )

    reports = []

    for split in (
        SUPERVISED_SPLITS
    ):
        writer = (
            writers[
                split
            ]
        )

        stats, sha_rows = (
            writer.close()
        )

        final_dir, building = (
            building_dirs[
                split
            ]
        )

        relative_prefix = (
            f"shards/{split}/"
            f"date={logical_date}"
        )

        partition_report = {
            "completed_at":
                base.now_iso(),
            "script_version":
                SCRIPT_VERSION,
            **fold_label_fields(
                scenario
            ),
            "split":
                split,
            "date":
                logical_date,
            "logical_date_source":
                "UTC day derived from ts",
            "split_source":
                (
                    "STEP 05F-B frozen "
                    "hostname LOSO mapping"
                ),
            "day_start_epoch":
                int(
                    day_start_epoch
                ),
            "day_end_epoch":
                int(
                    day_start_epoch
                    + 86400
                ),
            "source":
                str(
                    joined_root
                    / "split=*"
                    / "date=*"
                    / "*.parquet"
                ),
            "mapping":
                str(
                    mapping_path
                ),
            "window_seconds":
                int(
                    window_seconds
                ),
            "max_events_per_sample":
                int(
                    max_events
                ),
            "compressed_npz":
                bool(
                    compressed_npz
                ),
            "active_categorical_features":
                active_cat,
            "active_numerical_features":
                active_num,
            "binary_features": [
                "has_missed_bytes"
            ],
            "stats":
                stats,
            "shards": [
                {
                    "file":
                        (
                            f"{relative_prefix}/"
                            f"{name}"
                        ),
                    "sha256":
                        digest,
                    "size_bytes":
                        size,
                }
                for (
                    name,
                    digest,
                    size,
                )
                in sha_rows
            ],
        }

        dump_json(
            building
            / "_SUCCESS.json",
            partition_report,
        )

        if (
            final_dir.exists()
        ):
            shutil.rmtree(
                final_dir
            )

        building.replace(
            final_dir
        )

        reports.append(
            partition_report
        )

    return reports


def copy_loso_metadata(
    *,
    dataset_root: Path,
    mapping_path: Path,
    contract_path: Path,
) -> list[Path]:
    split_dir = (
        dataset_root
        / "split"
    )

    split_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    map_target = (
        split_dir
        / "host_split_frozen.csv"
    )

    contract_target = (
        split_dir
        / (
            "split_contract.json"
            if RANDOM_NAMING
            else "loso_fold_contract.json"
        )
    )

    shutil.copy2(
        mapping_path,
        map_target,
    )

    shutil.copy2(
        contract_path,
        contract_target,
    )

    return [
        map_target,
        contract_target,
    ]


def write_loso_readme(
    *,
    path: Path,
    heldout_scenario: str,
    window_minutes: int,
    max_events: int,
    active_cat: list[str],
    active_num: list[str],
    expected_stats: dict[str, Any],
) -> None:
    if MAPPING_MODE == "random":
        head = [
            (
                "# Network DL random-split dataset — "
                f"{heldout_scenario}"
            ),
            "",
            "## Mục đích",
            "",
            (
                "Dataset cho retrain theo split ngẫu nhiên "
                "host-disjoint, stratify host bị tấn công "
                "theo scenario (STEP 10)."
            ),
            "",
            (
                "Không có scenario held-out; preprocessing "
                "chỉ fit trên TRAIN của split này."
            ),
            "",
        ]
    else:
        head = [
            (
                "# Network DL LOSO dataset — "
                f"hold out {heldout_scenario}"
            ),
            "",
            "## Mục đích",
            "",
            (
                "Dataset cho "
                "Leave-One-Scenario-Out ablation."
            ),
            "",
            (
                f"`{heldout_scenario}` không được "
                "dùng để fit preprocessing hoặc "
                "train model."
            ),
            "",
        ]

    lines = [
        *head,
        "## Sample contract",
        "",
        (
            f"- Window: {window_minutes} phút."
        ),
        (
            f"- Max events/chunk: {max_events}."
        ),
        (
            "- Sample positive iff chunk có "
            "ít nhất 1 positive event."
        ),
        (
            "- Sequence order: chronological."
        ),
        "",
        "## Active categorical",
        "",
    ]

    for x in active_cat:
        lines.append(
            f"- `{x}`"
        )

    lines.extend([
        "",
        "## Active numerical",
        "",
    ])

    for x in active_num:
        lines.append(
            f"- `{x}`"
        )

    lines.extend([
        "",
        "## Frozen LOSO event rows",
        "",
    ])

    for split in (
        SUPERVISED_SPLITS
    ):
        s = (
            expected_stats[
                split
            ]
        )

        lines.append(
            f"- `{split}`: "
            f"hosts={s['hosts']:,}, "
            f"events={s['events']:,}, "
            f"positive_events="
            f"{s['positive_events']:,}"
        )

    lines.extend([
        "",
        "## Leakage boundary",
        "",
        (
            "- Preprocessing được fit bằng "
            "fold TRAIN only."
        ),
        (
            "- TRAIN/VAL/TEST được quyết định "
            "bằng frozen hostname LOSO mapping."
        ),
        (
            "- Original STEP 04B physical split "
            "path không phải LOSO split."
        ),
        "",
    ])

    path.write_text(
        neutral_text(
            "\n".join(
                lines
            )
        ),
        encoding="utf-8",
    )


def build_one_fold(
    *,
    scenario: str,
    output_root: Path,
    joined_root: Path,
    frozen_dir: Path,
    mapping_path: Path,
    contract: dict[str, Any],
    preprocess_root: Path,
    window_minutes: int,
    max_events: int,
    shard_max_events: int,
    arrow_batch_rows: int,
    threads: int,
    memory_limit: str,
    compressed_npz: bool,
    reset: bool,
    contract_name: str = "loso_fold_contract.json",
    dataset_root_base: Path | None = None,
    artifact_root_base: Path | None = None,
    fold_dir_template: str = "holdout_{fold}",
) -> dict[str, Any]:
    preprocess_dir = (
        preprocess_root
        / fold_dir_template.format(
            fold=scenario
        )
    )

    (
        maps,
        numeric,
        spec,
        preprocess_fp,
        preprocess_paths,
    ) = (
        base.validate_frozen_preprocess(
            preprocess_dir
        )
    )

    if (
        preprocess_fp.get(
            "heldout_scenario"
        )
        != scenario
    ):
        raise RuntimeError(
            "Preprocess heldout_scenario "
            "does not match fold."
        )

    if (
        preprocess_fp.get(
            "heldout_scenario_used_for_fit"
        )
        is not False
    ):
        raise RuntimeError(
            "Preprocess fingerprint says "
            "held-out scenario was used for fit."
        )

    active_cat = list(
        spec.get(
            "active_categorical_features",
            [],
        )
    )

    active_num = list(
        spec.get(
            "active_numerical_features",
            [],
        )
    )

    expected = (
        mapping_expected_stats(
            mapping_path
        )
    )

    total_expected = sum(
        s[
            "events"
        ]
        for s
        in expected.values()
    )

    if (
        total_expected
        != int(
            contract[
                "joined_supervised_events"
            ]
        )
    ):
        raise RuntimeError(
            "Fold mapping event total mismatch: "
            f"{scenario}="
            f"{total_expected:,}"
        )

    dataset_root = (
        (
            dataset_root_base
            or (
                output_root
                / "03_datasets"
                / "loso_network_dl_v1_1_15m"
            )
        )
        / fold_dir_template.format(
            fold=scenario
        )
    )

    artifact_dir = (
        (
            artifact_root_base
            or (
                output_root
                / "02_artifacts"
                / "08c_loso_dl_shards_v1_1_15m"
            )
        )
        / fold_dir_template.format(
            fold=scenario
        )
    )

    if reset:
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

    window_seconds = (
        int(
            window_minutes
        )
        * 60
    )

    contract_path = (
        frozen_dir
        / contract_name
    )

    build_config = {
        "script_version":
            SCRIPT_VERSION,
        "dataset_version":
            DATASET_VERSION,
        "experiment":
            (
                "Random scenario-stratified host split"
                if MAPPING_MODE == "random"
                else "Leave-One-Scenario-Out"
            ),
        **fold_label_fields(
            scenario
        ),
        "joined_root":
            str(
                joined_root
            ),
        "loso_contract_sha256":
            sha256_file(
                contract_path
            ),
        "loso_mapping_sha256":
            sha256_file(
                mapping_path
            ),
        "preprocess_frozen_fingerprint":
            preprocess_fp[
                "frozen_fingerprint_sha256"
            ],
        "window_minutes":
            int(
                window_minutes
            ),
        "window_seconds":
            int(
                window_seconds
            ),
        "max_events":
            int(
                max_events
            ),
        "shard_max_events":
            int(
                shard_max_events
            ),
        "compressed_npz":
            bool(
                compressed_npz
            ),
        "active_categorical_features":
            active_cat,
        "active_numerical_features":
            active_num,
        "binary_features": [
            "has_missed_bytes"
        ],
        "label_rule":
            (
                "chunk positive iff "
                ">=1 positive event"
            ),
        "split_policy":
            (
                "STEP 05F-B frozen LOSO "
                "hostname mapping"
            ),
        "logical_partition_policy":
            (
                "one source scan per UTC logical day; "
                "remap hostname -> LOSO split first; "
                "group by LOSO split + hostname + "
                "window_start; original STEP 04B "
                "split/date is not a sample boundary"
            ),
        "raw_ip_policy":
            (
                "Used transiently only for local "
                "REMOTE_ENDPOINT IDs; raw IP is not "
                "written into model tensors."
            ),
    }

    if EXCLUDE_RESP_IPS:
        build_config[
            "excluded_resp_ips"
        ] = list(
            EXCLUDE_RESP_IPS
        )

    config_path = (
        dataset_root
        / "build_config.json"
    )

    if (
        config_path.exists()
    ):
        existing = (
            base.load_json(
                config_path
            )
        )

        if (
            existing
            != build_config
        ):
            raise RuntimeError(
                "Existing fold dataset has "
                "different config. "
                "Use --reset-fold only if "
                "you intentionally rebuild."
            )
    else:
        dump_json(
            config_path,
            build_config,
        )

    print()
    print("=" * 108)
    print(
        f"STEP 05F-D — "
        f"hold out {scenario}"
    )
    print("=" * 108)
    print(
        f"[DATASET] {dataset_root}"
    )
    print(
        f"[MAPPING] {mapping_path}"
    )
    print(
        f"[PREPROCESS] {preprocess_dir}"
    )
    print(
        "[OPTIMIZATION] One source scan "
        "per logical day -> emit "
        "TRAIN/VAL/TEST together."
    )

    shard_root = (
        dataset_root
        / "shards"
    )

    spill_root = (
        artifact_dir
        / "_duckdb_spill"
    )

    days = (
        discover_fold_logical_days(
            joined_root=
                joined_root,
            mapping_path=
                mapping_path,
            threads=
                threads,
            memory_limit=
                memory_limit,
            spill_dir=
                spill_root,
        )
    )

    partition_reports = []

    for index, (
        day_index,
        logical_date,
    ) in enumerate(
        days,
        start=1,
    ):
        print(
            f"[DAY {index}/{len(days)}] "
            f"logical_date={logical_date}"
        )

        reports = (
            process_fold_day(
                scenario=
                    scenario,
                logical_date=
                    logical_date,
                day_start_epoch=
                    int(
                        day_index
                        * 86400
                    ),
                joined_root=
                    joined_root,
                mapping_path=
                    mapping_path,
                shard_root=
                    shard_root,
                active_cat=
                    active_cat,
                active_num=
                    active_num,
                maps=maps,
                numeric=numeric,
                window_seconds=
                    window_seconds,
                max_events=
                    max_events,
                shard_max_events=
                    shard_max_events,
                compressed_npz=
                    compressed_npz,
                threads=
                    threads,
                memory_limit=
                    memory_limit,
                arrow_batch_rows=
                    arrow_batch_rows,
                spill_dir=
                    spill_root,
            )
        )

        partition_reports.extend(
            reports
        )

        by_split = {
            r["split"]:
                r["stats"]
            for r in reports
        }

        print(
            "    "
            + " | ".join(
                (
                    f"{split.upper()}: "
                    f"events="
                    f"{by_split[split]['events']:,}, "
                    f"samples="
                    f"{by_split[split]['samples']:,}, "
                    f"pos="
                    f"{by_split[split]['positive_samples']:,}"
                )
                for split
                in SUPERVISED_SPLITS
            )
        )

    shutil.rmtree(
        spill_root,
        ignore_errors=True,
    )

    split_stats = (
        base.aggregate_stats(
            partition_reports
        )
    )

    for split in (
        SUPERVISED_SPLITS
    ):
        expected_events = int(
            expected[
                split
            ][
                "events"
            ]
        )

        expected_positive = int(
            expected[
                split
            ][
                "positive_events"
            ]
        )

        actual_events = int(
            split_stats[
                split
            ][
                "events"
            ]
        )

        actual_positive = int(
            split_stats[
                split
            ][
                "positive_events"
            ]
        )

        if (
            actual_events
            != expected_events
        ):
            raise RuntimeError(
                "EVENT CONSERVATION FAIL "
                f"fold={scenario} "
                f"split={split}: "
                f"expected="
                f"{expected_events:,}, "
                f"actual="
                f"{actual_events:,}"
            )

        if (
            actual_positive
            != expected_positive
        ):
            raise RuntimeError(
                "POSITIVE EVENT CONSERVATION FAIL "
                f"fold={scenario} "
                f"split={split}: "
                f"expected="
                f"{expected_positive:,}, "
                f"actual="
                f"{actual_positive:,}"
            )

    print()
    print(
        "[CHECK] Event + positive-event "
        "conservation PASS for "
        "TRAIN/VAL/TEST."
    )

    manifest_path = (
        base.merge_partition_manifests(
            dataset_root=
                dataset_root,
            partition_reports=
                partition_reports,
        )
    )

    preprocessing_copies = (
        base.copy_preprocess(
            dataset_root=
                dataset_root,
            source_paths=
                preprocess_paths,
        )
    )

    loso_metadata = (
        copy_loso_metadata(
            dataset_root=
                dataset_root,
            mapping_path=
                mapping_path,
            contract_path=
                contract_path,
        )
    )

    readme_path = (
        dataset_root
        / "README_DATASET.md"
    )

    write_loso_readme(
        path=
            readme_path,
        heldout_scenario=
            scenario,
        window_minutes=
            window_minutes,
        max_events=
            max_events,
        active_cat=
            active_cat,
        active_num=
            active_num,
        expected_stats=
            expected,
    )

    dataset_manifest = {
        "generated_at":
            base.now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "dataset_version":
            DATASET_VERSION,
        "build_config_sha256":
            base.sha256_obj(
                build_config
            ),
        "build_config":
            build_config,
        "source": {
            "step04b_joined_root":
                str(
                    joined_root
                ),
            "loso_contract":
                str(
                    contract_path
                ),
            "loso_contract_sha256":
                sha256_file(
                    contract_path
                ),
            "loso_mapping":
                str(
                    mapping_path
                ),
            "loso_mapping_sha256":
                sha256_file(
                    mapping_path
                ),
            "step05f_c_preprocess_fingerprint":
                preprocess_fp[
                    "frozen_fingerprint_sha256"
                ],
        },
        "expected_event_stats_from_frozen_mapping":
            expected,
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
                    "fold TRAIN sample-level "
                    "negative/positive count"
                ),
        },
        "loso_contract": {
            **fold_label_fields(
                scenario
            ),
            "heldout_scenario_used_for_preprocess_fit":
                False,
            "heldout_scenario_used_for_training":
                False,
            "test_policy":
                (
                    "open only after model and "
                    "VAL threshold freeze"
                ),
        },
    }

    dataset_manifest_path = (
        dataset_root
        / "dataset_manifest.json"
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
        *loso_metadata,
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

    report = {
        "generated_at":
            base.now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "status":
            "READY_FOR_STEP05F_D_VALIDATION",
        **fold_label_fields(
            scenario
        ),
        "decision": {
            "window_minutes":
                int(
                    window_minutes
                ),
            "max_events":
                int(
                    max_events
                ),
            "one_source_scan_per_logical_day":
                True,
            "same_representation_as_current_models":
                True,
        },
        "expected_event_stats":
            expected,
        "split_stats":
            split_stats,
        "dataset_root":
            str(
                dataset_root
            ),
        "sample_manifest":
            str(
                manifest_path
            ),
        "dataset_manifest":
            str(
                dataset_manifest_path
            ),
        "integrity":
            str(
                integrity_path
            ),
        "preprocess_fingerprint":
            preprocess_fp[
                "frozen_fingerprint_sha256"
            ],
        "loso_mapping_sha256":
            sha256_file(
                mapping_path
            ),
    }

    report_path = (
        artifact_dir
        / (
            "network_dl_shard_report.json"
            if RANDOM_NAMING
            else "network_dl_loso_shard_report.json"
        )
    )

    dump_json(
        report_path,
        report,
    )

    print()
    print("=" * 108)
    print(
        f"[SUCCESS] STEP 05F-D "
        f"{scenario} complete"
    )
    print(
        f"[DATASET] {dataset_root}"
    )
    print(
        f"[MANIFEST] {manifest_path}"
    )
    print(
        f"[REPORT] {report_path}"
    )

    for split in (
        SUPERVISED_SPLITS
    ):
        s = (
            split_stats[
                split
            ]
        )

        print(
            f"[{split.upper()}] "
            f"samples={s['samples']:,} | "
            f"positive="
            f"{s['positive_samples']:,} | "
            f"rate="
            f"{100*s['positive_sample_rate']:.4f}% | "
            f"events={s['events']:,} | "
            f"pos_weight="
            f"{s['pos_weight_neg_over_pos']}"
        )

    print("=" * 108)

    return report


def main() -> None:
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
        "--frozen-dir",
        default=None,
    )

    parser.add_argument(
        "--preprocess-root",
        default=None,
    )

    parser.add_argument(
        "--fold",
        default="all",
        help=(
            "all hoac ten mot fold trong contract "
            "(loso: scenario_1/2/3; random: seed_k)."
        ),
    )

    # ---- STEP 10C: tham số hóa để dùng lại cho split ngẫu nhiên (mặc định = LOSO cũ)
    parser.add_argument(
        "--mode",
        choices=["loso", "random"],
        default="loso",
    )

    parser.add_argument(
        "--contract-name",
        default=None,
        help=(
            "Mac dinh: loso_fold_contract.json (loso) / "
            "random_split_contract.json (random)."
        ),
    )

    parser.add_argument(
        "--artifact-dir",
        default=None,
        help=(
            "Mac dinh: 02_artifacts/08c_loso_dl_shards_v1_1_15m (loso) / "
            "10c_random_dl_shards_v1_1_15m (random)."
        ),
    )

    parser.add_argument(
        "--dataset-dir",
        default=None,
        help=(
            "Mac dinh: 03_datasets/loso_network_dl_v1_1_15m (loso) / "
            "random_network_dl_v1_1_15m (random)."
        ),
    )

    parser.add_argument(
        "--fold-dir-template",
        default=None,
        help=(
            "Mac dinh: holdout_{fold} (loso) / {fold} (random)."
        ),
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
        default=18.0,
    )

    parser.add_argument(
        "--allow-low-disk",
        action="store_true",
    )

    parser.add_argument(
        "--reset-fold",
        action="store_true",
    )

    args = parser.parse_args()

    base.require_packages()

    global MAPPING_MODE, RANDOM_NAMING, SPLIT_COL, SCRIPT_VERSION, DATASET_VERSION, EXCLUDE_RESP_IPS

    MAPPING_MODE = args.mode
    is_random = args.mode == "random"

    if is_random:
        RANDOM_NAMING = True
        SPLIT_COL = "assigned_split"
        SCRIPT_VERSION = (
            "step10c-random-split-network-dl-shards-v1.0"
        )
        DATASET_VERSION = "random-network-dl-v1.1-15m"

    contract_name = (
        args.contract_name
        or (
            "random_split_contract.json"
            if is_random
            else "loso_fold_contract.json"
        )
    )

    fold_dir_template = (
        args.fold_dir_template
        or (
            "{fold}"
            if is_random
            else "holdout_{fold}"
        )
    )

    output_root = Path(
        args.output_root
    )

    joined_root = (
        Path(
            args.joined_root
        )
        if args.joined_root
        else (
            output_root
            / "02_artifacts"
            / "02_network_joined_v1"
            / "joined"
        )
    )

    frozen_dir = (
        Path(
            args.frozen_dir
        )
        if args.frozen_dir
        else (
            output_root
            / "02_artifacts"
            / (
                "10a_random_split_v1"
                if is_random
                else "08a_loso_remap_v1"
            )
            / (
                ""
                if is_random
                else "frozen"
            )
        )
    )

    preprocess_root = (
        Path(
            args.preprocess_root
        )
        if args.preprocess_root
        else (
            output_root
            / "02_artifacts"
            / (
                "10b_random_preprocess_v1"
                if is_random
                else "08b_loso_preprocess_v1"
            )
        )
    )

    artifact_root_base = (
        Path(
            args.artifact_dir
        )
        if args.artifact_dir
        else (
            output_root
            / "02_artifacts"
            / (
                "10c_random_dl_shards_v1_1_15m"
                if is_random
                else "08c_loso_dl_shards_v1_1_15m"
            )
        )
    )

    dataset_root_base = (
        Path(
            args.dataset_dir
        )
        if args.dataset_dir
        else (
            output_root
            / "03_datasets"
            / (
                "random_network_dl_v1_1_15m"
                if is_random
                else "loso_network_dl_v1_1_15m"
            )
        )
    )

    if not joined_root.exists():
        raise FileNotFoundError(
            joined_root
        )

    (
        contract,
        mapping_paths,
    ) = verify_loso_contract(
        frozen_dir,
        contract_name=contract_name,
        expected_version=(
            RANDOM_CONTRACT_VERSION
            if is_random
            else LOSO_CONTRACT_VERSION
        ),
        expected_folds=(
            None
            if is_random
            else SCENARIOS
        ),
    )

    # STEP 11: contract co the yeu cau loai event theo IP dich (vd. beacon C2)
    EXCLUDE_RESP_IPS = tuple(
        contract.get(
            "excluded_resp_ips",
            [],
        )
    )

    if EXCLUDE_RESP_IPS:
        print(
            "[EXCLUDE] event co resp_h in "
            f"{list(EXCLUDE_RESP_IPS)} bi loai khi build shards"
        )

    if (
        args.fold != "all"
        and args.fold
        not in mapping_paths
    ):
        raise RuntimeError(
            f"Unknown fold {args.fold!r}; "
            f"contract has {sorted(mapping_paths)}."
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
            f"Need >= "
            f"{args.min_free_gib:.2f} GiB. "
            "Build one fold at a time or free disk."
        )

    print("=" * 108)
    print(
        "STEP 10C — Build random-split "
        if is_random
        else "STEP 05F-D — Build LOSO "
        "15-minute / 512-event DL shards"
    )
    print("=" * 108)
    print(
        f"[JOINED] {joined_root}"
    )
    print(
        f"[FROZEN {'SPLIT' if is_random else 'LOSO'}] {frozen_dir}"
    )
    print(
        f"[PREPROCESS] {preprocess_root}"
    )
    print(
        f"[FREE DISK] {free_gib:.2f} GiB"
    )
    print(
        "[IMPORTANT] Original STEP 04B split "
        "partitions are ignored for split assignment."
    )
    print(
        "[OPTIMIZATION] One joined-data scan "
        "per logical day/fold; emits "
        "TRAIN/VAL/TEST together."
    )

    selected = (
        list(
            mapping_paths
        )
        if args.fold == "all"
        else [
            args.fold
        ]
    )

    summary = {
        "generated_at":
            base.now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "selected_folds":
            selected,
        "folds":
            {},
    }

    for scenario in selected:
        report = build_one_fold(
            scenario=
                scenario,
            output_root=
                output_root,
            joined_root=
                joined_root,
            frozen_dir=
                frozen_dir,
            mapping_path=
                mapping_paths[
                    scenario
                ],
            contract=
                contract,
            preprocess_root=
                preprocess_root,
            window_minutes=
                args.window_minutes,
            max_events=
                args.max_events,
            shard_max_events=
                args.shard_max_events,
            arrow_batch_rows=
                args.arrow_batch_rows,
            threads=
                args.threads,
            memory_limit=
                args.duckdb_memory_limit,
            compressed_npz=
                args.compressed_npz,
            reset=
                args.reset_fold,
            contract_name=
                contract_name,
            dataset_root_base=
                dataset_root_base,
            artifact_root_base=
                artifact_root_base,
            fold_dir_template=
                fold_dir_template,
        )

        summary[
            "folds"
        ][scenario] = report

    summary_path = (
        artifact_root_base
        / (
            "STEP_10C_RANDOM_SHARDS_SUMMARY_"
            + "_".join(selected)
            + ".json"
            if is_random
            else "STEP_05F_D_LOSO_SHARDS_SUMMARY.json"
        )
    )

    dump_json(
        summary_path,
        summary,
    )

    print()
    print("=" * 108)
    print(
        "[SUCCESS] Requested STEP 05F-D "
        "fold(s) complete"
    )
    print(
        f"[SUMMARY] {summary_path}"
    )
    print(
        "[NEXT] Validate each generated fold "
        "before Kaggle upload/training."
    )
    print("=" * 108)


if __name__ == "__main__":
    main()
