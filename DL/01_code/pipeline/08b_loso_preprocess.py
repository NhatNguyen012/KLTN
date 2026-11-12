from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import network_schema  # noqa: E402


SCRIPT_VERSION = "step05f-c-loso-train-only-preprocess-v1.0"
PROFILE_VERSION = "step05f-c-host-profile-v1.0"

# STEP 10B: script dùng lại cho split ngẫu nhiên (--mode random). Mặc định giữ hành vi LOSO cũ.
LOSO_CONTRACT_VERSION = "step05f-b-loso-remap-audit-v1.1-zero-row-safe"
RANDOM_CONTRACT_VERSION = "step10a-random-scenario-split-v1.0"
LOSO_FOLDS = ("scenario_1", "scenario_2", "scenario_3")
EXPERIMENT_LABEL = "LOSO scenario generalization"

# Danh sach feature, ID dac biet, bang cong: doc tu network_event_schema_v1.json (nguon duy nhat, xem network_schema.py)
SCHEMA = network_schema.load_schema()

BASE_CATEGORICAL_FIELDS = list(SCHEMA["categorical"]["base_fields"])

DERIVED_CATEGORICAL_FIELDS = list(SCHEMA["categorical"]["derived_fields"])

ALL_CATEGORICAL_FIELDS = (
    BASE_CATEGORICAL_FIELDS
    + DERIVED_CATEGORICAL_FIELDS
)

NUMERIC_FIELDS = list(SCHEMA["numeric"]["fields"])

RESERVED_IDS = dict(SCHEMA["categorical"]["reserved_ids"])

SUPERVISED_SPLITS = (
    "train",
    "val",
    "test",
)

COMMON_PORTS = network_schema.common_ports(SCHEMA)


def now_iso() -> str:
    return datetime.now().isoformat()


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
    raw: bool = False,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_text(
        json.dumps(
            obj
            if raw
            else neutral(obj),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(
            lambda: f.read(
                1024 * 1024
            ),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def sql_path(path: Path) -> str:
    return (
        str(path)
        .replace("\\", "/")
        .replace("'", "''")
    )


def require_duckdb():
    try:
        import duckdb
    except ImportError as exc:
        raise RuntimeError(
            "STEP 05F-C cần DuckDB.\n"
            "Chạy: python -m pip install duckdb pandas"
        ) from exc

    return duckdb


def duckdb_connect(
    *,
    threads: int,
    memory_limit: str,
    temp_dir: Path,
):
    duckdb = require_duckdb()

    temp_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    db = duckdb.connect(
        database=":memory:"
    )

    db.execute(
        f"PRAGMA threads={int(threads)}"
    )
    db.execute(
        f"PRAGMA memory_limit='{memory_limit}'"
    )
    db.execute(
        f"SET temp_directory="
        f"'{sql_path(temp_dir)}'"
    )
    db.execute(
        "SET preserve_insertion_order=false"
    )

    return db


def joined_dataset_signature(
    joined_root: Path,
) -> dict[str, Any]:
    files = sorted(
        joined_root.rglob(
            "*.parquet"
        )
    )

    if not files:
        raise FileNotFoundError(
            f"No Parquet under {joined_root}"
        )

    h = hashlib.sha256()
    total_bytes = 0

    for path in files:
        stat = path.stat()
        rel = path.relative_to(
            joined_root
        ).as_posix()

        line = (
            f"{rel}\t"
            f"{stat.st_size}\t"
            f"{stat.st_mtime_ns}\n"
        )

        h.update(
            line.encode("utf-8")
        )

        total_bytes += (
            stat.st_size
        )

    return {
        "parquet_files":
            len(files),
        "compressed_bytes":
            total_bytes,
        "metadata_sha256":
            h.hexdigest(),
    }


def validate_04b_report(
    report: dict[str, Any],
    expected_supervised_rows: int,
) -> dict[str, int]:
    if (
        report.get(
            "script_version"
        )
        != "step04b-network-exact-join-v1.0"
    ):
        raise RuntimeError(
            "Unexpected STEP 04B report version: "
            f"{report.get('script_version')!r}"
        )

    joined = report.get(
        "joined",
        {},
    )

    if int(
        joined.get(
            "missing_label_rows",
            -1,
        )
    ) != 0:
        raise RuntimeError(
            "STEP 04B still has missing labels."
        )

    rows_by_split = (
        joined.get(
            "rows_by_split",
            {}
        )
    )

    supervised = sum(
        int(
            rows_by_split.get(
                split,
                0,
            )
        )
        for split in SUPERVISED_SPLITS
    )

    if (
        supervised
        != expected_supervised_rows
    ):
        raise RuntimeError(
            "STEP 04B supervised row total "
            "does not match frozen LOSO contract:\n"
            f"04B={supervised:,}\n"
            f"contract="
            f"{expected_supervised_rows:,}"
        )

    return {
        split:
            int(
                rows_by_split.get(
                    split,
                    0,
                )
            )
        for split
        in SUPERVISED_SPLITS
    }


def verify_frozen_contract(
    frozen_dir: Path,
    contract_name: str = "loso_fold_contract.json",
    expected_version: str = LOSO_CONTRACT_VERSION,
    expected_folds: tuple[str, ...] | None = LOSO_FOLDS,
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

    if (
        contract.get(
            "rules",
            {},
        ).get("physical_joined_copy")
        is not False
    ):
        raise RuntimeError(
            "Unexpected physical_joined_copy policy."
        )

    mappings: dict[
        str,
        Path,
    ] = {}

    for scenario, info in (
        contract.get(
            "folds",
            {}
        ).items()
    ):
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
                f"expected="
                f"{info['sha256']}\n"
                f"actual={actual}"
            )

        mappings[
            scenario
        ] = path

    if (
        expected_folds is not None
        and set(mappings)
        != set(expected_folds)
    ):
        raise RuntimeError(
            f"Expected exactly folds {sorted(expected_folds)}, "
            f"got {sorted(mappings)}."
        )

    return (
        contract,
        mappings,
    )


def normalize_cat_sql(
    column: str,
) -> str:
    return f"""
        CASE
            WHEN {column} IS NULL
                THEN '<MISSING>'
            WHEN trim(
                CAST(
                    {column}
                    AS VARCHAR
                )
            ) = ''
                THEN '<MISSING>'
            WHEN lower(
                trim(
                    CAST(
                        {column}
                        AS VARCHAR
                    )
                )
            ) IN (
                '-',
                '(empty)',
                'null',
                'none',
                'nan'
            )
                THEN '<MISSING>'
            ELSE lower(
                trim(
                    CAST(
                        {column}
                        AS VARCHAR
                    )
                )
            )
        END
    """.strip()


def ip_scope_sql(
    column: str,
) -> str:
    c = (
        f"lower(trim("
        f"CAST({column} AS VARCHAR)"
        f"))"
    )

    return f"""
        CASE
            WHEN {column} IS NULL
                OR trim(
                    CAST(
                        {column}
                        AS VARCHAR
                    )
                ) = ''
                OR {c} IN (
                    '-',
                    '(empty)',
                    'null',
                    'none'
                )
                THEN '<MISSING>'

            WHEN {c} = '::1'
                OR regexp_matches(
                    {c},
                    '^127\\.'
                )
                THEN 'LOOPBACK'

            WHEN regexp_matches(
                    {c},
                    '^10\\.'
                )
                OR regexp_matches(
                    {c},
                    '^192\\.168\\.'
                )
                OR regexp_matches(
                    {c},
                    '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'
                )
                THEN 'PRIVATE'

            WHEN regexp_matches(
                    {c},
                    '^169\\.254\\.'
                )
                OR regexp_matches(
                    {c},
                    '^fe80:'
                )
                THEN 'LINK_LOCAL'

            WHEN regexp_matches(
                    {c},
                    '^(fc|fd)'
                )
                THEN 'PRIVATE_IPV6'

            WHEN regexp_matches(
                    {c},
                    '^(22[4-9]|23[0-9])\\.'
                )
                OR regexp_matches(
                    {c},
                    '^ff'
                )
                THEN 'MULTICAST'

            WHEN {c}
                = '255.255.255.255'
                THEN 'BROADCAST'

            WHEN regexp_matches(
                    {c},
                    '^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}$'
                )
                THEN 'PUBLIC_IPV4'

            WHEN strpos(
                    {c},
                    ':'
                ) > 0
                THEN 'PUBLIC_IPV6'

            ELSE 'OTHER'
        END
    """.strip()


def port_class_sql(
    column: str,
) -> str:
    common = "\n".join(
        (
            f"WHEN {column} = {port} "
            f"THEN 'PORT_{port}_{name}'"
        )
        for port, name
        in sorted(
            COMMON_PORTS.items()
        )
    )

    return f"""
        CASE
            WHEN {column} IS NULL
                THEN '<MISSING>'

            {common}

            WHEN {column}
                BETWEEN 0 AND 1023
                THEN 'WELL_KNOWN_OTHER'

            WHEN {column}
                BETWEEN 1024 AND 49151
                THEN 'REGISTERED'

            WHEN {column}
                BETWEEN 49152 AND 65535
                THEN 'EPHEMERAL'

            ELSE 'OTHER'
        END
    """.strip()


def _numeric_expr(
    field: str,
) -> str:
    return f"""
        CASE
            WHEN {field} IS NULL
                OR {field} < 0
                THEN NULL
            ELSE ln(
                1.0
                + CAST(
                    {field}
                    AS DOUBLE
                )
            )
        END
    """.strip()


def category_profile_query(
    source_glob: str,
) -> str:
    grouping_sets = ",\n".join(
        (
            f"(hostname, {field})"
        )
        for field
        in ALL_CATEGORICAL_FIELDS
    )

    field_case = "\n".join(
        (
            f"WHEN GROUPING({field}) = 0 "
            f"THEN '{field}'"
        )
        for field
        in ALL_CATEGORICAL_FIELDS
    )

    value_coalesce = ", ".join(
        ALL_CATEGORICAL_FIELDS
    )

    return f"""
        WITH base AS (
            SELECT
                hostname,

                {normalize_cat_sql('app_family')}
                    AS app_family,

                {normalize_cat_sql('direction')}
                    AS direction,

                {normalize_cat_sql('proto')}
                    AS proto,

                {normalize_cat_sql('service')}
                    AS service,

                {normalize_cat_sql('conn_state')}
                    AS conn_state,

                {normalize_cat_sql('local_orig')}
                    AS local_orig,

                {normalize_cat_sql('local_resp')}
                    AS local_resp,

                {ip_scope_sql('orig_h')}
                    AS orig_ip_scope,

                {ip_scope_sql('resp_h')}
                    AS resp_ip_scope,

                {port_class_sql('orig_p')}
                    AS orig_port_class,

                {port_class_sql('resp_p')}
                    AS resp_port_class

            FROM read_parquet(
                '{source_glob}',
                hive_partitioning=true
            )

            WHERE
                split IN (
                    'train',
                    'val',
                    'test'
                )
                AND hostname IS NOT NULL
                AND trim(hostname) <> ''
        )

        SELECT
            hostname,

            CASE
                {field_case}
                ELSE 'unknown'
            END
                AS field,

            COALESCE(
                {value_coalesce},
                '<MISSING>'
            )
                AS value,

            count(*)::BIGINT
                AS n

        FROM base

        GROUP BY GROUPING SETS (
            {grouping_sets}
        )

        ORDER BY
            hostname,
            field,
            n DESC,
            value
    """


def numeric_profile_query(
    source_glob: str,
) -> str:
    parts = [
        "hostname",
        (
            "count(*)::BIGINT "
            "AS row_count"
        ),
    ]

    for field in NUMERIC_FIELDS:
        expr = _numeric_expr(
            field
        )

        parts.extend([
            (
                f"count({expr})::BIGINT "
                f"AS {field}__observed"
            ),
            (
                "sum("
                f"CASE WHEN {field} IS NULL "
                f"OR {field} < 0 "
                "THEN 1 ELSE 0 END"
                f")::BIGINT "
                f"AS {field}__missing"
            ),
            (
                f"sum({expr}) "
                f"AS {field}__sum"
            ),
            (
                f"sum(({expr}) * ({expr})) "
                f"AS {field}__sumsq"
            ),
            (
                f"min({field}) "
                f"AS {field}__raw_min"
            ),
            (
                f"max({field}) "
                f"AS {field}__raw_max"
            ),
        ])

    return f"""
        SELECT
            {", ".join(parts)}

        FROM read_parquet(
            '{source_glob}',
            hive_partitioning=true
        )

        WHERE
            split IN (
                'train',
                'val',
                'test'
            )
            AND hostname IS NOT NULL
            AND trim(hostname) <> ''

        GROUP BY hostname

        ORDER BY hostname
    """


def build_or_reuse_host_profiles(
    *,
    joined_root: Path,
    artifact_dir: Path,
    report04b_sha256: str,
    contract_file_sha256: str,
    contract: dict[str, Any],
    threads: int,
    memory_limit: str,
    rebuild: bool,
    profile_source_dir: Path | None = None,
) -> tuple[
    Path,
    Path,
    dict[str, Any],
]:
    shared_dir = (
        artifact_dir
        / "_shared_host_profiles"
    )

    shared_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    cat_path = (
        shared_dir
        / "host_category_counts.parquet"
    )

    num_path = (
        shared_dir
        / "host_numeric_moments.parquet"
    )

    state_path = (
        shared_dir
        / "profile_state.json"
    )

    temp_dir = (
        shared_dir
        / "_duckdb_spill"
    )

    dataset_sig = (
        joined_dataset_signature(
            joined_root
        )
    )

    desired_state = {
        "profile_version":
            PROFILE_VERSION,
        "joined_root":
            str(
                joined_root.resolve()
            ),
        "joined_dataset_signature":
            dataset_sig,
        "report04b_sha256":
            report04b_sha256,
        "loso_contract_file_sha256":
            contract_file_sha256,
        "expected_supervised_rows":
            int(
                contract[
                    "joined_supervised_events"
                ]
            ),
    }

    if (
        not rebuild
        and cat_path.exists()
        and num_path.exists()
        and state_path.exists()
    ):
        old_state = load_json(
            state_path
        )

        if (
            old_state
            == neutral(desired_state)
        ):
            print(
                "[PROFILE CACHE] "
                "Input signature match -> "
                "reuse per-host profiles."
            )

            return (
                cat_path,
                num_path,
                desired_state,
            )

        raise RuntimeError(
            "Cached STEP 05F-C host profiles "
            "exist but input signature changed.\n"
            "If this is intentional, rerun with "
            "--rebuild-profile."
        )

    # STEP 10B: profile theo host không phụ thuộc split -> dùng lại bản đã có
    # (chỉ đọc thư mục nguồn, copy sang artifact mới). Xác thực bằng các trường
    # không phụ thuộc đường dẫn/mtime: số file, tổng bytes, sha report 04B, số row.
    if (
        not rebuild
        and profile_source_dir is not None
    ):
        src_state_path = (
            profile_source_dir
            / "profile_state.json"
        )
        src_cat = (
            profile_source_dir
            / "host_category_counts.parquet"
        )
        src_num = (
            profile_source_dir
            / "host_numeric_moments.parquet"
        )

        if all(
            p.exists()
            for p in (
                src_state_path,
                src_cat,
                src_num,
            )
        ):
            old = load_json(
                src_state_path
            )
            old_sig = old.get(
                "joined_dataset_signature",
                {},
            )

            compatible = (
                old.get("profile_version")
                == PROFILE_VERSION
                and old.get("report04b_sha256")
                == report04b_sha256
                and int(
                    old.get(
                        "expected_supervised_rows",
                        -1,
                    )
                )
                == desired_state[
                    "expected_supervised_rows"
                ]
                and old_sig.get("parquet_files")
                == dataset_sig["parquet_files"]
                and old_sig.get("compressed_bytes")
                == dataset_sig["compressed_bytes"]
            )

            if compatible:
                shutil.copy2(
                    src_cat,
                    cat_path,
                )
                shutil.copy2(
                    src_num,
                    num_path,
                )
                dump_json(
                    state_path,
                    desired_state,
                )
                dump_json(
                    shared_dir
                    / "profile_reuse_note.json",
                    {
                        "reused_from":
                            str(profile_source_dir),
                        "source_state":
                            old,
                        "validated_fields": [
                            "profile_version",
                            "report04b_sha256",
                            "expected_supervised_rows",
                            "parquet_files",
                            "compressed_bytes",
                        ],
                    },
                    raw=True,
                )

                print(
                    "[PROFILE REUSE] "
                    f"copied per-host profiles from "
                    f"{profile_source_dir}"
                )

                return (
                    cat_path,
                    num_path,
                    desired_state,
                )

        print(
            "[PROFILE REUSE] source missing or "
            "incompatible -> rebuild from joined "
            "Parquet."
        )

    for path in (
        cat_path,
        num_path,
    ):
        if path.exists():
            path.unlink()

    db = duckdb_connect(
        threads=threads,
        memory_limit=
            memory_limit,
        temp_dir=temp_dir,
    )

    source_glob = sql_path(
        joined_root
        / "**"
        / "*.parquet"
    )

    try:
        print()
        print(
            "[PROFILE 1/2] "
            "Scan categorical counts per hostname..."
        )

        q_cat = (
            category_profile_query(
                source_glob
            )
        )

        db.execute(
            f"""
            COPY (
                {q_cat}
            )
            TO '{sql_path(cat_path)}'
            (
                FORMAT PARQUET,
                COMPRESSION ZSTD
            )
            """
        )

        print(
            "[PROFILE 2/2] "
            "Scan numerical moments per hostname..."
        )

        q_num = (
            numeric_profile_query(
                source_glob
            )
        )

        db.execute(
            f"""
            COPY (
                {q_num}
            )
            TO '{sql_path(num_path)}'
            (
                FORMAT PARQUET,
                COMPRESSION ZSTD
            )
            """
        )

    finally:
        db.close()

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )

    dump_json(
        state_path,
        desired_state,
    )

    print(
        "[PROFILE] Shared compact host profiles created."
    )

    return (
        cat_path,
        num_path,
        desired_state,
    )


def read_parquet_df(
    path: Path,
) -> pd.DataFrame:
    duckdb = require_duckdb()

    db = duckdb.connect(
        database=":memory:"
    )

    try:
        return db.execute(
            f"""
            SELECT *
            FROM read_parquet(
                '{sql_path(path)}'
            )
            """
        ).fetchdf()

    finally:
        db.close()


def field_policy(
    *,
    field: str,
    app_min_freq: int,
    service_min_freq: int,
    default_min_freq: int,
    app_max_values: int,
    service_max_values: int,
    default_max_values: int,
) -> tuple[int, int]:
    if field == "app_family":
        return (
            app_min_freq,
            app_max_values,
        )

    if field == "service":
        return (
            service_min_freq,
            service_max_values,
        )

    if (
        field
        in DERIVED_CATEGORICAL_FIELDS
    ):
        return (
            1,
            256,
        )

    return (
        default_min_freq,
        default_max_values,
    )


def fold_category_counts(
    *,
    host_cat: pd.DataFrame,
    mapping: pd.DataFrame,
) -> dict[
    str,
    dict[
        str,
        dict[str, int]
    ],
]:
    m = mapping[
        [
            "hostname",
            "loso_split",
        ]
    ].copy()

    merged = host_cat.merge(
        m,
        on="hostname",
        how="left",
        validate="many_to_one",
    )

    if (
        merged[
            "loso_split"
        ].isna().any()
    ):
        missing_hosts = (
            merged.loc[
                merged[
                    "loso_split"
                ].isna(),
                "hostname",
            ]
            .astype(str)
            .drop_duplicates()
            .tolist()
        )

        raise RuntimeError(
            "Host category profile contains "
            "hostnames absent from frozen mapping: "
            f"{missing_hosts[:20]}"
        )

    grouped = (
        merged.groupby(
            [
                "loso_split",
                "field",
                "value",
            ],
            as_index=False,
            sort=False,
        )["n"]
        .sum()
    )

    result: dict[
        str,
        dict[
            str,
            dict[str, int]
        ],
    ] = {}

    for row in (
        grouped.itertuples(
            index=False
        )
    ):
        split = str(
            row.loso_split
        )
        field = str(
            row.field
        )
        value = str(
            row.value
        )
        count = int(
            row.n
        )

        result.setdefault(
            split,
            {},
        ).setdefault(
            field,
            {},
        )[value] = count

    return result


def combine_numeric_profile(
    *,
    host_num: pd.DataFrame,
    mapping: pd.DataFrame,
) -> dict[
    str,
    dict[str, Any],
]:
    m = mapping[
        [
            "hostname",
            "loso_split",
        ]
    ].copy()

    merged = host_num.merge(
        m,
        on="hostname",
        how="left",
        validate="one_to_one",
    )

    if (
        merged[
            "loso_split"
        ].isna().any()
    ):
        missing_hosts = (
            merged.loc[
                merged[
                    "loso_split"
                ].isna(),
                "hostname",
            ]
            .astype(str)
            .tolist()
        )

        raise RuntimeError(
            "Host numeric profile contains "
            "hostnames absent from frozen mapping: "
            f"{missing_hosts[:20]}"
        )

    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for split in SUPERVISED_SPLITS:
        subset = merged[
            merged[
                "loso_split"
            ] == split
        ]

        row_count = int(
            subset[
                "row_count"
            ].sum()
        )

        split_out: dict[
            str,
            Any,
        ] = {
            "row_count":
                row_count,
            "features":
                {},
        }

        for field in NUMERIC_FIELDS:
            observed = int(
                subset[
                    f"{field}__observed"
                ].sum()
            )

            missing = int(
                subset[
                    f"{field}__missing"
                ].sum()
            )

            total_sum = float(
                subset[
                    f"{field}__sum"
                ].fillna(
                    0.0
                ).sum()
            )

            total_sumsq = float(
                subset[
                    f"{field}__sumsq"
                ].fillna(
                    0.0
                ).sum()
            )

            if observed > 0:
                mean = (
                    total_sum
                    / observed
                )

                variance = max(
                    0.0,
                    (
                        total_sumsq
                        / observed
                    )
                    - mean * mean,
                )

                std = math.sqrt(
                    variance
                )
            else:
                mean = 0.0
                std = 0.0

            raw_min_series = (
                subset[
                    f"{field}__raw_min"
                ].dropna()
            )

            raw_max_series = (
                subset[
                    f"{field}__raw_max"
                ].dropna()
            )

            raw_min = (
                raw_min_series.min()
                if len(
                    raw_min_series
                )
                else None
            )

            raw_max = (
                raw_max_series.max()
                if len(
                    raw_max_series
                )
                else None
            )

            if hasattr(
                raw_min,
                "item",
            ):
                raw_min = (
                    raw_min.item()
                )

            if hasattr(
                raw_max,
                "item",
            ):
                raw_max = (
                    raw_max.item()
                )

            split_out[
                "features"
            ][field] = {
                "observed":
                    observed,
                "missing":
                    missing,
                "missing_rate":
                    (
                        missing
                        / row_count
                        if row_count
                        else 0.0
                    ),
                "log1p_mean":
                    float(mean),
                "log1p_std":
                    float(std),
                "raw_min":
                    raw_min,
                "raw_max":
                    raw_max,
            }

        result[
            split
        ] = split_out

    return result


def build_category_maps(
    counts: dict[
        str,
        dict[
            str,
            dict[str, int]
        ],
    ],
    *,
    app_min_freq: int,
    service_min_freq: int,
    default_min_freq: int,
    app_max_values: int,
    service_max_values: int,
    default_max_values: int,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    train = counts.get(
        "train",
        {},
    )

    maps: dict[
        str,
        Any,
    ] = {
        "version":
            "network-category-maps-v1.1",
        "reserved_ids":
            RESERVED_IDS,
        "fit_split":
            "train",
        "fields":
            {},
    }

    diagnostics: dict[
        str,
        Any,
    ] = {}

    for field in (
        ALL_CATEGORICAL_FIELDS
    ):
        train_counts = dict(
            train.get(
                field,
                {},
            )
        )

        min_freq, max_values = (
            field_policy(
                field=field,
                app_min_freq=
                    app_min_freq,
                service_min_freq=
                    service_min_freq,
                default_min_freq=
                    default_min_freq,
                app_max_values=
                    app_max_values,
                service_max_values=
                    service_max_values,
                default_max_values=
                    default_max_values,
            )
        )

        candidates = [
            (
                value,
                int(count),
            )
            for value, count
            in train_counts.items()
            if (
                value
                != "<MISSING>"
                and int(count)
                >= min_freq
            )
        ]

        candidates.sort(
            key=lambda item: (
                -item[1],
                item[0],
            )
        )

        candidates = (
            candidates[
                :max_values
            ]
        )

        mapping = dict(
            RESERVED_IDS
        )

        next_id = 2

        for (
            value,
            _count,
        ) in candidates:
            if (
                value
                in mapping
            ):
                continue

            mapping[
                value
            ] = next_id

            next_id += 1

        maps[
            "fields"
        ][field] = {
            "mapping":
                mapping,
            "size":
                len(
                    mapping
                ),
            "min_train_frequency":
                min_freq,
            "max_values_excluding_reserved":
                max_values,
        }

        known = set(
            mapping.keys()
        )

        train_rows = int(
            sum(
                train_counts.values()
            )
        )

        train_missing = int(
            train_counts.get(
                "<MISSING>",
                0,
            )
        )

        train_unique = len(
            train_counts
        )

        varying_missing = (
            0
            < train_missing
            < train_rows
        )

        active = (
            train_unique > 1
            or varying_missing
        )

        maps[
            "fields"
        ][field][
            "active_for_model"
        ] = bool(active)

        diag: dict[
            str,
            Any,
        ] = {
            "train_unique_values_including_missing":
                train_unique,
            "mapping_size_including_reserved":
                len(
                    mapping
                ),
            "min_train_frequency":
                min_freq,
            "max_values_excluding_reserved":
                max_values,
            "by_split":
                {},
        }

        for split in (
            SUPERVISED_SPLITS
        ):
            split_counts = (
                counts.get(
                    split,
                    {},
                ).get(
                    field,
                    {},
                )
            )

            n = int(
                sum(
                    split_counts.values()
                )
            )

            missing = int(
                split_counts.get(
                    "<MISSING>",
                    0,
                )
            )

            unk = int(
                sum(
                    int(count)
                    for value, count
                    in split_counts.items()
                    if (
                        value
                        not in known
                        and value
                        != "<MISSING>"
                    )
                )
            )

            diag[
                "by_split"
            ][split] = {
                "rows":
                    n,
                "missing":
                    missing,
                "missing_rate":
                    (
                        missing / n
                        if n
                        else 0.0
                    ),
                "mapped_to_UNK":
                    unk,
                "UNK_rate":
                    (
                        unk / n
                        if n
                        else 0.0
                    ),
            }

        diagnostics[
            field
        ] = diag

    return (
        maps,
        diagnostics,
    )


def build_numeric_stats(
    numeric_profile: dict[
        str,
        dict[str, Any],
    ],
    *,
    min_numeric_std: float,
    zscore_clip_abs: float,
) -> tuple[
    dict[str, Any],
    list[str],
    dict[str, str],
]:
    train = numeric_profile.get(
        "train"
    )

    if not train:
        raise RuntimeError(
            "No TRAIN numerical profile."
        )

    result: dict[
        str,
        Any,
    ] = {
        "version":
            "network-numeric-stats-v1.1",
        "fit_split":
            "train",
        "transform":
            (
                "log1p_nonnegative_"
                "then_zscore"
            ),
        "zscore_clip_abs":
            float(
                zscore_clip_abs
            ),
        "missing_policy": {
            "normalized_value":
                0.0,
            "parallel_missing_mask":
                True,
            "note": (
                "0.0 after z-score "
                "corresponds to TRAIN mean. "
                "Missing is distinguished "
                "by x_num_missing mask."
            ),
        },
        "features":
            {},
    }

    active_num: list[
        str
    ] = []

    inactive_num: dict[
        str,
        str
    ] = {}

    for field in NUMERIC_FIELDS:
        info = train[
            "features"
        ][field]

        std = float(
            info[
                "log1p_std"
            ]
        )

        scale = (
            std
            if std > 1e-12
            else 1.0
        )

        active = (
            std
            >= min_numeric_std
        )

        if active:
            active_num.append(
                field
            )
        else:
            inactive_num[
                field
            ] = (
                "TRAIN log1p "
                f"std={std:.9f} "
                f"< {min_numeric_std}; "
                "raw z-score would be "
                "unstable for rare "
                "non-zero values"
            )

        result[
            "features"
        ][field] = {
            "log1p_mean":
                float(
                    info[
                        "log1p_mean"
                    ]
                ),
            "log1p_std":
                std,
            "scale_used":
                scale,
            "train_observed":
                int(
                    info[
                        "observed"
                    ]
                ),
            "train_missing":
                int(
                    info[
                        "missing"
                    ]
                ),
            "train_missing_rate":
                float(
                    info[
                        "missing_rate"
                    ]
                ),
            "raw_train_min":
                info[
                    "raw_min"
                ],
            "raw_train_max":
                info[
                    "raw_max"
                ],
            "active_for_model":
                bool(active),
            "zscore_clip_abs":
                float(
                    zscore_clip_abs
                ),
        }

    return (
        result,
        active_num,
        inactive_num,
    )


def build_spec(
    *,
    heldout_scenario: str,
    category_maps:
        dict[str, Any],
    numeric_stats:
        dict[str, Any],
    category_diagnostics:
        dict[str, Any],
    active_num:
        list[str],
    inactive_num:
        dict[str, str],
    min_numeric_std:
        float,
    zscore_clip_abs:
        float,
    supervised_rows:
        int,
) -> dict[str, Any]:
    active_cat: list[
        str
    ] = []

    inactive_cat: dict[
        str,
        str,
    ] = {}

    for field in (
        ALL_CATEGORICAL_FIELDS
    ):
        active = bool(
            category_maps[
                "fields"
            ][field][
                "active_for_model"
            ]
        )

        if active:
            active_cat.append(
                field
            )
        else:
            inactive_cat[
                field
            ] = (
                "constant_on_fold_train; "
                "kept only for "
                "audit/reproducibility"
            )

    derived_binary = [
        {
            "name":
                "has_missed_bytes",
            "source":
                "missed_bytes",
            "rule":
                (
                    "1.0 if "
                    "missed_bytes > 0 "
                    "else 0.0"
                ),
            "fit_required":
                False,
            "reason":
                (
                    "Preserve rare "
                    "missed-bytes signal "
                    "without unstable "
                    "z-score."
                ),
        }
    ]

    return {
        "version":
            "network-preprocess-spec-v1.1",
        "experiment":
            EXPERIMENT_LABEL,
        "heldout_scenario":
            heldout_scenario,
        "fit_split":
            "train",
        "fit_scope":
            (
                "STEP 05F-B frozen "
                "LOSO fold TRAIN only"
            ),
        "split_source":
            (
                "STEP 05F-B frozen "
                "hostname LOSO mapping"
            ),
        "input_contract":
            "network-feature-contract-v1.0",
        "profiled_categorical_features":
            ALL_CATEGORICAL_FIELDS,
        "active_categorical_features":
            active_cat,
        "inactive_categorical_features":
            inactive_cat,
        "profiled_numerical_features":
            NUMERIC_FIELDS,
        "active_numerical_features":
            active_num,
        "inactive_numerical_features":
            inactive_num,
        "derived_binary_features":
            derived_binary,
        "categorical_reserved_ids":
            RESERVED_IDS,
        "derived_rules": {
            "ip_scope": [
                "<MISSING>",
                "LOOPBACK",
                "PRIVATE",
                "PRIVATE_IPV6",
                "LINK_LOCAL",
                "MULTICAST",
                "BROADCAST",
                "PUBLIC_IPV4",
                "PUBLIC_IPV6",
                "OTHER",
            ],
            "port_class_common_ports":
                COMMON_PORTS,
            "port_class_fallbacks": [
                "WELL_KNOWN_OTHER",
                "REGISTERED",
                "EPHEMERAL",
                "OTHER",
                "<MISSING>",
            ],
        },
        "numeric_transform":
            (
                "log1p_nonnegative_"
                "then_train_zscore_"
                "then_clip"
            ),
        "numeric_zscore_clip_abs":
            float(
                zscore_clip_abs
            ),
        "numeric_missing_policy": {
            **numeric_stats[
                "missing_policy"
            ],
            "clip_after_zscore": [
                -float(
                    zscore_clip_abs
                ),
                float(
                    zscore_clip_abs
                ),
            ],
        },
        "selection_policy": {
            "categorical_active_rule":
                (
                    "Field must vary "
                    "on fold TRAIN or "
                    "have varying TRAIN "
                    "missingness."
                ),
            "numeric_active_rule":
                (
                    "Fold TRAIN log1p "
                    f"std >= "
                    f"{min_numeric_std}."
                ),
            "label_used_for_feature_selection":
                False,
            "val_used_for_feature_selection":
                False,
            "test_used_for_feature_selection":
                False,
            "heldout_scenario_used_for_fit":
                False,
        },
        "non_predictive_fields": [
            "uid",
            "hostname",
            "split",
            "loso_split",
            "label",
            "raw exact timestamp",
            (
                "raw global IP identity "
                "as learned category"
            ),
        ],
        "graph_construction_fields_kept_raw_until_step05f_d": [
            "orig_h",
            "orig_p",
            "resp_h",
            "resp_p",
        ],
        "loso_supervised_rows":
            int(
                supervised_rows
            ),
        "next_step":
            (
                "STEP 05F-D builds "
                "fold-specific "
                "(hostname, 15-minute-"
                "window, chunk) "
                "sequence/graph shards "
                "using this frozen "
                "preprocessing."
            ),
    }


def build_fold(
    *,
    heldout_scenario: str,
    mapping_path: Path,
    mapping_sha256: str,
    host_cat: pd.DataFrame,
    host_num: pd.DataFrame,
    artifact_dir: Path,
    contract: dict[str, Any],
    contract_file_sha256: str,
    report04b_sha256: str,
    profile_state: dict[str, Any],
    app_min_freq: int,
    service_min_freq: int,
    default_min_freq: int,
    app_max_values: int,
    service_max_values: int,
    default_max_values: int,
    min_numeric_std: float,
    zscore_clip_abs: float,
    mapping_mode: str = "loso",
) -> dict[str, Any]:
    mapping = pd.read_csv(
        mapping_path
    )

    if SPLIT_COL != "loso_split":
        # mode random: CSV dung cot assigned_split; ten noi bo giu loso_split (khong ghi ra artifact)
        mapping = mapping.rename(
            columns={
                SPLIT_COL: "loso_split"
            }
        )

    required = {
        "hostname",
        "loso_split",
        "heldout_scenario",
        "gt_positive_host_group",
        "gt_primary_scenario",
        "event_rows",
        "positive_event_rows",
    }

    missing = (
        required
        - set(
            mapping.columns
        )
    )

    if missing:
        raise RuntimeError(
            f"{mapping_path}: "
            f"missing columns "
            f"{sorted(missing)}"
        )

    if (
        mapping[
            "hostname"
        ].duplicated().any()
    ):
        raise RuntimeError(
            f"{mapping_path}: "
            "duplicate hostname."
        )

    if (
        set(
            mapping[
                "loso_split"
            ].unique()
        )
        - set(
            SUPERVISED_SPLITS
        )
    ):
        raise RuntimeError(
            f"{mapping_path}: "
            "invalid loso_split."
        )

    scenarios = (
        mapping[
            "heldout_scenario"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    # mode random: không có scenario giữ riêng; heldout_scenario của mapping phải là "NONE"
    # và tên fold (vd. seed_1) được dùng làm nhãn fold ở các artifact phía sau.
    expected_scenarios = (
        ["NONE"]
        if mapping_mode == "random"
        else [heldout_scenario]
    )

    if scenarios != expected_scenarios:
        raise RuntimeError(
            f"{mapping_path}: "
            "heldout_scenario mismatch."
        )

    profile_hosts = set(
        host_num[
            "hostname"
        ].astype(str)
    )

    mapping_hosts = set(
        mapping[
            "hostname"
        ].astype(str)
    )

    if (
        profile_hosts
        != mapping_hosts
    ):
        raise RuntimeError(
            "Frozen mapping/profile "
            "hostname mismatch.\n"
            f"missing_in_mapping="
            f"{sorted(profile_hosts - mapping_hosts)[:20]}\n"
            f"missing_in_profile="
            f"{sorted(mapping_hosts - profile_hosts)[:20]}"
        )

    counts = (
        fold_category_counts(
            host_cat=host_cat,
            mapping=mapping,
        )
    )

    numeric_profile = (
        combine_numeric_profile(
            host_num=host_num,
            mapping=mapping,
        )
    )

    (
        category_maps,
        category_diagnostics,
    ) = build_category_maps(
        counts,
        app_min_freq=
            app_min_freq,
        service_min_freq=
            service_min_freq,
        default_min_freq=
            default_min_freq,
        app_max_values=
            app_max_values,
        service_max_values=
            service_max_values,
        default_max_values=
            default_max_values,
    )

    (
        numeric_stats,
        active_num,
        inactive_num,
    ) = build_numeric_stats(
        numeric_profile,
        min_numeric_std=
            min_numeric_std,
        zscore_clip_abs=
            zscore_clip_abs,
    )

    split_stats = {}

    for split in (
        SUPERVISED_SPLITS
    ):
        subset = mapping[
            mapping[
                "loso_split"
            ] == split
        ]

        split_stats[
            split
        ] = {
            "hosts":
                int(
                    len(
                        subset
                    )
                ),
            "event_rows":
                int(
                    subset[
                        "event_rows"
                    ].sum()
                ),
            "positive_event_rows":
                int(
                    subset[
                        "positive_event_rows"
                    ].sum()
                ),
        }

    total_events = sum(
        x[
            "event_rows"
        ]
        for x
        in split_stats.values()
    )

    expected_events = int(
        contract[
            "joined_supervised_events"
        ]
    )

    spec = build_spec(
        heldout_scenario=
            heldout_scenario,
        category_maps=
            category_maps,
        numeric_stats=
            numeric_stats,
        category_diagnostics=
            category_diagnostics,
        active_num=
            active_num,
        inactive_num=
            inactive_num,
        min_numeric_std=
            min_numeric_std,
        zscore_clip_abs=
            zscore_clip_abs,
        supervised_rows=
            total_events,
    )

    active_cat = list(
        spec[
            "active_categorical_features"
        ]
    )

    warnings: list[
        str
    ] = []

    for (
        field,
        diag,
    ) in (
        category_diagnostics.items()
    ):
        val_unk = float(
            diag[
                "by_split"
            ]["val"][
                "UNK_rate"
            ]
        )

        test_unk = float(
            diag[
                "by_split"
            ]["test"][
                "UNK_rate"
            ]
        )

        if (
            val_unk > 0.05
            or test_unk > 0.05
        ):
            warnings.append(
                f"{field}: "
                "OOV/UNK >5% "
                f"(val={val_unk:.3%}, "
                f"test={test_unk:.3%})."
            )

    gates = {
        "mapping_sha_matches_contract":
            (
                sha256_file(
                    mapping_path
                )
                == mapping_sha256
            ),
        "hostname_profile_exact_match":
            (
                profile_hosts
                == mapping_hosts
            ),
        "event_conservation":
            (
                total_events
                == expected_events
            ),
        "train_rows_exist":
            (
                split_stats[
                    "train"
                ][
                    "event_rows"
                ] > 0
            ),
        "val_rows_exist":
            (
                split_stats[
                    "val"
                ][
                    "event_rows"
                ] > 0
            ),
        "test_rows_exist":
            (
                split_stats[
                    "test"
                ][
                    "event_rows"
                ] > 0
            ),
        "train_positive_exists":
            (
                split_stats[
                    "train"
                ][
                    "positive_event_rows"
                ] > 0
            ),
        "val_positive_exists":
            (
                split_stats[
                    "val"
                ][
                    "positive_event_rows"
                ] > 0
            ),
        "test_positive_exists":
            (
                split_stats[
                    "test"
                ][
                    "positive_event_rows"
                ] > 0
            ),
        "all_category_maps_nonempty":
            all(
                int(
                    info[
                        "size"
                    ]
                ) >= 2
                for info
                in category_maps[
                    "fields"
                ].values()
            ),
        "all_numeric_stats_present":
            all(
                field
                in numeric_stats[
                    "features"
                ]
                for field
                in NUMERIC_FIELDS
            ),
        "val_not_used_for_fit":
            True,
        "test_not_used_for_fit":
            True,
        "heldout_scenario_not_used_for_fit":
            True,
        "label_not_used_for_feature_selection":
            True,
    }

    ready = all(
        gates.values()
    )

    candidate_core = {
        "heldout_scenario":
            heldout_scenario,
        "mapping_sha256":
            mapping_sha256,
        "contract_file_sha256":
            contract_file_sha256,
        "report04b_sha256":
            report04b_sha256,
        "profile_state":
            profile_state,
        "policy": {
            "app_min_freq":
                app_min_freq,
            "service_min_freq":
                service_min_freq,
            "default_min_freq":
                default_min_freq,
            "app_max_values":
                app_max_values,
            "service_max_values":
                service_max_values,
            "default_max_values":
                default_max_values,
            "min_numeric_std":
                min_numeric_std,
            "zscore_clip_abs":
                zscore_clip_abs,
        },
        "category_maps":
            category_maps,
        "numeric_stats":
            numeric_stats,
        "spec":
            spec,
    }

    candidate_fp = (
        sha256_bytes(
            canonical_bytes(
                candidate_core
            )
        )
    )

    report = {
        "generated_at":
            now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "status":
            (
                "CANDIDATE_READY_FOR_REVIEW"
                if ready
                else "NOT_READY"
            ),
        "heldout_scenario":
            heldout_scenario,
        "fit_policy": {
            "fit_split":
                "train",
            "fit_scope":
                "LOSO fold TRAIN only",
            "val_used_for_fit":
                False,
            "test_used_for_fit":
                False,
            "heldout_scenario_used_for_fit":
                False,
            "label_used_for_feature_selection":
                False,
        },
        "split_stats":
            split_stats,
        "active_categorical_features":
            active_cat,
        "inactive_categorical_features":
            spec[
                "inactive_categorical_features"
            ],
        "active_numerical_features":
            active_num,
        "inactive_numerical_features":
            inactive_num,
        "derived_binary_features":
            spec[
                "derived_binary_features"
            ],
        "category_diagnostics":
            category_diagnostics,
        "numeric_profile_by_split":
            numeric_profile,
        "gates":
            gates,
        "warnings":
            warnings,
        "candidate_fingerprint_sha256":
            candidate_fp,
    }

    return {
        "category_maps":
            category_maps,
        "numeric_stats":
            numeric_stats,
        "spec":
            spec,
        "report":
            report,
        "candidate_fingerprint":
            candidate_fp,
    }


def write_fold_md(
    path: Path,
    *,
    report: dict[str, Any],
    frozen: bool,
    frozen_fp: str | None,
) -> None:
    lines = [
        (
            "# STEP 05F-C — "
            f"{EXPERIMENT_LABEL} preprocessing "
            f"({report['heldout_scenario']})"
        ),
        "",
        "## Trạng thái",
        "",
        (
            "**FROZEN — READY FOR STEP 05F-D**"
            if frozen
            else (
                "**"
                + report[
                    "status"
                ]
                + "**"
            )
        ),
        "",
        "## Leakage policy",
        "",
        "- Category maps chỉ fit trên fold TRAIN.",
        "- Numeric mean/std chỉ fit trên fold TRAIN.",
        "- Held-out scenario không tham gia fit.",
        "- VAL/TEST chỉ được dùng để audit OOV/missing sau khi TRAIN mapping đã được tạo.",
        "- Label không được dùng để chọn feature.",
        "",
        "## Split statistics",
        "",
    ]

    for split in (
        SUPERVISED_SPLITS
    ):
        s = report[
            "split_stats"
        ][split]

        lines.append(
            f"- `{split}`: "
            f"hosts={s['hosts']:,}, "
            f"events={s['event_rows']:,}, "
            f"positive_events="
            f"{s['positive_event_rows']:,}"
        )

    lines.extend([
        "",
        "## Active categorical",
        "",
    ])

    for field in report[
        "active_categorical_features"
    ]:
        lines.append(
            f"- `{field}`"
        )

    lines.extend([
        "",
        "## Active numerical",
        "",
    ])

    for field in report[
        "active_numerical_features"
    ]:
        lines.append(
            f"- `{field}`"
        )

    lines.extend([
        "",
        "## Derived binary",
        "",
        "- `has_missed_bytes`",
        "",
        "## OOV audit",
        "",
    ])

    for field, diag in report[
        "category_diagnostics"
    ].items():
        lines.append(
            f"- `{field}`: "
            f"VAL UNK="
            f"{diag['by_split']['val']['UNK_rate']:.5%}, "
            f"TEST UNK="
            f"{diag['by_split']['test']['UNK_rate']:.5%}"
        )

    lines.extend([
        "",
        "## Gates",
        "",
    ])

    for key, value in report[
        "gates"
    ].items():
        lines.append(
            f"- `{key}`: "
            f"{'PASS' if value else 'FAIL'}"
        )

    lines.extend([
        "",
        "## Warnings",
        "",
    ])

    if report[
        "warnings"
    ]:
        for warning in report[
            "warnings"
        ]:
            lines.append(
                f"- {warning}"
            )
    else:
        lines.append(
            "- Không có warning tự động."
        )

    if frozen_fp:
        lines.extend([
            "",
            "## Frozen fingerprint",
            "",
            f"`{frozen_fp}`",
        ])

    lines.extend([
        "",
        "## Next step",
        "",
        (
            "STEP 10C — build random-split 15-minute/512 shards."
            if RANDOM_NAMING
            else "STEP 05F-D — build LOSO 15-minute/512 shards."
            if frozen
            else (
                "Review cả 3 fold. "
                "Nếu tất cả PASS, "
                "rerun SAME command "
                "với `--freeze`."
            )
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
        "--report04b",
        default=None,
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
        "--app-min-freq",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--service-min-freq",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--default-min-freq",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--app-max-values",
        type=int,
        default=5000,
    )

    parser.add_argument(
        "--service-max-values",
        type=int,
        default=1000,
    )

    parser.add_argument(
        "--default-max-values",
        type=int,
        default=256,
    )

    parser.add_argument(
        "--min-numeric-std",
        type=float,
        default=0.01,
    )

    parser.add_argument(
        "--zscore-clip-abs",
        type=float,
        default=10.0,
    )

    parser.add_argument(
        "--rebuild-profile",
        action="store_true",
    )

    parser.add_argument(
        "--freeze",
        action="store_true",
    )

    # ---- STEP 10B: tham số hóa để dùng lại cho split ngẫu nhiên (mặc định = LOSO cũ)
    parser.add_argument(
        "--mode",
        choices=["loso", "random"],
        default="loso",
        help=(
            "loso: hanh vi cu (STEP 05F-C). "
            "random: split ngau nhien theo scenario (STEP 10A), "
            "khong co held-out scenario."
        ),
    )

    parser.add_argument(
        "--contract-name",
        default=None,
        help=(
            "Ten file contract trong --frozen-dir. "
            "Mac dinh: loso_fold_contract.json (loso) / "
            "random_split_contract.json (random)."
        ),
    )

    parser.add_argument(
        "--folds",
        nargs="+",
        default=None,
        help=(
            "Fold can chay (mac dinh: tat ca fold trong contract)."
        ),
    )

    parser.add_argument(
        "--artifact-dir",
        default=None,
        help=(
            "Thu muc output. Mac dinh: 02_artifacts/"
            "08b_loso_preprocess_v1 (loso) / "
            "10b_random_preprocess_v1 (random)."
        ),
    )

    parser.add_argument(
        "--fold-dir-template",
        default=None,
        help=(
            "Ten thu muc fold duoi artifact-dir. "
            "Mac dinh: holdout_{fold} (loso) / {fold} (random)."
        ),
    )

    parser.add_argument(
        "--profile-source-dir",
        default=None,
        help=(
            "Thu muc _shared_host_profiles co san de copy "
            "(chi doc), thay vi quet lai joined Parquet."
        ),
    )

    args = parser.parse_args()

    global EXPERIMENT_LABEL, RANDOM_NAMING, SPLIT_COL, SCRIPT_VERSION

    is_random = args.mode == "random"

    if is_random:
        EXPERIMENT_LABEL = (
            "Random scenario-stratified host split"
        )
        RANDOM_NAMING = True
        SPLIT_COL = "assigned_split"
        SCRIPT_VERSION = (
            "step10b-random-split-train-only-preprocess-v1.0"
        )

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

    report04b_path = (
        Path(
            args.report04b
        )
        if args.report04b
        else (
            output_root
            / "02_artifacts"
            / "02_network_joined_v1"
            / "network_join_exact_report.json"
        )
    )

    artifact_dir = (
        Path(
            args.artifact_dir
        )
        if args.artifact_dir
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

    artifact_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not joined_root.exists():
        raise FileNotFoundError(
            joined_root
        )

    if not report04b_path.exists():
        raise FileNotFoundError(
            report04b_path
        )

    (
        contract,
        mapping_paths,
    ) = verify_frozen_contract(
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
            else LOSO_FOLDS
        ),
    )

    if args.folds:
        unknown = (
            set(args.folds)
            - set(mapping_paths)
        )

        if unknown:
            raise RuntimeError(
                f"Unknown folds {sorted(unknown)}; "
                f"contract has {sorted(mapping_paths)}."
            )

        mapping_paths = {
            fold: mapping_paths[fold]
            for fold in args.folds
        }

    contract_path = (
        frozen_dir
        / contract_name
    )

    contract_file_sha = (
        sha256_file(
            contract_path
        )
    )

    report04b = load_json(
        report04b_path
    )

    report04b_sha = (
        sha256_file(
            report04b_path
        )
    )

    original_rows = (
        validate_04b_report(
            report04b,
            int(
                contract[
                    "joined_supervised_events"
                ]
            ),
        )
    )

    print("=" * 104)
    print(
        "STEP 10B — random-split TRAIN-only Network preprocessing"
        if is_random
        else "STEP 05F-C — LOSO TRAIN-only Network preprocessing"
    )
    print("=" * 104)
    print(
        f"[JOINED] {joined_root}"
    )
    print(
        f"[FROZEN] {frozen_dir}"
    )
    print(
        f"[SUPERVISED EVENTS] "
        f"{int(contract['joined_supervised_events']):,}"
    )
    print(
        f"[POSITIVE EVENTS] "
        f"{int(contract['joined_positive_events']):,}"
    )
    print(
        "[FIT] fold TRAIN only"
    )
    print(
        "[NO LEAKAGE] held-out scenario / VAL / TEST excluded from fit"
    )
    print(
        f"[THREADS] {args.threads}"
    )
    print(
        f"[DUCKDB] "
        f"memory_limit="
        f"{args.duckdb_memory_limit}"
    )
    print()

    (
        cat_profile_path,
        num_profile_path,
        profile_state,
    ) = build_or_reuse_host_profiles(
        joined_root=
            joined_root,
        artifact_dir=
            artifact_dir,
        report04b_sha256=
            report04b_sha,
        contract_file_sha256=
            contract_file_sha,
        contract=
            contract,
        threads=
            args.threads,
        memory_limit=
            args.duckdb_memory_limit,
        rebuild=
            args.rebuild_profile,
        profile_source_dir=(
            Path(
                args.profile_source_dir
            )
            if args.profile_source_dir
            else None
        ),
    )

    host_cat = read_parquet_df(
        cat_profile_path
    )

    host_num = read_parquet_df(
        num_profile_path
    )

    print()
    print(
        f"[HOST PROFILE] "
        f"categorical hosts="
        f"{host_cat['hostname'].nunique():,} | "
        f"numeric hosts="
        f"{host_num['hostname'].nunique():,}"
    )

    fold_results = {}
    all_ready = True

    for (
        scenario,
        mapping_path,
    ) in (
        mapping_paths.items()
    ):
        print()
        print(
            f"[FOLD] holdout="
            f"{scenario}"
        )

        fold = build_fold(
            heldout_scenario=
                scenario,
            mapping_path=
                mapping_path,
            mapping_sha256=
                contract[
                    "folds"
                ][scenario][
                    "sha256"
                ],
            host_cat=
                host_cat,
            host_num=
                host_num,
            artifact_dir=
                artifact_dir,
            contract=
                contract,
            contract_file_sha256=
                contract_file_sha,
            report04b_sha256=
                report04b_sha,
            profile_state=
                profile_state,
            app_min_freq=
                args.app_min_freq,
            service_min_freq=
                args.service_min_freq,
            default_min_freq=
                args.default_min_freq,
            app_max_values=
                args.app_max_values,
            service_max_values=
                args.service_max_values,
            default_max_values=
                args.default_max_values,
            min_numeric_std=
                args.min_numeric_std,
            zscore_clip_abs=
                args.zscore_clip_abs,
            mapping_mode=
                args.mode,
        )

        report = fold[
            "report"
        ]

        fold_dir = (
            artifact_dir
            / fold_dir_template.format(
                fold=scenario
            )
        )

        fold_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        candidate_maps = (
            fold_dir
            / "network_category_maps_candidate.json"
        )

        candidate_numeric = (
            fold_dir
            / "network_numeric_stats_candidate.json"
        )

        candidate_spec = (
            fold_dir
            / "network_preprocess_spec_candidate.json"
        )

        report_path = (
            fold_dir
            / "network_preprocess_report.json"
        )

        state_path = (
            fold_dir
            / "candidate_state.json"
        )

        md_path = (
            fold_dir
            / (
                "STEP_10B_PREPROCESS.md"
                if is_random
                else "STEP_08B_LOSO_PREPROCESS.md"
            )
        )

        dump_json(
            candidate_maps,
            fold[
                "category_maps"
            ],
        )

        dump_json(
            candidate_numeric,
            fold[
                "numeric_stats"
            ],
        )

        dump_json(
            candidate_spec,
            fold[
                "spec"
            ],
        )

        dump_json(
            report_path,
            report,
        )

        state = {
            "script_version":
                SCRIPT_VERSION,
            "heldout_scenario":
                scenario,
            "mapping_sha256":
                contract[
                    "folds"
                ][scenario][
                    "sha256"
                ],
            "contract_file_sha256":
                contract_file_sha,
            "report04b_sha256":
                report04b_sha,
            "profile_state":
                profile_state,
            "candidate_fingerprint_sha256":
                fold[
                    "candidate_fingerprint"
                ],
        }

        dump_json(
            state_path,
            state,
        )

        frozen_fp = None

        if args.freeze:
            if (
                report[
                    "status"
                ]
                != "CANDIDATE_READY_FOR_REVIEW"
            ):
                raise RuntimeError(
                    f"{scenario}: "
                    "candidate not ready."
                )

            if not all(
                report[
                    "gates"
                ].values()
            ):
                raise RuntimeError(
                    f"{scenario}: "
                    "gates not all PASS."
                )

            final_maps = (
                fold_dir
                / "network_category_maps.json"
            )

            final_numeric = (
                fold_dir
                / "network_numeric_stats.json"
            )

            final_spec = (
                fold_dir
                / "network_preprocess_spec.json"
            )

            fp_path = (
                fold_dir
                / "network_preprocess_fingerprint.json"
            )

            shutil.copy2(
                candidate_maps,
                final_maps,
            )

            shutil.copy2(
                candidate_numeric,
                final_numeric,
            )

            shutil.copy2(
                candidate_spec,
                final_spec,
            )

            fp_payload = {
                "generated_at":
                    now_iso(),
                "script_version":
                    SCRIPT_VERSION,
                "experiment":
                    EXPERIMENT_LABEL,
                "heldout_scenario":
                    scenario,
                "fit_split":
                    "train",
                "fit_scope":
                    "LOSO fold TRAIN only",
                "val_used_for_fit":
                    False,
                "test_used_for_fit":
                    False,
                "heldout_scenario_used_for_fit":
                    False,
                "label_used_for_feature_selection":
                    False,
                "loso_contract_sha256":
                    contract_file_sha,
                "loso_mapping_sha256":
                    contract[
                        "folds"
                    ][scenario][
                        "sha256"
                    ],
                "report04b_sha256":
                    report04b_sha,
                "candidate_fingerprint_sha256":
                    fold[
                        "candidate_fingerprint"
                    ],
                "category_maps_sha256":
                    sha256_file(
                        final_maps
                    ),
                "numeric_stats_sha256":
                    sha256_file(
                        final_numeric
                    ),
                "preprocess_spec_sha256":
                    sha256_file(
                        final_spec
                    ),
            }

            if args.mode == "random":
                # chỉ thêm ở mode random để mode LOSO mặc định giữ nguyên nội dung fingerprint
                fp_payload[
                    "experiment_mode"
                ] = "random"
                fp_payload[
                    "event_schema"
                ] = {
                    "version":
                        SCHEMA["schema_version"],
                    "sha256":
                        SCHEMA["_sha256"],
                }

            frozen_fp = (
                sha256_bytes(
                    canonical_bytes(
                        fp_payload
                    )
                )
            )

            fp_payload[
                "frozen_fingerprint_sha256"
            ] = frozen_fp

            dump_json(
                fp_path,
                fp_payload,
            )

        write_fold_md(
            md_path,
            report=report,
            frozen=args.freeze,
            frozen_fp=frozen_fp,
        )

        fold_results[
            scenario
        ] = {
            "status":
                (
                    "FROZEN"
                    if args.freeze
                    else report[
                        "status"
                    ]
                ),
            "split_stats":
                report[
                    "split_stats"
                ],
            "active_categorical_features":
                report[
                    "active_categorical_features"
                ],
            "active_numerical_features":
                report[
                    "active_numerical_features"
                ],
            "warnings":
                report[
                    "warnings"
                ],
            "candidate_fingerprint_sha256":
                fold[
                    "candidate_fingerprint"
                ],
            "frozen_fingerprint_sha256":
                frozen_fp,
        }

        if (
            report[
                "status"
            ]
            != "CANDIDATE_READY_FOR_REVIEW"
        ):
            all_ready = False

        print(
            f"    [STATUS] "
            f"{fold_results[scenario]['status']}"
        )

        for split in (
            SUPERVISED_SPLITS
        ):
            s = report[
                "split_stats"
            ][split]

            print(
                f"    [{split.upper()}] "
                f"hosts={s['hosts']:,} | "
                f"events={s['event_rows']:,} | "
                f"positive_events="
                f"{s['positive_event_rows']:,}"
            )

        print(
            "    [ACTIVE CAT] "
            + ", ".join(
                report[
                    "active_categorical_features"
                ]
            )
        )

        print(
            "    [ACTIVE NUM] "
            + ", ".join(
                report[
                    "active_numerical_features"
                ]
            )
        )

        test_oov = {
            field:
                diag[
                    "by_split"
                ]["test"][
                    "UNK_rate"
                ]
            for field, diag
            in report[
                "category_diagnostics"
            ].items()
        }

        top_oov = sorted(
            test_oov.items(),
            key=lambda x:
                -x[1],
        )[:5]

        print(
            "    [TOP TEST UNK] "
            + " | ".join(
                (
                    f"{field}="
                    f"{rate:.3%}"
                )
                for field, rate
                in top_oov
            )
        )

    master = {
        "generated_at":
            now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "mode":
            (
                "freeze"
                if args.freeze
                else "candidate_review"
            ),
        "joined_root":
            str(
                joined_root
            ),
        "report04b":
            str(
                report04b_path
            ),
        "frozen_loso_dir":
            str(
                frozen_dir
            ),
        "loso_contract_file_sha256":
            contract_file_sha,
        "joined_original_supervised_rows":
            original_rows,
        "profile_state":
            profile_state,
        "all_folds_ready":
            all_ready,
        "folds":
            fold_results,
        "next_step":
            (
                "STEP 05F-D — build "
                "fold-specific 15m/512 shards"
                if args.freeze
                else (
                    "Review all folds, "
                    "then rerun SAME command "
                    "with --freeze."
                )
            ),
    }

    master_path = (
        artifact_dir
        / (
            "STEP_10B_PREPROCESS_SUMMARY.json"
            if is_random
            else "STEP_05F_C_LOSO_PREPROCESS_SUMMARY.json"
        )
    )

    dump_json(
        master_path,
        master,
    )

    print()
    print("=" * 104)

    if args.freeze:
        print(
            "[SUCCESS] STEP 10B "
            "all random-split preprocessors FROZEN"
            if is_random
            else "[SUCCESS] STEP 05F-C "
            "all LOSO preprocessors FROZEN"
        )
        print(
            "[NEXT] STEP 05F-D — "
            "build fold-specific "
            "15m/512 shards."
        )
    else:
        print(
            "[STATUS] "
            + (
                "ALL FOLDS READY TO FREEZE"
                if all_ready
                else "REVIEW REQUIRED"
            )
        )
        print(
            "[NEXT] Review reports, "
            "then rerun SAME command "
            "with --freeze."
        )

    print(
        f"[SUMMARY] {master_path}"
    )
    print("=" * 104)


if __name__ == "__main__":
    main()
