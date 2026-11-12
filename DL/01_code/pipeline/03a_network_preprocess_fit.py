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


SCRIPT_VERSION = "step04c-network-preprocess-train-only-v1.0"

BASE_CATEGORICAL_FIELDS = [
    "app_family",
    "direction",
    "proto",
    "service",
    "conn_state",
    "local_orig",
    "local_resp",
]

DERIVED_CATEGORICAL_FIELDS = [
    "orig_ip_scope",
    "resp_ip_scope",
    "orig_port_class",
    "resp_port_class",
]

ALL_CATEGORICAL_FIELDS = BASE_CATEGORICAL_FIELDS + DERIVED_CATEGORICAL_FIELDS

NUMERIC_FIELDS = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "missed_bytes",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
]

RESERVED_IDS = {
    "<UNK>": 0,
    "<MISSING>": 1,
}


def now_iso() -> str:
    return datetime.now().isoformat()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_duckdb():
    try:
        import duckdb
    except ImportError as exc:
        raise RuntimeError(
            "STEP 04C cần DuckDB.\n"
            "Chạy: python -m pip install duckdb"
        ) from exc
    return duckdb


def sql_path(path: Path) -> str:
    return str(path).replace("\\", "/").replace("'", "''")


def load_04b_report(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))

    if report.get("script_version") != "step04b-network-exact-join-v1.0":
        raise RuntimeError(
            "STEP 04B report version không đúng với contract hiện tại: "
            f"{report.get('script_version')!r}"
        )

    joined = report.get("joined", {})
    if int(joined.get("joined_unique_uid_rows", 0)) <= 0:
        raise RuntimeError("STEP 04B report không có joined rows.")

    if int(joined.get("missing_label_rows", -1)) != 0:
        raise RuntimeError(
            "STEP 04B vẫn có missing label. Không được fit preprocessing."
        )

    if int(report.get("ecar_exact", {}).get("hostname_conflict_uid", -1)) != 0:
        raise RuntimeError(
            "STEP 04B có hostname-conflict UID. Không được tiếp tục tự động."
        )

    return report


def joined_glob(joined_root: Path) -> str:
    return sql_path(joined_root / "**" / "*.parquet")


def duckdb_connect(*, threads: int, memory_limit: str, temp_dir: Path):
    duckdb = require_duckdb()

    temp_dir.mkdir(parents=True, exist_ok=True)

    db = duckdb.connect(database=":memory:")
    db.execute(f"PRAGMA threads={int(threads)}")
    db.execute(f"PRAGMA memory_limit='{memory_limit}'")
    db.execute(f"SET temp_directory='{sql_path(temp_dir)}'")
    db.execute("SET preserve_insertion_order=false")
    return db


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


def ip_scope_sql(column: str) -> str:
    c = f"lower(trim(CAST({column} AS VARCHAR)))"
    return f"""
        CASE
            WHEN {column} IS NULL OR trim(CAST({column} AS VARCHAR)) = ''
                OR {c} IN ('-', '(empty)', 'null', 'none')
                THEN '<MISSING>'

            WHEN {c} = '::1'
                OR regexp_matches({c}, '^127\\.')
                THEN 'LOOPBACK'

            WHEN regexp_matches({c}, '^10\\.')
                OR regexp_matches({c}, '^192\\.168\\.')
                OR regexp_matches({c}, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.')
                THEN 'PRIVATE'

            WHEN regexp_matches({c}, '^169\\.254\\.')
                OR regexp_matches({c}, '^fe80:')
                THEN 'LINK_LOCAL'

            WHEN regexp_matches({c}, '^(fc|fd)')
                THEN 'PRIVATE_IPV6'

            WHEN regexp_matches({c}, '^(22[4-9]|23[0-9])\\.')
                OR regexp_matches({c}, '^ff')
                THEN 'MULTICAST'

            WHEN {c} = '255.255.255.255'
                THEN 'BROADCAST'

            WHEN regexp_matches(
                {c},
                '^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}$'
            )
                THEN 'PUBLIC_IPV4'

            WHEN strpos({c}, ':') > 0
                THEN 'PUBLIC_IPV6'

            ELSE 'OTHER'
        END
    """.strip()


COMMON_PORTS = {
    20: "FTP_DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NETBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1433: "MSSQL",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRES",
    5985: "WINRM_HTTP",
    5986: "WINRM_HTTPS",
    8080: "HTTP_ALT",
    8443: "HTTPS_ALT",
}


def port_class_sql(column: str) -> str:
    common = "\n".join(
        f"WHEN {column} = {port} THEN 'PORT_{port}_{name}'"
        for port, name in sorted(COMMON_PORTS.items())
    )

    return f"""
        CASE
            WHEN {column} IS NULL THEN '<MISSING>'
            {common}
            WHEN {column} BETWEEN 0 AND 1023 THEN 'WELL_KNOWN_OTHER'
            WHEN {column} BETWEEN 1024 AND 49151 THEN 'REGISTERED'
            WHEN {column} BETWEEN 49152 AND 65535 THEN 'EPHEMERAL'
            ELSE 'OTHER'
        END
    """.strip()


def base_cte(source_glob: str) -> str:
    return f"""
        WITH base AS (
            SELECT
                split,

                {normalize_cat_sql('app_family')} AS app_family,
                {normalize_cat_sql('direction')} AS direction,
                {normalize_cat_sql('proto')} AS proto,
                {normalize_cat_sql('service')} AS service,
                {normalize_cat_sql('conn_state')} AS conn_state,
                {normalize_cat_sql('local_orig')} AS local_orig,
                {normalize_cat_sql('local_resp')} AS local_resp,

                {ip_scope_sql('orig_h')} AS orig_ip_scope,
                {ip_scope_sql('resp_h')} AS resp_ip_scope,

                {port_class_sql('orig_p')} AS orig_port_class,
                {port_class_sql('resp_p')} AS resp_port_class,

                duration,
                orig_bytes,
                resp_bytes,
                missed_bytes,
                orig_pkts,
                orig_ip_bytes,
                resp_pkts,
                resp_ip_bytes,

                label

            FROM read_parquet(
                '{source_glob}',
                hive_partitioning=true
            )
            WHERE split IN ('train', 'val', 'test', 'unmatched_split')
        )
    """


def query_category_counts(db, source_glob: str) -> list[tuple[str, str, str, int]]:
    group_sets = ",\n".join(
        f"(split, {field})"
        for field in ALL_CATEGORICAL_FIELDS
    )

    field_case = "\n".join(
        f"WHEN GROUPING({field}) = 0 THEN '{field}'"
        for field in ALL_CATEGORICAL_FIELDS
    )

    value_coalesce = ", ".join(ALL_CATEGORICAL_FIELDS)

    sql = f"""
        {base_cte(source_glob)}

        SELECT
            split,
            CASE
                {field_case}
                ELSE 'unknown'
            END AS field,
            COALESCE({value_coalesce}, '<MISSING>') AS value,
            count(*)::BIGINT AS n

        FROM base

        GROUP BY GROUPING SETS (
            {group_sets}
        )

        ORDER BY split, field, n DESC, value
    """

    return [
        (str(split), str(field), str(value), int(n))
        for split, field, value, n in db.execute(sql).fetchall()
    ]


def _numeric_expr(field: str) -> str:
    return f"""
        CASE
            WHEN {field} IS NULL OR {field} < 0 THEN NULL
            ELSE ln(1.0 + CAST({field} AS DOUBLE))
        END
    """.strip()


def query_numeric_profile(db, source_glob: str) -> dict[str, dict[str, Any]]:
    select_parts = ["split", "count(*)::BIGINT AS row_count"]

    for field in NUMERIC_FIELDS:
        expr = _numeric_expr(field)

        select_parts.extend([
            f"count({expr})::BIGINT AS {field}__observed",
            (
                f"sum(CASE WHEN {field} IS NULL OR {field} < 0 "
                f"THEN 1 ELSE 0 END)::BIGINT AS {field}__missing"
            ),
            f"avg({expr}) AS {field}__mean",
            f"stddev_pop({expr}) AS {field}__std",
            f"min({field}) AS {field}__raw_min",
            f"max({field}) AS {field}__raw_max",
        ])

    sql = f"""
        {base_cte(source_glob)}

        SELECT
            {", ".join(select_parts)}
        FROM base
        GROUP BY split
        ORDER BY split
    """

    cursor = db.execute(sql)
    rows = cursor.fetchall()
    columns = [d[0] for d in cursor.description]

    result: dict[str, dict[str, Any]] = {}

    for raw_row in rows:
        row = dict(zip(columns, raw_row))
        split = str(row.pop("split"))
        result[split] = {}

        row_count = int(row["row_count"])
        result[split]["row_count"] = row_count
        result[split]["features"] = {}

        for field in NUMERIC_FIELDS:
            observed = int(row[f"{field}__observed"])
            missing = int(row[f"{field}__missing"])
            mean = row[f"{field}__mean"]
            std = row[f"{field}__std"]

            mean = float(mean) if mean is not None and math.isfinite(float(mean)) else 0.0
            std = float(std) if std is not None and math.isfinite(float(std)) else 0.0

            result[split]["features"][field] = {
                "observed": observed,
                "missing": missing,
                "missing_rate": (missing / row_count if row_count else 0.0),
                "log1p_mean": mean,
                "log1p_std": std,
                "raw_min": row[f"{field}__raw_min"],
                "raw_max": row[f"{field}__raw_max"],
            }

    return result


def group_category_counts(
    rows: list[tuple[str, str, str, int]]
) -> dict[str, dict[str, dict[str, int]]]:
    result: dict[str, dict[str, dict[str, int]]] = {}

    for split, field, value, count in rows:
        result.setdefault(split, {}).setdefault(field, {})[value] = int(count)

    return result


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
        return app_min_freq, app_max_values
    if field == "service":
        return service_min_freq, service_max_values
    if field in DERIVED_CATEGORICAL_FIELDS:
        return 1, 256
    return default_min_freq, default_max_values


def build_category_maps(
    counts: dict[str, dict[str, dict[str, int]]],
    *,
    app_min_freq: int,
    service_min_freq: int,
    default_min_freq: int,
    app_max_values: int,
    service_max_values: int,
    default_max_values: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    train = counts.get("train", {})
    maps: dict[str, Any] = {
        "version": "network-category-maps-v1.0",
        "reserved_ids": RESERVED_IDS,
        "fit_split": "train",
        "fields": {},
    }

    diagnostics: dict[str, Any] = {}

    for field in ALL_CATEGORICAL_FIELDS:
        train_counts = dict(train.get(field, {}))
        total_train = sum(train_counts.values())

        min_freq, max_values = field_policy(
            field=field,
            app_min_freq=app_min_freq,
            service_min_freq=service_min_freq,
            default_min_freq=default_min_freq,
            app_max_values=app_max_values,
            service_max_values=service_max_values,
            default_max_values=default_max_values,
        )

        candidates = [
            (value, count)
            for value, count in train_counts.items()
            if value != "<MISSING>" and int(count) >= min_freq
        ]
        candidates.sort(key=lambda item: (-item[1], item[0]))
        candidates = candidates[:max_values]

        mapping = dict(RESERVED_IDS)
        next_id = 2

        for value, _count in candidates:
            if value in mapping:
                continue
            mapping[value] = next_id
            next_id += 1

        maps["fields"][field] = {
            "mapping": mapping,
            "size": len(mapping),
            "min_train_frequency": min_freq,
            "max_values_excluding_reserved": max_values,
        }

        diag = {
            "train_unique_values_including_missing": len(train_counts),
            "mapping_size_including_reserved": len(mapping),
            "min_train_frequency": min_freq,
            "max_values_excluding_reserved": max_values,
            "by_split": {},
        }

        known = set(mapping.keys())

        for split in ("train", "val", "test", "unmatched_split"):
            split_counts = counts.get(split, {}).get(field, {})
            n = sum(split_counts.values())
            missing = int(split_counts.get("<MISSING>", 0))
            unk = sum(
                int(count)
                for value, count in split_counts.items()
                if value not in known and value != "<MISSING>"
            )

            diag["by_split"][split] = {
                "rows": int(n),
                "missing": missing,
                "missing_rate": (missing / n if n else 0.0),
                "mapped_to_UNK": int(unk),
                "UNK_rate": (unk / n if n else 0.0),
            }

        diagnostics[field] = diag

    return maps, diagnostics


def build_numeric_stats(numeric_profile: dict[str, dict[str, Any]]) -> dict[str, Any]:
    train = numeric_profile.get("train")

    if not train:
        raise RuntimeError("Không có TRAIN numerical profile.")

    result: dict[str, Any] = {
        "version": "network-numeric-stats-v1.0",
        "fit_split": "train",
        "transform": "log1p_nonnegative_then_zscore",
        "missing_policy": {
            "normalized_value": 0.0,
            "parallel_missing_mask": True,
            "note": (
                "0.0 sau z-score tương ứng TRAIN mean. Missing được phân biệt "
                "bằng x_num_missing mask ở STEP 04D."
            ),
        },
        "features": {},
    }

    for field in NUMERIC_FIELDS:
        info = train["features"][field]
        std = float(info["log1p_std"])

        scale = std if std > 1e-12 else 1.0

        result["features"][field] = {
            "log1p_mean": float(info["log1p_mean"]),
            "log1p_std": std,
            "scale_used": scale,
            "train_observed": int(info["observed"]),
            "train_missing": int(info["missing"]),
            "train_missing_rate": float(info["missing_rate"]),
            "raw_train_min": info["raw_min"],
            "raw_train_max": info["raw_max"],
        }

    return result


def build_spec(
    *,
    report04b: dict[str, Any],
    category_maps: dict[str, Any],
    numeric_stats: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": "network-preprocess-spec-v1.0",
        "fit_split": "train",
        "split_source": "frozen STEP 02 hostname split inherited through STEP 04B",
        "input_contract": "network-feature-contract-v1.0",
        "categorical_features": ALL_CATEGORICAL_FIELDS,
        "numerical_features": NUMERIC_FIELDS,
        "categorical_reserved_ids": RESERVED_IDS,
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
            "port_class_common_ports": COMMON_PORTS,
            "port_class_fallbacks": [
                "WELL_KNOWN_OTHER",
                "REGISTERED",
                "EPHEMERAL",
                "OTHER",
                "<MISSING>",
            ],
        },
        "numeric_transform": numeric_stats["transform"],
        "numeric_missing_policy": numeric_stats["missing_policy"],
        "non_predictive_fields": [
            "uid",
            "hostname",
            "split",
            "label",
            "raw exact timestamp",
            "raw global IP identity as learned category",
        ],
        "graph_construction_fields_kept_raw_until_step04d": [
            "orig_h",
            "orig_p",
            "resp_h",
            "resp_p",
        ],
        "unmatched_split_policy": (
            "Keep for audit/diagnostics. Do not use in baseline supervised "
            "TRAIN/VAL/TEST."
        ),
        "step04b_joined_rows": int(
            report04b["joined"]["joined_unique_uid_rows"]
        ),
        "next_step": (
            "STEP 04D builds shared (hostname, 15-minute-window, chunk) "
            "graph/sequence samples using these frozen mappings/statistics."
        ),
    }


def make_report(
    *,
    report04b: dict[str, Any],
    category_diagnostics: dict[str, Any],
    numeric_profile: dict[str, Any],
    category_maps: dict[str, Any],
    numeric_stats: dict[str, Any],
    policy: dict[str, Any],
    candidate_fingerprint: str,
) -> dict[str, Any]:
    warnings: list[str] = []

    for field, diag in category_diagnostics.items():
        val_unk = diag["by_split"]["val"]["UNK_rate"]
        test_unk = diag["by_split"]["test"]["UNK_rate"]

        if val_unk > 0.05 or test_unk > 0.05:
            warnings.append(
                f"{field}: OOV/UNK rate >5% ở VAL hoặc TEST "
                f"(val={val_unk:.3%}, test={test_unk:.3%})."
            )

    for field in NUMERIC_FIELDS:
        std = numeric_stats["features"][field]["log1p_std"]
        if std <= 1e-12:
            warnings.append(
                f"{field}: TRAIN log1p std gần 0; scale_used=1.0."
            )

    automatic_checks = {
        "step04b_missing_label_zero": (
            int(report04b["joined"]["missing_label_rows"]) == 0
        ),
        "train_rows_exist": (
            int(report04b["joined"]["rows_by_split"]["train"]) > 0
        ),
        "train_positive_exists": (
            int(report04b["joined"]["labels_by_split"]["train"]["1"]) > 0
        ),
        "all_category_maps_nonempty": all(
            int(info["size"]) >= 2
            for info in category_maps["fields"].values()
        ),
        "all_numeric_stats_present": all(
            field in numeric_stats["features"]
            for field in NUMERIC_FIELDS
        ),
    }

    ready = all(automatic_checks.values())

    return {
        "generated_at": now_iso(),
        "script_version": SCRIPT_VERSION,
        "status": "CANDIDATE_READY_FOR_REVIEW" if ready else "NOT_READY",
        "fit_policy": {
            "fit_split": "train",
            "val_used_for_fit": False,
            "test_used_for_fit": False,
            "unmatched_split_used_for_fit": False,
            **policy,
        },
        "step04b_summary": {
            "joined_rows": int(
                report04b["joined"]["joined_unique_uid_rows"]
            ),
            "rows_by_split": report04b["joined"]["rows_by_split"],
            "labels_by_split": report04b["joined"]["labels_by_split"],
        },
        "category_diagnostics": category_diagnostics,
        "numeric_profile_by_split": numeric_profile,
        "automatic_checks": automatic_checks,
        "warnings": warnings,
        "candidate_fingerprint_sha256": candidate_fingerprint,
        "decision_gate": (
            "Review category cardinality, TRAIN rare-category collapse, "
            "VAL/TEST UNK rates, missing rates, numeric std, and app_family "
            "dominance. Freeze only after review."
        ),
    }


def write_md(
    path: Path,
    *,
    report: dict[str, Any],
    frozen: bool,
    artifact_dir: Path,
) -> None:
    status = (
        "FROZEN — READY FOR STEP 04D"
        if frozen
        else report["status"]
    )

    lines = [
        "# STEP 04C — TRAIN-only Network preprocessing",
        "",
        "## Trạng thái",
        "",
        f"**{status}**",
        "",
        "## Mục tiêu",
        "",
        "Tạo và freeze preprocessing contract cho Network DL mà không để VAL/TEST ảnh hưởng đến mapping/statistics.",
        "",
        "## Nguyên tắc leakage",
        "",
        "- Category maps chỉ fit trên TRAIN.",
        "- Numerical mean/std chỉ fit trên TRAIN.",
        "- VAL/TEST chỉ được dùng để đo missing/OOV sau khi TRAIN mapping đã được tạo.",
        "- `label` không tham gia việc chọn category hay numerical scaling.",
        "- `unmatched_split` không tham gia fit và không dùng cho baseline supervised training.",
        "",
        "## Categorical features",
        "",
    ]

    for field, diag in report["category_diagnostics"].items():
        train = diag["by_split"]["train"]
        val = diag["by_split"]["val"]
        test = diag["by_split"]["test"]

        lines.extend([
            f"### `{field}`",
            "",
            f"- TRAIN unique values: **{diag['train_unique_values_including_missing']:,}**",
            f"- Mapping size (gồm `<UNK>/<MISSING>`): **{diag['mapping_size_including_reserved']:,}**",
            f"- TRAIN mapped-to-UNK rate: **{train['UNK_rate']:.5%}**",
            f"- VAL UNK rate: **{val['UNK_rate']:.5%}**",
            f"- TEST UNK rate: **{test['UNK_rate']:.5%}**",
            f"- TRAIN missing rate: **{train['missing_rate']:.5%}**",
            "",
        ])

    lines.extend([
        "## Numerical transform",
        "",
        "Policy:",
        "",
        "```text",
        "non-negative raw value",
        "    -> log1p",
        "    -> z-score bằng TRAIN mean/std",
        "```",
        "",
        "Missing numerical value:",
        "",
        "```text",
        "normalized value = 0.0",
        "+ parallel missing mask",
        "```",
        "",
    ])

    train_numeric = report["numeric_profile_by_split"].get("train", {})
    for field, info in train_numeric.get("features", {}).items():
        lines.append(
            f"- `{field}`: missing={info['missing_rate']:.5%}, "
            f"log1p_mean={info['log1p_mean']:.6f}, "
            f"log1p_std={info['log1p_std']:.6f}"
        )

    lines.extend([
        "",
        "## Semantic derived categories",
        "",
        "IP không được dùng làm global learned identity. Chỉ derive finite scope:",
        "",
        "```text",
        "LOOPBACK / PRIVATE / PRIVATE_IPV6 / LINK_LOCAL /",
        "MULTICAST / BROADCAST / PUBLIC_IPV4 / PUBLIC_IPV6 / OTHER",
        "```",
        "",
        "Port không dùng exact port làm global category. Dùng semantic/common-port class + bucket.",
        "",
        "## Output",
        "",
        f"- Artifact root: `{artifact_dir}`",
        "- Candidate maps/stats/spec luôn được tạo trước.",
        "- Khi `--freeze`, final files được tạo mà không scan lại 92M rows.",
        "",
        "## Warning / review",
        "",
    ])

    if report["warnings"]:
        for warning in report["warnings"]:
            lines.append(f"- {warning}")
    else:
        lines.append("- Không có warning tự động.")

    lines.extend([
        "",
        "## Next step",
        "",
        (
            "Nếu candidate được review và chấp nhận: rerun cùng command với "
            "`--freeze`, sau đó sang STEP 04D."
            if not frozen
            else (
                "STEP 04D — build shared `(hostname, 15-minute-window, chunk)` "
                "graph/sequence samples và Kaggle shards."
            )
        ),
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument("--output-root", required=True)
    parser.add_argument("--joined-root", default=None)
    parser.add_argument("--report04b", default=None)

    parser.add_argument("--threads", type=int, default=max(2, min(8, os.cpu_count() or 4)))
    parser.add_argument("--duckdb-memory-limit", default="8GB")

    parser.add_argument("--app-min-freq", type=int, default=5)
    parser.add_argument("--service-min-freq", type=int, default=5)
    parser.add_argument("--default-min-freq", type=int, default=1)

    parser.add_argument("--app-max-values", type=int, default=5000)
    parser.add_argument("--service-max-values", type=int, default=1000)
    parser.add_argument("--default-max-values", type=int, default=256)

    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--rebuild-candidate", action="store_true")

    args = parser.parse_args()

    output_root = Path(args.output_root)

    joined_root = (
        Path(args.joined_root)
        if args.joined_root
        else output_root / "02_artifacts" / "02_network_joined_v1" / "joined"
    )

    report04b_path = (
        Path(args.report04b)
        if args.report04b
        else output_root / "02_artifacts" / "02_network_joined_v1" / "network_join_exact_report.json"
    )

    artifact_dir = output_root / "02_artifacts" / "03_network_preprocess_v1"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    temp_dir = artifact_dir / "_duckdb_spill"

    candidate_maps_path = artifact_dir / "network_category_maps_candidate.json"
    candidate_numeric_path = artifact_dir / "network_numeric_stats_candidate.json"
    candidate_spec_path = artifact_dir / "network_preprocess_spec_candidate.json"
    report_path = artifact_dir / "network_preprocess_report.json"
    state_path = artifact_dir / "candidate_state.json"
    md_path = artifact_dir / "STEP_03A_NETWORK_PREPROCESS_FIT.md"

    final_maps_path = artifact_dir / "network_category_maps.json"
    final_numeric_path = artifact_dir / "network_numeric_stats.json"
    final_spec_path = artifact_dir / "network_preprocess_spec.json"
    fingerprint_path = artifact_dir / "network_preprocess_fingerprint.json"

    if not joined_root.exists():
        raise FileNotFoundError(joined_root)
    if not report04b_path.exists():
        raise FileNotFoundError(report04b_path)

    report04b = load_04b_report(report04b_path)
    report04b_sha = sha256_file(report04b_path)

    policy = {
        "app_min_freq": args.app_min_freq,
        "service_min_freq": args.service_min_freq,
        "default_min_freq": args.default_min_freq,
        "app_max_values": args.app_max_values,
        "service_max_values": args.service_max_values,
        "default_max_values": args.default_max_values,
    }

    desired_state = {
        "script_version": SCRIPT_VERSION,
        "report04b_sha256": report04b_sha,
        "joined_rows": int(report04b["joined"]["joined_unique_uid_rows"]),
        "policy": policy,
    }

    candidate_files_exist = all(
        p.exists()
        for p in (
            candidate_maps_path,
            candidate_numeric_path,
            candidate_spec_path,
            report_path,
            state_path,
        )
    )

    reuse_candidate = False

    if candidate_files_exist and not args.rebuild_candidate:
        old_state = json.loads(state_path.read_text(encoding="utf-8"))
        reuse_candidate = old_state == desired_state

        if not reuse_candidate:
            raise RuntimeError(
                "Candidate STEP 04C đã tồn tại nhưng input/policy khác command hiện tại.\n"
                "Nếu muốn scan lại có chủ đích, thêm --rebuild-candidate."
            )

    print("=" * 96)
    print("STEP 04C — TRAIN-only Network preprocessing")
    print("=" * 96)
    print(f"[JOINED] {joined_root}")
    print(f"[ROWS]   {report04b['joined']['joined_unique_uid_rows']:,}")
    print("[FIT]    TRAIN only")
    print(f"[THREADS] {args.threads}")
    print(f"[DUCKDB]  memory_limit={args.duckdb_memory_limit}")
    print()

    if not reuse_candidate:
        db = duckdb_connect(
            threads=args.threads,
            memory_limit=args.duckdb_memory_limit,
            temp_dir=temp_dir,
        )

        try:
            source = joined_glob(joined_root)

            print("[1/4] Scan categorical distributions across splits...")
            category_rows = query_category_counts(db, source)
            category_counts = group_category_counts(category_rows)

            print("[2/4] Build TRAIN-only category maps...")
            category_maps, category_diagnostics = build_category_maps(
                category_counts,
                app_min_freq=args.app_min_freq,
                service_min_freq=args.service_min_freq,
                default_min_freq=args.default_min_freq,
                app_max_values=args.app_max_values,
                service_max_values=args.service_max_values,
                default_max_values=args.default_max_values,
            )

            print("[3/4] Scan numerical statistics across splits...")
            numeric_profile = query_numeric_profile(db, source)
            numeric_stats = build_numeric_stats(numeric_profile)

            print("[4/4] Build candidate spec/report...")
            spec = build_spec(
                report04b=report04b,
                category_maps=category_maps,
                numeric_stats=numeric_stats,
            )

            candidate_core = {
                "category_maps": category_maps,
                "numeric_stats": numeric_stats,
                "spec": spec,
                "report04b_sha256": report04b_sha,
            }
            candidate_fingerprint = sha256_bytes(
                canonical_json_bytes(candidate_core)
            )

            report = make_report(
                report04b=report04b,
                category_diagnostics=category_diagnostics,
                numeric_profile=numeric_profile,
                category_maps=category_maps,
                numeric_stats=numeric_stats,
                policy=policy,
                candidate_fingerprint=candidate_fingerprint,
            )

            candidate_maps_path.write_text(
                json.dumps(category_maps, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            candidate_numeric_path.write_text(
                json.dumps(numeric_stats, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            candidate_spec_path.write_text(
                json.dumps(spec, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            report_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            state_path.write_text(
                json.dumps(desired_state, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        finally:
            db.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    else:
        print("[CACHE] Candidate input/policy match -> không scan lại 92M rows.")
        category_maps = json.loads(
            candidate_maps_path.read_text(encoding="utf-8")
        )
        numeric_stats = json.loads(
            candidate_numeric_path.read_text(encoding="utf-8")
        )
        spec = json.loads(
            candidate_spec_path.read_text(encoding="utf-8")
        )
        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )

    frozen = False

    if args.freeze:
        print()
        print("[FREEZE] Validate candidate...")

        if report.get("status") != "CANDIDATE_READY_FOR_REVIEW":
            raise RuntimeError(
                f"Candidate chưa ready: {report.get('status')!r}"
            )

        if not all(report.get("automatic_checks", {}).values()):
            raise RuntimeError(
                "Automatic checks chưa PASS. Không freeze."
            )

        shutil.copy2(candidate_maps_path, final_maps_path)
        shutil.copy2(candidate_numeric_path, final_numeric_path)
        shutil.copy2(candidate_spec_path, final_spec_path)

        fingerprint_payload = {
            "generated_at": now_iso(),
            "script_version": SCRIPT_VERSION,
            "report04b_sha256": report04b_sha,
            "category_maps_sha256": sha256_file(final_maps_path),
            "numeric_stats_sha256": sha256_file(final_numeric_path),
            "preprocess_spec_sha256": sha256_file(final_spec_path),
            "candidate_fingerprint_sha256": report[
                "candidate_fingerprint_sha256"
            ],
            "fit_split": "train",
            "val_used_for_fit": False,
            "test_used_for_fit": False,
            "unmatched_split_used_for_fit": False,
        }

        frozen_fingerprint = sha256_bytes(
            canonical_json_bytes(fingerprint_payload)
        )
        fingerprint_payload["frozen_fingerprint_sha256"] = frozen_fingerprint

        fingerprint_path.write_text(
            json.dumps(
                fingerprint_payload,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        frozen = True

    write_md(
        md_path,
        report=report,
        frozen=frozen,
        artifact_dir=artifact_dir,
    )

    print()
    print("=" * 96)
    print(
        "[STATUS] "
        + ("FROZEN — READY FOR STEP 04D" if frozen else report["status"])
    )
    print()

    for field in ALL_CATEGORICAL_FIELDS:
        diag = report["category_diagnostics"][field]
        print(
            f"[CAT] {field:18s} "
            f"map={diag['mapping_size_including_reserved']:>5,} | "
            f"trainUNK={100*diag['by_split']['train']['UNK_rate']:>7.3f}% | "
            f"valUNK={100*diag['by_split']['val']['UNK_rate']:>7.3f}% | "
            f"testUNK={100*diag['by_split']['test']['UNK_rate']:>7.3f}%"
        )

    print()
    print(f"[REPORT] {report_path}")
    print(f"[MD]     {md_path}")

    if frozen:
        print(f"[MAPS]   {final_maps_path}")
        print(f"[NUM]    {final_numeric_path}")
        print(f"[SPEC]   {final_spec_path}")
        print(f"[FP]     {fingerprint_path}")
    else:
        print("[NEXT] Review report rồi rerun SAME command với --freeze.")

    print("=" * 96)


if __name__ == "__main__":
    main()
