from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd


SCRIPT_VERSION = "step05f-b-loso-remap-audit-v1.1-zero-row-safe"
SUPERVISED_SPLITS = ("train", "val", "test")


def now_iso() -> str:
    return datetime.now().isoformat()


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def normalized_bool(series: pd.Series) -> pd.Series:
    if series.dtype == bool:
        return series

    lowered = (
        series.astype(str)
        .str.strip()
        .str.lower()
    )

    return lowered.isin(
        {"true", "1", "yes", "y"}
    )


def discover_candidate_folds(
    candidate_root: Path,
) -> list[tuple[str, Path]]:
    result = []

    for folder in sorted(
        candidate_root.glob(
            "holdout_*"
        )
    ):
        if not folder.is_dir():
            continue

        host_csv = (
            folder
            / "host_split_candidate.csv"
        )

        if not host_csv.exists():
            continue

        df = pd.read_csv(host_csv)

        scenarios = (
            df[
                "heldout_scenario"
            ]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        if len(scenarios) != 1:
            raise RuntimeError(
                f"{host_csv} must contain exactly "
                "one heldout_scenario."
            )

        result.append(
            (
                scenarios[0],
                host_csv,
            )
        )

    if not result:
        raise RuntimeError(
            f"No candidate folds found under "
            f"{candidate_root}"
        )

    return result


def joined_host_summary(
    *,
    joined_root: Path,
    threads: int,
    memory_limit: str,
    temp_dir: Path,
) -> pd.DataFrame:
    """
    Scan the 04B joined Parquet ONCE and aggregate to hostname-level.

    No 85M-row copy is produced.

    This is sufficient to prove:
      - which original split each hostname belongs to
      - exact event counts per hostname
      - exact positive-event counts per hostname
      - ts range per hostname

    Later STEP 05F-C/05F-D will use the frozen hostname mapping directly
    against the original joined Parquet.
    """

    parquet_glob = (
        joined_root
        / "split=*"
        / "date=*"
        / "*.parquet"
    )

    # Early filesystem sanity check.
    one_file = next(
        joined_root.rglob("*.parquet"),
        None,
    )

    if one_file is None:
        raise FileNotFoundError(
            f"No Parquet files under {joined_root}"
        )

    temp_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    con = duckdb.connect(
        database=":memory:"
    )

    try:
        con.execute(
            f"SET threads={int(threads)}"
        )
        con.execute(
            f"SET memory_limit='{memory_limit}'"
        )
        con.execute(
            f"SET temp_directory="
            f"'{str(temp_dir).replace(chr(92), '/')}'"
        )

        source = (
            str(parquet_glob)
            .replace("\\", "/")
            .replace("'", "''")
        )

        query = f"""
        SELECT
            hostname,
            split AS original_split,
            COUNT(*)::BIGINT AS event_rows,
            SUM(
                CASE
                    WHEN CAST(label AS INTEGER) = 1
                        THEN 1
                    ELSE 0
                END
            )::BIGINT AS positive_event_rows,
            MIN(CAST(ts AS DOUBLE)) AS min_ts,
            MAX(CAST(ts AS DOUBLE)) AS max_ts
        FROM read_parquet(
            '{source}',
            hive_partitioning=true
        )
        WHERE
            split IN ('train', 'val', 'test')
            AND hostname IS NOT NULL
            AND trim(hostname) <> ''
        GROUP BY
            hostname,
            split
        ORDER BY
            hostname,
            split
        """

        return con.execute(
            query
        ).fetchdf()

    finally:
        con.close()
        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )


def validate_candidate(
    *,
    candidate: pd.DataFrame,
    host_stats: pd.DataFrame,
    heldout_scenario: str,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    required = {
        "hostname",
        "gt_positive_host_group",
        "gt_primary_scenario",
        "original_split",
        "loso_split",
        "heldout_scenario",
        "role",
    }

    missing = (
        required
        - set(candidate.columns)
    )

    if missing:
        raise RuntimeError(
            f"Candidate missing columns: "
            f"{sorted(missing)}"
        )

    candidate = candidate.copy()

    candidate[
        "gt_positive_host_group"
    ] = normalized_bool(
        candidate[
            "gt_positive_host_group"
        ]
    )

    # One host -> one mapping per fold.
    duplicate_hosts = (
        candidate[
            "hostname"
        ]
        .duplicated(
            keep=False
        )
    )

    duplicate_hostnames = sorted(
        candidate.loc[
            duplicate_hosts,
            "hostname",
        ]
        .astype(str)
        .unique()
        .tolist()
    )

    valid_split_values = candidate[
        "loso_split"
    ].isin(
        SUPERVISED_SPLITS
    )

    # Every joined hostname should belong to exactly one current split.
    split_count_by_host = (
        host_stats.groupby(
            "hostname"
        )[
            "original_split"
        ]
        .nunique()
    )

    multi_original_split_hosts = (
        split_count_by_host[
            split_count_by_host > 1
        ]
        .index
        .astype(str)
        .tolist()
    )

    host_agg = (
        host_stats.groupby(
            "hostname",
            as_index=False,
        )
        .agg(
            event_rows=(
                "event_rows",
                "sum",
            ),
            positive_event_rows=(
                "positive_event_rows",
                "sum",
            ),
            min_ts=(
                "min_ts",
                "min",
            ),
            max_ts=(
                "max_ts",
                "max",
            ),
        )
    )

    original_split_lookup = (
        host_stats.drop_duplicates(
            "hostname"
        )[
            [
                "hostname",
                "original_split",
            ]
        ]
        .rename(
            columns={
                "original_split":
                    "joined_original_split"
            }
        )
    )

    merged = (
        candidate.merge(
            host_agg,
            on="hostname",
            how="outer",
            indicator=True,
        )
        .merge(
            original_split_lookup,
            on="hostname",
            how="left",
        )
    )

    candidate_only_hosts = sorted(
        merged.loc[
            merged["_merge"]
            == "left_only",
            "hostname",
        ]
        .dropna()
        .astype(str)
        .tolist()
    )

    joined_only_hosts = sorted(
        merged.loc[
            merged["_merge"]
            == "right_only",
            "hostname",
        ]
        .dropna()
        .astype(str)
        .tolist()
    )

    both = merged[
        merged["_merge"]
        == "both"
    ].copy()

    original_split_mismatch = (
        both[
            "original_split"
        ]
        != both[
            "joined_original_split"
        ]
    )

    mismatch_hosts = sorted(
        both.loc[
            original_split_mismatch,
            "hostname",
        ]
        .astype(str)
        .tolist()
    )

    # Scenario gates.
    heldout_positive = both[
        (
            both[
                "gt_positive_host_group"
            ] == True
        )
        & (
            both[
                "gt_primary_scenario"
            ].astype(str)
            == heldout_scenario
        )
    ]

    seen_positive = both[
        (
            both[
                "gt_positive_host_group"
            ] == True
        )
        & (
            both[
                "gt_primary_scenario"
            ].astype(str)
            != heldout_scenario
        )
    ]

    benign = both[
        both[
            "gt_positive_host_group"
        ] == False
    ]

    heldout_only_test = bool(
        len(heldout_positive) > 0
        and (
            heldout_positive[
                "loso_split"
            ]
            == "test"
        ).all()
    )

    seen_not_test = bool(
        not (
            seen_positive[
                "loso_split"
            ]
            == "test"
        ).any()
    )

    benign_frozen = bool(
        (
            benign[
                "loso_split"
            ]
            == benign[
                "original_split"
            ]
        ).all()
    )

    # Exact event-level counts after logical remap.
    by_split = (
        both.groupby(
            "loso_split",
            as_index=False,
        )
        .agg(
            hosts=(
                "hostname",
                "nunique",
            ),
            event_rows=(
                "event_rows",
                "sum",
            ),
            positive_event_rows=(
                "positive_event_rows",
                "sum",
            ),
        )
    )

    split_stats = {}

    for split in SUPERVISED_SPLITS:
        row = by_split[
            by_split[
                "loso_split"
            ] == split
        ]

        if len(row) == 0:
            split_stats[
                split
            ] = {
                "hosts": 0,
                "event_rows": 0,
                "positive_event_rows": 0,
            }
        else:
            item = row.iloc[0]

            split_stats[
                split
            ] = {
                "hosts":
                    int(item["hosts"]),
                "event_rows":
                    int(item["event_rows"]),
                "positive_event_rows":
                    int(
                        item[
                            "positive_event_rows"
                        ]
                    ),
            }

    # Scenario x LOSO split host/event counts.
    scenario_rows = both[
        both[
            "gt_positive_host_group"
        ] == True
    ]

    scenario_table = (
        scenario_rows.groupby(
            [
                "gt_primary_scenario",
                "loso_split",
            ],
            as_index=False,
        )
        .agg(
            hosts=(
                "hostname",
                "nunique",
            ),
            event_rows=(
                "event_rows",
                "sum",
            ),
            positive_event_rows=(
                "positive_event_rows",
                "sum",
            ),
        )
    )

    scenario_stats: dict[
        str,
        dict[str, Any],
    ] = {}

    for scenario in sorted(
        scenario_rows[
            "gt_primary_scenario"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    ):
        scenario_stats[
            scenario
        ] = {}

        for split in SUPERVISED_SPLITS:
            row = scenario_table[
                (
                    scenario_table[
                        "gt_primary_scenario"
                    ].astype(str)
                    == scenario
                )
                & (
                    scenario_table[
                        "loso_split"
                    ]
                    == split
                )
            ]

            if len(row) == 0:
                scenario_stats[
                    scenario
                ][split] = {
                    "hosts": 0,
                    "event_rows": 0,
                    "positive_event_rows": 0,
                }
            else:
                item = row.iloc[0]

                scenario_stats[
                    scenario
                ][split] = {
                    "hosts":
                        int(item["hosts"]),
                    "event_rows":
                        int(item["event_rows"]),
                    "positive_event_rows":
                        int(
                            item[
                                "positive_event_rows"
                            ]
                        ),
                }

    total_original_events = int(
        host_agg[
            "event_rows"
        ].sum()
    )

    total_remapped_events = int(
        both[
            "event_rows"
        ].sum()
    )

    event_conservation = (
        total_original_events
        == total_remapped_events
    )

    # Candidate may contain hosts that never appear in the STEP 04B joined
    # network dataset (e.g. host telemetry exists, but no exact eCAR-Bro/Bro
    # joined rows). Such zero-network-row hosts are harmless for this Network
    # DL LOSO experiment IF they are pure benign hosts.
    candidate_only_meta = candidate[
        candidate["hostname"].isin(
            candidate_only_hosts
        )
    ].copy()

    candidate_only_positive_hosts = sorted(
        candidate_only_meta.loc[
            candidate_only_meta[
                "gt_positive_host_group"
            ] == True,
            "hostname",
        ]
        .astype(str)
        .unique()
        .tolist()
    )

    candidate_extra_hosts_safe = (
        len(candidate_only_positive_hosts)
        == 0
    )

    gates = {
        "candidate_hostname_unique":
            len(duplicate_hostnames)
            == 0,
        "loso_split_values_valid":
            bool(
                valid_split_values.all()
            ),
        "joined_hostname_one_original_split":
            len(
                multi_original_split_hosts
            )
            == 0,
        "candidate_covers_all_joined_hosts":
            len(joined_only_hosts)
            == 0,
        "candidate_extra_hosts_safe_zero_network_rows":
            candidate_extra_hosts_safe,
        "candidate_original_split_matches_joined":
            len(mismatch_hosts)
            == 0,
        "heldout_positive_hosts_only_test":
            heldout_only_test,
        "seen_positive_hosts_not_test":
            seen_not_test,
        "pure_benign_hosts_keep_original_split":
            benign_frozen,
        "event_conservation":
            event_conservation,
    }

    passed = all(
        gates.values()
    )

    # Clean output columns.
    audited = both[
        [
            "hostname",
            "gt_positive_host_group",
            "gt_primary_scenario",
            "original_split",
            "loso_split",
            "heldout_scenario",
            "role",
            "event_rows",
            "positive_event_rows",
            "min_ts",
            "max_ts",
        ]
    ].sort_values(
        "hostname"
    )

    report = {
        "heldout_scenario":
            heldout_scenario,
        "status":
            (
                "PASS_READY_TO_FREEZE"
                if passed
                else "FAIL"
            ),
        "gates":
            gates,
        "total_original_supervised_event_rows":
            total_original_events,
        "total_remapped_supervised_event_rows":
            total_remapped_events,
        "split_stats":
            split_stats,
        "scenario_stats":
            scenario_stats,
        "errors": {
            "duplicate_candidate_hostnames":
                duplicate_hostnames[
                    :100
                ],
            "joined_hosts_missing_from_candidate":
                joined_only_hosts[
                    :100
                ],
            "candidate_zero_network_row_hosts":
                candidate_only_hosts[
                    :100
                ],
            "candidate_zero_network_row_positive_hosts":
                candidate_only_positive_hosts[
                    :100
                ],
            "original_split_mismatch_hosts":
                mismatch_hosts[
                    :100
                ],
            "multi_original_split_hosts":
                multi_original_split_hosts[
                    :100
                ],
        },
    }

    return audited, report


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--joined-root",
        required=True,
        help=(
            "STEP 04B joined folder, e.g. "
            r"D:\UIT\KLTNv2\02_artifacts\02_network_joined_v1\joined"
        ),
    )

    parser.add_argument(
        "--candidate-root",
        required=True,
        help=(
            "Folder containing holdout_scenario_*/"
            "host_split_candidate.csv"
        ),
    )

    parser.add_argument(
        "--output-root",
        required=True,
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=8,
    )

    parser.add_argument(
        "--duckdb-memory-limit",
        default="8GB",
    )

    parser.add_argument(
        "--freeze",
        action="store_true",
        help=(
            "Freeze mappings only if all gates PASS. "
            "Run once without this flag first."
        ),
    )

    args = parser.parse_args()

    joined_root = Path(
        args.joined_root
    )
    candidate_root = Path(
        args.candidate_root
    )
    output_root = Path(
        args.output_root
    )

    artifact_dir = (
        output_root
        / "02_artifacts"
        / "08a_loso_remap_v1"
    )

    artifact_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    spill_dir = (
        artifact_dir
        / "_duckdb_spill"
    )

    print("=" * 100)
    print(
        "STEP 05F-B — LOSO logical remap audit"
    )
    print("=" * 100)
    print(
        "[MODE] "
        + (
            "FREEZE"
            if args.freeze
            else "CANDIDATE REVIEW"
        )
    )
    print(
        "[POLICY] No 85M-row copy. "
        "Scan joined Parquet once -> hostname stats -> "
        "freeze fold mapping."
    )
    print()

    folds = discover_candidate_folds(
        candidate_root
    )

    print(
        f"[FOLDS] {len(folds)}"
    )

    print(
        "[1/3] Scan STEP 04B joined dataset "
        "to exact hostname-level statistics..."
    )

    host_stats = joined_host_summary(
        joined_root=joined_root,
        threads=args.threads,
        memory_limit=
            args.duckdb_memory_limit,
        temp_dir=spill_dir,
    )

    host_stats_path = (
        artifact_dir
        / "joined_host_event_stats.csv"
    )

    host_stats.to_csv(
        host_stats_path,
        index=False,
    )

    print(
        f"[JOINED HOSTS] "
        f"{host_stats['hostname'].nunique():,}"
    )
    print(
        f"[SUPERVISED EVENTS] "
        f"{int(host_stats['event_rows'].sum()):,}"
    )
    print(
        f"[POSITIVE EVENTS] "
        f"{int(host_stats['positive_event_rows'].sum()):,}"
    )
    print()

    print(
        "[2/3] Audit each LOSO fold..."
    )

    all_reports = {}
    combined_plans = []
    all_pass = True

    candidate_hashes = {}

    for heldout, candidate_path in folds:
        print()
        print(
            f"[FOLD] holdout={heldout}"
        )

        candidate = pd.read_csv(
            candidate_path
        )

        audited, report = (
            validate_candidate(
                candidate=candidate,
                host_stats=host_stats,
                heldout_scenario=
                    heldout,
            )
        )

        fold_out = (
            artifact_dir
            / f"holdout_{heldout}"
        )

        fold_out.mkdir(
            parents=True,
            exist_ok=True,
        )

        audited_path = (
            fold_out
            / "host_split_audited.csv"
        )

        audited.to_csv(
            audited_path,
            index=False,
        )

        report_path = (
            fold_out
            / "fold_remap_audit.json"
        )

        dump_json(
            report_path,
            report,
        )

        candidate_hashes[
            heldout
        ] = sha256_file(
            candidate_path
        )

        plan = audited.copy()

        plan.insert(
            0,
            "fold",
            f"holdout_{heldout}",
        )

        combined_plans.append(
            plan
        )

        all_reports[
            heldout
        ] = report

        if (
            report["status"]
            != "PASS_READY_TO_FREEZE"
        ):
            all_pass = False

        print(
            f"    [STATUS] "
            f"{report['status']}"
        )

        for split in SUPERVISED_SPLITS:
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

    combined = pd.concat(
        combined_plans,
        ignore_index=True,
    )

    combined_path = (
        artifact_dir
        / "loso_remap_plan.csv"
    )

    combined.to_csv(
        combined_path,
        index=False,
    )

    master_report = {
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
            str(joined_root),
        "candidate_root":
            str(candidate_root),
        "joined_host_stats":
            str(host_stats_path),
        "joined_supervised_events":
            int(
                host_stats[
                    "event_rows"
                ].sum()
            ),
        "joined_positive_events":
            int(
                host_stats[
                    "positive_event_rows"
                ].sum()
            ),
        "candidate_sha256":
            candidate_hashes,
        "all_folds_pass":
            all_pass,
        "folds":
            all_reports,
        "design_decision":
            (
                "Do not materialize three full joined datasets. "
                "Freeze hostname->LOSO split mappings and let "
                "STEP 05F-C/05F-D query original STEP 04B Parquet "
                "through the frozen mapping."
            ),
    }

    master_report_path = (
        artifact_dir
        / "STEP_05F_B_LOSO_REMAP_AUDIT.json"
    )

    dump_json(
        master_report_path,
        master_report,
    )

    print()
    print(
        "[3/3] Build review/freeze contract..."
    )

    if args.freeze:
        if not all_pass:
            print(
                "[FREEZE BLOCKED] "
                "At least one fold failed."
            )
            raise SystemExit(2)

        frozen_dir = (
            artifact_dir
            / "frozen"
        )

        if frozen_dir.exists():
            existing_contract = (
                frozen_dir
                / "loso_fold_contract.json"
            )

            if existing_contract.exists():
                print(
                    "[FROZEN] Existing frozen contract detected."
                )
                print(
                    "[SAFETY] Delete it manually only if you "
                    "intentionally want a new experiment definition."
                )
                raise SystemExit(3)

        frozen_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        frozen_folds = {}

        for heldout, _candidate_path in folds:
            source = (
                artifact_dir
                / f"holdout_{heldout}"
                / "host_split_audited.csv"
            )

            target = (
                frozen_dir
                / f"host_split_holdout_{heldout}.csv"
            )

            shutil.copy2(
                source,
                target,
            )

            frozen_folds[
                heldout
            ] = {
                "file":
                    target.name,
                "sha256":
                    sha256_file(
                        target
                    ),
            }

        contract = {
            "frozen_at":
                now_iso(),
            "script_version":
                SCRIPT_VERSION,
            "joined_root":
                str(joined_root),
            "joined_supervised_events":
                int(
                    host_stats[
                        "event_rows"
                    ].sum()
                ),
            "joined_positive_events":
                int(
                    host_stats[
                        "positive_event_rows"
                    ].sum()
                ),
            "folds":
                frozen_folds,
            "rules": {
                "unit":
                    "hostname",
                "heldout_scenario_positive_hosts":
                    "TEST only",
                "seen_scenario_positive_hosts":
                    "TRAIN/VAL only",
                "pure_benign_hosts":
                    "preserve original split",
                "physical_joined_copy":
                    False,
                "next_step":
                    (
                        "Refit STEP 04C preprocessing "
                        "separately on each fold TRAIN only."
                    ),
            },
        }

        contract_text = json.dumps(
            contract,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        contract[
            "contract_sha256"
        ] = sha256_text(
            contract_text
        )

        contract_path = (
            frozen_dir
            / "loso_fold_contract.json"
        )

        dump_json(
            contract_path,
            contract,
        )

        print()
        print(
            "[SUCCESS] LOSO mappings FROZEN"
        )
        print(
            f"[CONTRACT] {contract_path}"
        )
        print(
            f"[SHA256] "
            f"{contract['contract_sha256']}"
        )
        print(
            "[NEXT] STEP 05F-C — fit network "
            "preprocessing per fold TRAIN only."
        )

    else:
        print()
        print(
            "[STATUS] "
            + (
                "ALL FOLDS PASS — READY TO FREEZE"
                if all_pass
                else "FAIL — REVIEW ERRORS"
            )
        )
        print(
            f"[REPORT] "
            f"{master_report_path}"
        )
        print(
            f"[PLAN] {combined_path}"
        )

        if all_pass:
            print()
            print(
                "[NEXT COMMAND] Re-run the same command "
                "with --freeze."
            )


if __name__ == "__main__":
    main()
