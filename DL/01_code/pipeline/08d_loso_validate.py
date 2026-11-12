from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np


SCRIPT_VERSION = "step05f-d-validate-loso-fold-v1.1-int-like-csv-fix"
VALID_SPLITS = ("train", "val", "test")


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


def dump_json(path: Path, obj: Any) -> None:
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
            h.update(block)

    return h.hexdigest()


def parse_bool(value: Any) -> bool:
    return (
        str(value)
        .strip()
        .lower()
        in {
            "1",
            "true",
            "yes",
            "y",
        }
    )


def parse_int_like(value: Any) -> int:
    """
    Parse integer-like CSV values robustly.

    Frozen LOSO CSVs may contain values such as:
        5224
        5224.0
        ""
        None

    The previous validator used int("5224.0"), which raises ValueError.
    """
    if value is None:
        return 0

    text = str(value).strip()

    if not text:
        return 0

    try:
        return int(text)
    except ValueError:
        number = float(text)

        if not number.is_integer():
            raise ValueError(
                f"Expected integer-like value, got {value!r}"
            )

        return int(number)


def parse_integrity_line(
    line: str,
) -> tuple[str, str, int]:
    parts = line.rstrip("\n").split(
        "  "
    )

    if len(parts) != 3:
        raise ValueError(
            f"Invalid integrity line: {line!r}"
        )

    digest, relative, size = parts

    return (
        digest.strip(),
        relative.strip(),
        int(size.strip()),
    )


def read_integrity(
    path: Path,
) -> list[tuple[str, str, int]]:
    rows = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        for line in f:
            if not line.strip():
                continue

            rows.append(
                parse_integrity_line(
                    line
                )
            )

    return rows


def verify_integrity(
    *,
    dataset_root: Path,
    integrity_path: Path,
    verify_sha: bool,
) -> dict[str, Any]:
    rows = read_integrity(
        integrity_path
    )

    missing = []
    size_mismatch = []
    sha_mismatch = []
    checked_sha = 0
    total_bytes = 0

    for index, (
        expected_sha,
        relative,
        expected_size,
    ) in enumerate(
        rows,
        start=1,
    ):
        path = (
            dataset_root
            / relative
        )

        if not path.exists():
            missing.append(
                relative
            )
            continue

        actual_size = (
            path.stat().st_size
        )

        total_bytes += (
            actual_size
        )

        if (
            actual_size
            != expected_size
        ):
            size_mismatch.append({
                "file":
                    relative,
                "expected":
                    expected_size,
                "actual":
                    actual_size,
            })

        if verify_sha:
            actual_sha = (
                sha256_file(
                    path
                )
            )

            checked_sha += 1

            if (
                actual_sha
                != expected_sha
            ):
                sha_mismatch.append({
                    "file":
                        relative,
                    "expected":
                        expected_sha,
                    "actual":
                        actual_sha,
                })

            if (
                index % 50 == 0
                or index == len(rows)
            ):
                print(
                    f"[SHA] {index:,}/"
                    f"{len(rows):,}"
                )

    return {
        "entries":
            len(rows),
        "missing_files":
            missing,
        "size_mismatch":
            size_mismatch,
        "sha_verified":
            bool(
                verify_sha
            ),
        "sha_files_checked":
            checked_sha,
        "sha_mismatch":
            sha_mismatch,
        "listed_bytes":
            total_bytes,
    }


def load_host_mapping(
    path: Path,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, Any],
]:
    mapping = {}
    split_hosts = {
        split: set()
        for split in VALID_SPLITS
    }

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        for row in csv.DictReader(
            f
        ):
            hostname = (
                str(
                    row[
                        "hostname"
                    ]
                )
                .strip()
                .lower()
            )

            split = (
                str(
                    row[
                        SPLIT_COL
                    ]
                )
                .strip()
                .lower()
            )

            if not hostname:
                raise RuntimeError(
                    "Empty hostname in frozen mapping."
                )

            if (
                split
                not in VALID_SPLITS
            ):
                raise RuntimeError(
                    f"Invalid LOSO split: {split!r}"
                )

            if (
                hostname
                in mapping
            ):
                raise RuntimeError(
                    "Duplicate hostname in "
                    f"frozen mapping: {hostname}"
                )

            info = {
                "split":
                    split,
                "gt_positive":
                    parse_bool(
                        row.get(
                            "gt_positive_host_group"
                        )
                    ),
                "scenario":
                    str(
                        row.get(
                            "gt_primary_scenario"
                        )
                        or ""
                    ).strip(),
                "event_rows":
                    parse_int_like(
                        row.get(
                            "event_rows"
                        )
                    ),
                "positive_event_rows":
                    parse_int_like(
                        row.get(
                            "positive_event_rows"
                        )
                    ),
            }

            mapping[
                hostname
            ] = info

            split_hosts[
                split
            ].add(
                hostname
            )

    host_intersections = {}

    for i, left in enumerate(
        VALID_SPLITS
    ):
        for right in (
            VALID_SPLITS[
                i + 1:
            ]
        ):
            overlap = sorted(
                split_hosts[
                    left
                ]
                & split_hosts[
                    right
                ]
            )

            host_intersections[
                f"{left}_vs_{right}"
            ] = overlap

    return (
        mapping,
        {
            "host_counts": {
                split:
                    len(
                        split_hosts[
                            split
                        ]
                    )
                for split
                in VALID_SPLITS
            },
            "host_intersections":
                host_intersections,
        },
    )


def read_manifest(
    *,
    path: Path,
    host_mapping:
        dict[str, dict[str, Any]],
    heldout_scenario: str | None,
    max_events: int,
    window_seconds: int,
) -> dict[str, Any]:
    sample_ids = set()
    sample_keys = set()

    split_stats = {
        split: {
            "samples": 0,
            "positive_samples": 0,
            "negative_samples": 0,
            "events": 0,
            "positive_events": 0,
            "hostnames": set(),
            "shards": set(),
        }
        for split
        in VALID_SPLITS
    }

    day_positive_samples = {
        split: Counter()
        for split
        in VALID_SPLITS
    }

    errors = {
        "duplicate_sample_id": [],
        "duplicate_sample_key": [],
        "missing_host_in_mapping": [],
        "host_split_mismatch": [],
        "invalid_label_rule": [],
        "event_count_out_of_range": [],
        "window_alignment_error": [],
        "date_mismatch": [],
        "positive_sample_on_nonpositive_host": [],
        "test_positive_not_heldout_scenario": [],
        "train_val_positive_from_heldout_scenario": [],
        "missing_shard_reference": [],
    }

    row_count = 0

    # mode random (heldout_scenario is None): thong ke positive window theo scenario x split / host
    pos_by_scenario_split = Counter()
    pos_by_split_host = Counter()

    with path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(
            f
        ):
            row_count += 1

            sample_id = (
                row[
                    "sample_id"
                ]
            )

            split = (
                row[
                    "split"
                ]
                .strip()
                .lower()
            )

            hostname = (
                row[
                    "hostname"
                ]
                .strip()
                .lower()
            )

            window_start = int(
                row[
                    "window_start_epoch"
                ]
            )

            chunk_index = int(
                row[
                    "chunk_index"
                ]
            )

            label = int(
                row[
                    "label"
                ]
            )

            event_count = int(
                row[
                    "event_count"
                ]
            )

            positive_event_count = int(
                row[
                    "positive_event_count"
                ]
            )

            shard_file = (
                row[
                    "shard_file"
                ]
                .replace(
                    "\\",
                    "/",
                )
            )

            if (
                split
                not in VALID_SPLITS
            ):
                raise RuntimeError(
                    f"Invalid manifest split: {split}"
                )

            if (
                sample_id
                in sample_ids
            ):
                errors[
                    "duplicate_sample_id"
                ].append(
                    sample_id
                )
            else:
                sample_ids.add(
                    sample_id
                )

            sample_key = (
                hostname,
                window_start,
                chunk_index,
            )

            if (
                sample_key
                in sample_keys
            ):
                errors[
                    "duplicate_sample_key"
                ].append(
                    {
                        "hostname":
                            hostname,
                        "window_start":
                            window_start,
                        "chunk_index":
                            chunk_index,
                    }
                )
            else:
                sample_keys.add(
                    sample_key
                )

            host_info = (
                host_mapping.get(
                    hostname
                )
            )

            if host_info is None:
                errors[
                    "missing_host_in_mapping"
                ].append(
                    hostname
                )
            else:
                if (
                    host_info[
                        "split"
                    ]
                    != split
                ):
                    errors[
                        "host_split_mismatch"
                    ].append({
                        "hostname":
                            hostname,
                        "manifest_split":
                            split,
                        "mapping_split":
                            host_info[
                                "split"
                            ],
                    })

                if label == 1:
                    if not host_info[
                        "gt_positive"
                    ]:
                        errors[
                            "positive_sample_on_nonpositive_host"
                        ].append(
                            sample_id
                        )

                    if (
                        heldout_scenario
                        is not None
                        and split
                        == "test"
                        and host_info[
                            "scenario"
                        ]
                        != heldout_scenario
                    ):
                        errors[
                            "test_positive_not_heldout_scenario"
                        ].append(
                            sample_id
                        )

                    if (
                        heldout_scenario
                        is not None
                        and split
                        in {
                            "train",
                            "val",
                        }
                        and host_info[
                            "scenario"
                        ]
                        == heldout_scenario
                    ):
                        errors[
                            "train_val_positive_from_heldout_scenario"
                        ].append(
                            sample_id
                        )

            expected_label = (
                1
                if positive_event_count
                > 0
                else 0
            )

            if (
                label
                != expected_label
            ):
                errors[
                    "invalid_label_rule"
                ].append(
                    sample_id
                )

            if not (
                1
                <= event_count
                <= max_events
            ):
                errors[
                    "event_count_out_of_range"
                ].append(
                    {
                        "sample_id":
                            sample_id,
                        "event_count":
                            event_count,
                    }
                )

            if (
                window_start
                % window_seconds
                != 0
            ):
                errors[
                    "window_alignment_error"
                ].append(
                    sample_id
                )

            utc_date = (
                datetime.fromtimestamp(
                    window_start,
                    tz=timezone.utc,
                )
                .strftime(
                    "%Y-%m-%d"
                )
            )

            if (
                utc_date
                != row[
                    "date"
                ]
            ):
                errors[
                    "date_mismatch"
                ].append({
                    "sample_id":
                        sample_id,
                    "manifest_date":
                        row[
                            "date"
                        ],
                    "utc_date":
                        utc_date,
                })

            stats = (
                split_stats[
                    split
                ]
            )

            stats[
                "samples"
            ] += 1

            stats[
                "positive_samples"
            ] += (
                1
                if label == 1
                else 0
            )

            stats[
                "negative_samples"
            ] += (
                1
                if label == 0
                else 0
            )

            stats[
                "events"
            ] += event_count

            stats[
                "positive_events"
            ] += (
                positive_event_count
            )

            stats[
                "hostnames"
            ].add(
                hostname
            )

            stats[
                "shards"
            ].add(
                shard_file
            )

            if label == 1:
                day_positive_samples[
                    split
                ][
                    utc_date
                ] += 1

                if host_info is not None:
                    pos_by_scenario_split[
                        (
                            str(
                                host_info[
                                    "scenario"
                                ]
                            ),
                            split,
                        )
                    ] += 1
                    pos_by_split_host[
                        (
                            split,
                            hostname,
                        )
                    ] += 1

    final_stats = {}

    for split in (
        VALID_SPLITS
    ):
        raw = (
            split_stats[
                split
            ]
        )

        final_stats[
            split
        ] = {
            "samples":
                raw[
                    "samples"
                ],
            "positive_samples":
                raw[
                    "positive_samples"
                ],
            "negative_samples":
                raw[
                    "negative_samples"
                ],
            "events":
                raw[
                    "events"
                ],
            "positive_events":
                raw[
                    "positive_events"
                ],
            "hosts_with_samples":
                len(
                    raw[
                        "hostnames"
                    ]
                ),
            "shards_referenced":
                len(
                    raw[
                        "shards"
                    ]
                ),
            "positive_sample_rate":
                (
                    raw[
                        "positive_samples"
                    ]
                    / raw[
                        "samples"
                    ]
                    if raw[
                        "samples"
                    ]
                    else 0.0
                ),
            "pos_weight_neg_over_pos":
                (
                    raw[
                        "negative_samples"
                    ]
                    / raw[
                        "positive_samples"
                    ]
                    if raw[
                        "positive_samples"
                    ]
                    else None
                ),
        }

    random_extra = {}

    if heldout_scenario is None:
        random_extra = {
            "positive_samples_by_scenario_split": {
                f"{scenario}|{split}": count
                for (scenario, split), count
                in sorted(
                    pos_by_scenario_split.items()
                )
            },
            "positive_samples_by_split_host": {
                f"{split}|{host}": count
                for (split, host), count
                in sorted(
                    pos_by_split_host.items()
                )
            },
        }

    return {
        **random_extra,
        "rows":
            row_count,
        "split_stats":
            final_stats,
        "day_positive_samples": {
            split:
                dict(
                    sorted(
                        counter.items()
                    )
                )
            for split, counter
            in day_positive_samples.items()
        },
        "errors":
            {
                key:
                    values[:100]
                for key, values
                in errors.items()
            },
        "error_counts":
            {
                key:
                    len(values)
                for key, values
                in errors.items()
            },
    }


def compare_report_stats(
    *,
    observed: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    mismatches = []

    fields = (
        "samples",
        "positive_samples",
        "negative_samples",
        "events",
        "positive_events",
    )

    for split in (
        VALID_SPLITS
    ):
        for field in fields:
            a = int(
                observed[
                    split
                ][field]
            )

            b = int(
                expected[
                    split
                ][field]
            )

            if a != b:
                mismatches.append({
                    "split":
                        split,
                    "field":
                        field,
                    "observed":
                        a,
                    "expected":
                        b,
                })

    return {
        "pass":
            len(
                mismatches
            )
            == 0,
        "mismatches":
            mismatches,
    }


def smoke_npz(
    *,
    dataset_root: Path,
    manifest_path: Path,
    spec: dict[str, Any],
    samples_per_split: int,
) -> dict[str, Any]:
    chosen = {
        split: []
        for split in VALID_SPLITS
    }

    with manifest_path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(
            f
        ):
            split = (
                row[
                    "split"
                ]
            )

            if (
                split
                not in chosen
            ):
                continue

            if (
                len(
                    chosen[
                        split
                    ]
                )
                < samples_per_split
            ):
                chosen[
                    split
                ].append(
                    row
                )

            if all(
                len(
                    chosen[
                        s
                    ]
                )
                >= samples_per_split
                for s
                in VALID_SPLITS
            ):
                break

    cat_dim = len(
        spec[
            "active_categorical_features"
        ]
    )

    num_dim = len(
        spec[
            "active_numerical_features"
        ]
    )

    errors = []
    inspected = []

    required_arrays = {
        "x_cat",
        "x_num",
        "x_num_missing",
        "x_bin",
        "delta_t_log1p",
        "edge_app_local",
        "edge_remote_local",
        "sample_offsets",
        "sample_labels",
        "sample_event_counts",
        "sample_positive_event_counts",
        "sample_app_node_counts",
        "sample_remote_node_counts",
        "sample_window_start",
        "sample_chunk_index",
        "categorical_feature_names",
        "numerical_feature_names",
        "binary_feature_names",
    }

    cache = {}

    for split in (
        VALID_SPLITS
    ):
        for row in (
            chosen[
                split
            ]
        ):
            relative = (
                row[
                    "shard_file"
                ]
                .replace(
                    "\\",
                    "/",
                )
            )

            shard_path = (
                dataset_root
                / relative
            )

            if (
                relative
                not in cache
            ):
                if not shard_path.exists():
                    errors.append(
                        f"Missing shard: {relative}"
                    )
                    continue

                with np.load(
                    shard_path,
                    allow_pickle=False,
                ) as z:
                    cache[
                        relative
                    ] = {
                        key:
                            z[key]
                        for key
                        in z.files
                    }

            z = cache[
                relative
            ]

            missing_arrays = (
                required_arrays
                - set(
                    z.keys()
                )
            )

            if missing_arrays:
                errors.append(
                    f"{relative}: missing arrays "
                    f"{sorted(missing_arrays)}"
                )
                continue

            i = int(
                row[
                    "shard_sample_index"
                ]
            )

            offsets = (
                z[
                    "sample_offsets"
                ]
            )

            if not (
                0
                <= i
                < len(
                    z[
                        "sample_labels"
                    ]
                )
            ):
                errors.append(
                    f"{relative}: sample index "
                    f"{i} out of range"
                )
                continue

            start = int(
                offsets[
                    i
                ]
            )

            end = int(
                offsets[
                    i + 1
                ]
            )

            n = (
                end
                - start
            )

            expected_n = int(
                row[
                    "event_count"
                ]
            )

            if n != expected_n:
                errors.append(
                    f"{relative}[{i}]: "
                    f"offset event count "
                    f"{n} != manifest "
                    f"{expected_n}"
                )

            if (
                z[
                    "x_cat"
                ].shape[1]
                != cat_dim
            ):
                errors.append(
                    f"{relative}: "
                    "categorical dimension mismatch"
                )

            if (
                z[
                    "x_num"
                ].shape[1]
                != num_dim
            ):
                errors.append(
                    f"{relative}: "
                    "numerical dimension mismatch"
                )

            if (
                z[
                    "x_num_missing"
                ].shape
                != z[
                    "x_num"
                ].shape
            ):
                errors.append(
                    f"{relative}: "
                    "x_num_missing shape mismatch"
                )

            if (
                int(
                    z[
                        "sample_labels"
                    ][i]
                )
                != int(
                    row[
                        "label"
                    ]
                )
            ):
                errors.append(
                    f"{relative}[{i}]: "
                    "label mismatch"
                )

            if (
                int(
                    z[
                        "sample_positive_event_counts"
                    ][i]
                )
                != int(
                    row[
                        "positive_event_count"
                    ]
                )
            ):
                errors.append(
                    f"{relative}[{i}]: "
                    "positive_event_count mismatch"
                )

            if not (
                np.isfinite(
                    z[
                        "x_num"
                    ][
                        start:end
                    ]
                ).all()
                and np.isfinite(
                    z[
                        "delta_t_log1p"
                    ][
                        start:end
                    ]
                ).all()
            ):
                errors.append(
                    f"{relative}[{i}]: "
                    "non-finite numeric value"
                )

            inspected.append({
                "split":
                    split,
                "sample_id":
                    row[
                        "sample_id"
                    ],
                "shard":
                    relative,
                "index":
                    i,
                "events":
                    n,
                "label":
                    int(
                        row[
                            "label"
                        ]
                    ),
            })

    return {
        "samples_per_split":
            samples_per_split,
        "samples_inspected":
            len(
                inspected
            ),
        "inspected":
            inspected,
        "errors":
            errors[:100],
        "error_count":
            len(
                errors
            ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset-root",
        required=True,
    )

    parser.add_argument(
        "--output-root",
        required=True,
    )

    parser.add_argument(
        "--verify-sha",
        action="store_true",
    )

    parser.add_argument(
        "--smoke-samples-per-split",
        type=int,
        default=3,
    )

    # ---- STEP 10D: tham so hoa de dung lai cho split ngau nhien (mac dinh = LOSO cu)
    parser.add_argument(
        "--mode",
        choices=["loso", "random"],
        default="loso",
    )

    parser.add_argument(
        "--artifact-dir",
        default=None,
        help=(
            "Mac dinh: 02_artifacts/08d_loso_validation (loso) / "
            "10d_random_validation (random)."
        ),
    )

    parser.add_argument(
        "--fold-dir-template",
        default=None,
        help=(
            "Mac dinh: holdout_{fold} (loso) / {fold} (random)."
        ),
    )

    args = parser.parse_args()

    global RANDOM_NAMING, SPLIT_COL, SCRIPT_VERSION

    is_random = args.mode == "random"

    if is_random:
        RANDOM_NAMING = True
        SPLIT_COL = "assigned_split"
        SCRIPT_VERSION = "step10d-validate-random-split-v1.0"

    dataset_root = Path(
        args.dataset_root
    )

    output_root = Path(
        args.output_root
    )

    manifest_json_path = (
        dataset_root
        / "dataset_manifest.json"
    )

    build_config_path = (
        dataset_root
        / "build_config.json"
    )

    sample_manifest_path = (
        dataset_root
        / "split"
        / "network_sample_manifest.csv"
    )

    host_map_path = (
        dataset_root
        / "split"
        / "host_split_frozen.csv"
    )

    integrity_path = (
        dataset_root
        / "integrity"
        / "sha256sums.txt"
    )

    preprocess_spec_path = (
        dataset_root
        / "preprocessing"
        / "network_preprocess_spec.json"
    )

    required = [
        manifest_json_path,
        build_config_path,
        sample_manifest_path,
        host_map_path,
        integrity_path,
        preprocess_spec_path,
    ]

    missing = [
        str(path)
        for path
        in required
        if not path.exists()
    ]

    if missing:
        raise FileNotFoundError(
            "Missing required dataset files:\n"
            + "\n".join(
                missing
            )
        )

    manifest_json = load_json(
        manifest_json_path
    )

    build_config = load_json(
        build_config_path
    )

    spec = load_json(
        preprocess_spec_path
    )

    contract_key = (
        "split_contract"
        if is_random
        else "loso_contract"
    )

    heldout_scenario = (
        manifest_json[
            contract_key
        ][
            "heldout_scenario"
        ]
    )

    if is_random != (
        heldout_scenario is None
    ):
        raise RuntimeError(
            f"--mode {args.mode} khong khop dataset_manifest "
            f"(heldout_scenario={heldout_scenario!r})."
        )

    fold_label = (
        manifest_json[
            contract_key
        ]["fold_name"]
        if is_random
        else heldout_scenario
    )

    max_events = int(
        build_config[
            "max_events"
        ]
    )

    window_seconds = int(
        build_config[
            "window_seconds"
        ]
    )

    print("=" * 100)
    print(
        "STEP 10D — random-split validation"
        if is_random
        else "STEP 05F-D — LOSO fold validation"
    )
    print("=" * 100)
    print(
        f"[DATASET] {dataset_root}"
    )
    print(
        f"[HELDOUT] {heldout_scenario} (fold={fold_label})"
    )
    print(
        f"[WINDOW] "
        f"{build_config['window_minutes']} min"
    )
    print(
        f"[MAX EVENTS] {max_events}"
    )

    print()
    print(
        "[1/4] Validate frozen host mapping..."
    )

    (
        host_mapping,
        host_audit,
    ) = load_host_mapping(
        host_map_path
    )

    print(
        "[HOSTS] "
        + " | ".join(
            (
                f"{split}="
                f"{host_audit['host_counts'][split]:,}"
            )
            for split
            in VALID_SPLITS
        )
    )

    print()
    print(
        "[2/4] Validate full sample manifest..."
    )

    manifest_audit = (
        read_manifest(
            path=
                sample_manifest_path,
            host_mapping=
                host_mapping,
            heldout_scenario=
                heldout_scenario,
            max_events=
                max_events,
            window_seconds=
                window_seconds,
        )
    )

    for split in (
        VALID_SPLITS
    ):
        s = (
            manifest_audit[
                "split_stats"
            ][split]
        )

        print(
            f"[{split.upper()}] "
            f"samples={s['samples']:,} | "
            f"positive="
            f"{s['positive_samples']:,} | "
            f"events={s['events']:,} | "
            f"hosts_with_samples="
            f"{s['hosts_with_samples']:,} | "
            f"shards="
            f"{s['shards_referenced']:,}"
        )

    print()
    print(
        "[3/4] Compare with dataset_manifest..."
    )

    stats_compare = (
        compare_report_stats(
            observed=
                manifest_audit[
                    "split_stats"
                ],
            expected=
                manifest_json[
                    "split_stats"
                ],
        )
    )

    print(
        "[STATS MATCH] "
        + (
            "PASS"
            if stats_compare[
                "pass"
            ]
            else "FAIL"
        )
    )

    print()
    print(
        "[4/4] Integrity + NPZ smoke test..."
    )

    integrity_audit = (
        verify_integrity(
            dataset_root=
                dataset_root,
            integrity_path=
                integrity_path,
            verify_sha=
                args.verify_sha,
        )
    )

    print(
        f"[INTEGRITY] "
        f"entries="
        f"{integrity_audit['entries']:,} | "
        f"missing="
        f"{len(integrity_audit['missing_files'])} | "
        f"size_mismatch="
        f"{len(integrity_audit['size_mismatch'])} | "
        f"sha_mismatch="
        f"{len(integrity_audit['sha_mismatch'])}"
    )

    smoke = smoke_npz(
        dataset_root=
            dataset_root,
        manifest_path=
            sample_manifest_path,
        spec=
            spec,
        samples_per_split=
            args.smoke_samples_per_split,
    )

    print(
        f"[NPZ SMOKE] "
        f"inspected="
        f"{smoke['samples_inspected']} | "
        f"errors="
        f"{smoke['error_count']}"
    )

    host_overlap_count = sum(
        len(
            values
        )
        for values
        in host_audit[
            "host_intersections"
        ].values()
    )

    manifest_error_total = sum(
        manifest_audit[
            "error_counts"
        ].values()
    )

    gates = {
        "dataset_status_ready_for_validation":
            (
                manifest_json.get(
                    "status"
                )
                in {
                    None,
                    "READY_FOR_STEP05F_D_VALIDATION",
                }
            ),
        "heldout_scenario_matches_build_config":
            (
                heldout_scenario
                == build_config[
                    "heldout_scenario"
                ]
            ),
        "host_split_disjoint":
            (
                host_overlap_count
                == 0
            ),
        "manifest_no_logic_errors":
            (
                manifest_error_total
                == 0
            ),
        "manifest_stats_match_dataset_manifest":
            stats_compare[
                "pass"
            ],
        "integrity_no_missing_files":
            (
                len(
                    integrity_audit[
                        "missing_files"
                    ]
                )
                == 0
            ),
        "integrity_no_size_mismatch":
            (
                len(
                    integrity_audit[
                        "size_mismatch"
                    ]
                )
                == 0
            ),
        "integrity_sha_pass":
            (
                (
                    not args.verify_sha
                )
                or (
                    len(
                        integrity_audit[
                            "sha_mismatch"
                        ]
                    )
                    == 0
                )
            ),
        "npz_smoke_pass":
            (
                smoke[
                    "error_count"
                ]
                == 0
            ),
    }

    passed = all(
        gates.values()
    )

    report = {
        "generated_at":
            datetime.now(
                timezone.utc
            ).isoformat(),
        "script_version":
            SCRIPT_VERSION,
        "status":
            (
                "PASS"
                if passed
                else "FAIL"
            ),
        "dataset_root":
            str(
                dataset_root
            ),
        "heldout_scenario":
            heldout_scenario,
        **(
            {
                "fold_name":
                    fold_label,
                "experiment_mode":
                    "random",
            }
            if is_random
            else {}
        ),
        "build_config": {
            "window_minutes":
                build_config[
                    "window_minutes"
                ],
            "max_events":
                max_events,
            "script_version":
                build_config[
                    "script_version"
                ],
        },
        "host_audit":
            host_audit,
        "manifest_audit":
            manifest_audit,
        "stats_compare":
            stats_compare,
        "integrity_audit":
            integrity_audit,
        "npz_smoke":
            smoke,
        "gates":
            gates,
        "next_step":
            (
                "Build next seed or package for Kaggle."
                if is_random
                else "Build next LOSO fold or package for Kaggle."
                if passed
                else "Fix validation failures before continuing."
            ),
    }

    fold_dir_template = (
        args.fold_dir_template
        or (
            "{fold}"
            if is_random
            else "holdout_{fold}"
        )
    )

    artifact_dir = (
        (
            Path(
                args.artifact_dir
            )
            if args.artifact_dir
            else (
                output_root
                / "02_artifacts"
                / (
                    "10d_random_validation"
                    if is_random
                    else "08d_loso_validation"
                )
            )
        )
        / fold_dir_template.format(
            fold=fold_label
        )
    )

    artifact_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path = (
        artifact_dir
        / "validation_report.json"
    )

    dump_json(
        report_path,
        report,
    )

    md_path = (
        artifact_dir
        / (
            "STEP_10D_VALIDATION.md"
            if is_random
            else "STEP_08D_LOSO_VALIDATION.md"
        )
    )

    lines = [
        (
            "# STEP 05F-D — "
            f"Validation {fold_label}"
        ),
        "",
        "## Status",
        "",
        (
            "**PASS**"
            if passed
            else "**FAIL**"
        ),
        "",
        "## Core statistics",
        "",
    ]

    for split in (
        VALID_SPLITS
    ):
        s = (
            manifest_audit[
                "split_stats"
            ][split]
        )

        lines.append(
            f"- `{split}`: "
            f"samples={s['samples']:,}; "
            f"positive={s['positive_samples']:,}; "
            f"events={s['events']:,}; "
            f"hosts_with_samples="
            f"{s['hosts_with_samples']:,}; "
            f"shards="
            f"{s['shards_referenced']:,}."
        )

    lines.extend([
        "",
        "## Positive samples by UTC day",
        "",
        "```text",
    ])

    for split in (
        VALID_SPLITS
    ):
        lines.append(
            f"{split}: "
            + json.dumps(
                manifest_audit[
                    "day_positive_samples"
                ][split],
                ensure_ascii=False,
            )
        )

    lines.extend([
        "```",
        "",
        "## Gates",
        "",
    ])

    for key, value in (
        gates.items()
    ):
        lines.append(
            f"- `{key}`: "
            f"{'PASS' if value else 'FAIL'}"
        )

    lines.extend([
        "",
        "## Interpretation",
        "",
        (
            (
                f"`{fold_label}` là split ngẫu nhiên host-disjoint "
                "(không có scenario held-out); positive window theo "
                "scenario × split nằm trong validation_report.json "
                "(`positive_samples_by_scenario_split`)."
            )
            if is_random
            else (
                f"`{heldout_scenario}` là unseen-scenario TEST fold. "
                "TRAIN/VAL không được chứa positive sample của scenario này."
            )
        ),
        "",
        (
            "TEST positive count thường nhỏ hơn positive event count "
            "vì nhiều malicious events nằm chung một 15-minute/512-event chunk."
        ),
        "",
        "## Next",
        "",
        (
            (
                "Nếu PASS: dataset sẵn sàng upload Kaggle để train."
                if is_random
                else "Nếu PASS: build fold kế tiếp. "
                "Chưa train LOSO cho tới khi cả 3 folds đều PASS validation."
            )
        ),
        "",
    ])

    md_path.write_text(
        neutral_text(
            "\n".join(
                lines
            )
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 100)
    print(
        f"[STATUS] "
        f"{report['status']}"
    )
    print(
        f"[REPORT] {report_path}"
    )
    print(
        f"[MD] {md_path}"
    )

    if passed:
        print(
            "[NEXT] Scenario fold validated."
        )
    else:
        print(
            "[STOP] Fix validation failures "
            "before building/training further."
        )

    print("=" * 100)

    if not passed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
