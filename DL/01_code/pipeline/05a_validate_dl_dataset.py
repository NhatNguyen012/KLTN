from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np


SCRIPT_VERSION = "step05a-kaggle-dataset-validation-v1.0"


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
    return hashlib.sha256(
        canonical_bytes(obj)
    ).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def validate_integrity(
    dataset_root: Path,
    *,
    verify_sha: bool,
) -> dict[str, Any]:
    path = (
        dataset_root
        / "integrity"
        / "sha256sums.txt"
    )

    if not path.exists():
        raise FileNotFoundError(path)

    entries = []
    missing = []
    size_mismatch = []
    sha_mismatch = []

    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line:
                continue

            parts = line.split("  ")

            if len(parts) != 3:
                raise RuntimeError(
                    f"Invalid sha256sums line {lineno}: {line!r}"
                )

            digest, relative, size_text = parts

            file_path = dataset_root / relative

            entry = {
                "relative": relative,
                "expected_sha256": digest,
                "expected_size": int(size_text),
            }
            entries.append(entry)

            if not file_path.exists():
                missing.append(relative)
                continue

            actual_size = file_path.stat().st_size

            if actual_size != int(size_text):
                size_mismatch.append({
                    "file": relative,
                    "expected": int(size_text),
                    "actual": actual_size,
                })

            if verify_sha:
                actual_sha = sha256_file(file_path)

                if actual_sha != digest:
                    sha_mismatch.append({
                        "file": relative,
                        "expected": digest,
                        "actual": actual_sha,
                    })

    return {
        "entries": len(entries),
        "verify_sha": verify_sha,
        "missing_files": missing,
        "size_mismatch": size_mismatch,
        "sha_mismatch": sha_mismatch,
        "pass": (
            not missing
            and not size_mismatch
            and not sha_mismatch
        ),
    }


def validate_preprocessing(dataset_root: Path) -> dict[str, Any]:
    prep = dataset_root / "preprocessing"

    maps_path = prep / "network_category_maps.json"
    numeric_path = prep / "network_numeric_stats.json"
    spec_path = prep / "network_preprocess_spec.json"
    fp_path = prep / "network_preprocess_fingerprint.json"

    for path in (
        maps_path,
        numeric_path,
        spec_path,
        fp_path,
    ):
        if not path.exists():
            raise FileNotFoundError(path)

    maps = load_json(maps_path)
    numeric = load_json(numeric_path)
    spec = load_json(spec_path)
    fp = load_json(fp_path)

    checks = {
        "category_maps_sha256":
            sha256_file(maps_path),
        "numeric_stats_sha256":
            sha256_file(numeric_path),
        "preprocess_spec_sha256":
            sha256_file(spec_path),
    }

    mismatch = {}

    for key, actual in checks.items():
        expected = fp.get(key)

        if expected != actual:
            mismatch[key] = {
                "expected": expected,
                "actual": actual,
            }

    flags = {
        "fit_split_train":
            fp.get("fit_split") == "train",
        "val_not_used_for_fit":
            fp.get("val_used_for_fit") is False,
        "test_not_used_for_fit":
            fp.get("test_used_for_fit") is False,
        "unmatched_not_used_for_fit":
            fp.get(
                "unmatched_split_used_for_fit"
            ) is False,
    }

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

    return {
        "hash_mismatch": mismatch,
        "flags": flags,
        "active_categorical_features":
            active_cat,
        "active_numerical_features":
            active_num,
        "pass": (
            not mismatch
            and all(flags.values())
            and bool(active_cat)
            and bool(active_num)
        ),
        "_maps": maps,
        "_numeric": numeric,
        "_spec": spec,
        "_fingerprint": fp,
    }


def validate_manifest(
    dataset_root: Path,
    *,
    window_seconds: int,
    max_events: int,
) -> dict[str, Any]:
    path = (
        dataset_root
        / "split"
        / "network_sample_manifest.csv"
    )

    if not path.exists():
        raise FileNotFoundError(path)

    split_counts = Counter()
    positive_counts = Counter()
    event_counts = Counter()
    shard_counts: dict[str, set[str]] = defaultdict(set)

    host_split: dict[str, str] = {}
    host_leakage = []

    sample_ids = set()
    duplicate_sample_ids = []

    group_chunks: dict[
        tuple[str, str, int],
        list[int]
    ] = defaultdict(list)

    bad_rows = []
    misaligned_windows = 0
    event_count_overflow = 0

    with path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as f:
        reader = csv.DictReader(f)

        for row_no, row in enumerate(
            reader,
            start=2,
        ):
            split = row["split"]
            hostname = row["hostname"]
            sid = row["sample_id"]
            window_start = int(
                row["window_start_epoch"]
            )
            chunk_index = int(
                row["chunk_index"]
            )
            label = int(row["label"])
            event_count = int(
                row["event_count"]
            )

            if split not in {
                "train",
                "val",
                "test",
            }:
                bad_rows.append({
                    "row": row_no,
                    "reason": "invalid_split",
                    "value": split,
                })
                continue

            previous = host_split.get(hostname)

            if (
                previous is not None
                and previous != split
            ):
                host_leakage.append({
                    "hostname": hostname,
                    "split_a": previous,
                    "split_b": split,
                })

            host_split[hostname] = split

            if sid in sample_ids:
                duplicate_sample_ids.append(sid)

            sample_ids.add(sid)

            if window_start % window_seconds != 0:
                misaligned_windows += 1

            if not (
                1 <= event_count <= max_events
            ):
                event_count_overflow += 1

            if label not in {0, 1}:
                bad_rows.append({
                    "row": row_no,
                    "reason": "invalid_label",
                    "value": label,
                })

            split_counts[split] += 1
            positive_counts[split] += label
            event_counts[split] += event_count

            shard_counts[split].add(
                row["shard_file"]
            )

            group_chunks[
                (
                    split,
                    hostname,
                    window_start,
                )
            ].append(chunk_index)

    non_contiguous_chunks = []

    for key, chunks in group_chunks.items():
        unique = sorted(set(chunks))

        if len(unique) != len(chunks):
            non_contiguous_chunks.append({
                "key": key,
                "reason": "duplicate_chunk_index",
            })
            continue

        expected = list(range(
            0,
            max(unique) + 1,
        ))

        if unique != expected:
            non_contiguous_chunks.append({
                "key": key,
                "chunks": unique,
            })

    return {
        "samples_by_split": dict(split_counts),
        "positive_samples_by_split":
            dict(positive_counts),
        "events_by_split": dict(event_counts),
        "shards_by_split": {
            split: len(paths)
            for split, paths in shard_counts.items()
        },
        "distinct_hostnames": len(host_split),
        "hostname_split_leakage": host_leakage,
        "duplicate_sample_ids":
            duplicate_sample_ids[:100],
        "duplicate_sample_id_count":
            len(duplicate_sample_ids),
        "misaligned_windows":
            misaligned_windows,
        "event_count_overflow":
            event_count_overflow,
        "non_contiguous_chunk_groups":
            non_contiguous_chunks[:100],
        "non_contiguous_chunk_group_count":
            len(non_contiguous_chunks),
        "bad_rows": bad_rows[:100],
        "bad_row_count": len(bad_rows),
        "pass": (
            not host_leakage
            and not duplicate_sample_ids
            and misaligned_windows == 0
            and event_count_overflow == 0
            and not non_contiguous_chunks
            and not bad_rows
        ),
    }


def _names(arr: np.ndarray) -> list[str]:
    return [str(x) for x in arr.tolist()]


def validate_one_shard(
    path: Path,
    *,
    active_cat: list[str],
    active_num: list[str],
    max_events: int,
    category_maps: dict[str, Any],
) -> dict[str, Any]:
    required = {
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

    errors = []

    with np.load(
        path,
        allow_pickle=False,
    ) as z:
        missing_keys = sorted(
            required - set(z.files)
        )

        if missing_keys:
            return {
                "file": str(path),
                "pass": False,
                "errors": [
                    "missing keys: "
                    + ", ".join(missing_keys)
                ],
            }

        x_cat = z["x_cat"]
        x_num = z["x_num"]
        x_miss = z["x_num_missing"]
        x_bin = z["x_bin"]
        delta = z["delta_t_log1p"]
        app = z["edge_app_local"]
        remote = z["edge_remote_local"]

        offsets = z["sample_offsets"]
        labels = z["sample_labels"]
        counts = z["sample_event_counts"]
        positive_counts = (
            z["sample_positive_event_counts"]
        )
        app_counts = (
            z["sample_app_node_counts"]
        )
        remote_counts = (
            z["sample_remote_node_counts"]
        )

        cat_names = _names(
            z["categorical_feature_names"]
        )
        num_names = _names(
            z["numerical_feature_names"]
        )
        bin_names = _names(
            z["binary_feature_names"]
        )

        total_events = len(x_cat)
        sample_count = len(labels)

        if cat_names != active_cat:
            errors.append(
                f"categorical names mismatch: "
                f"{cat_names} != {active_cat}"
            )

        if num_names != active_num:
            errors.append(
                f"numerical names mismatch: "
                f"{num_names} != {active_num}"
            )

        if bin_names != [
            "has_missed_bytes"
        ]:
            errors.append(
                f"binary names mismatch: {bin_names}"
            )

        if x_cat.ndim != 2:
            errors.append(
                f"x_cat ndim={x_cat.ndim}"
            )
        elif x_cat.shape[1] != len(active_cat):
            errors.append(
                f"x_cat features={x_cat.shape[1]}"
            )

        if x_num.ndim != 2:
            errors.append(
                f"x_num ndim={x_num.ndim}"
            )
        elif x_num.shape[1] != len(active_num):
            errors.append(
                f"x_num features={x_num.shape[1]}"
            )

        if x_miss.shape != x_num.shape:
            errors.append(
                "x_num_missing shape mismatch"
            )

        if x_bin.ndim != 2 or x_bin.shape[1] != 1:
            errors.append(
                f"x_bin shape={x_bin.shape}"
            )

        for name, arr in (
            ("x_num", x_num),
            ("delta_t_log1p", delta),
        ):
            if not np.isfinite(arr).all():
                errors.append(
                    f"{name} contains NaN/inf"
                )

        for name, arr in (
            ("x_cat", x_cat),
            ("x_num", x_num),
            ("x_num_missing", x_miss),
            ("x_bin", x_bin),
            ("delta", delta),
            ("app_local", app),
            ("remote_local", remote),
        ):
            if len(arr) != total_events:
                errors.append(
                    f"{name} event length mismatch"
                )

        if len(offsets) != sample_count + 1:
            errors.append(
                "sample_offsets length mismatch"
            )

        if len(offsets) > 0:
            if int(offsets[0]) != 0:
                errors.append(
                    "offsets[0] != 0"
                )

            if int(offsets[-1]) != total_events:
                errors.append(
                    "offsets[-1] != total_events"
                )

            if np.any(
                offsets[1:] < offsets[:-1]
            ):
                errors.append(
                    "sample_offsets not monotonic"
                )

        expected_counts = np.diff(
            offsets.astype(np.int64)
        )

        if not np.array_equal(
            expected_counts,
            counts.astype(np.int64),
        ):
            errors.append(
                "sample_event_counts != diff(offsets)"
            )

        if np.any(counts < 1):
            errors.append(
                "zero-length sample"
            )

        if np.any(counts > max_events):
            errors.append(
                "sample > max_events"
            )

        if not np.isin(
            labels,
            np.asarray([0, 1]),
        ).all():
            errors.append(
                "invalid sample label"
            )

        expected_labels = (
            positive_counts > 0
        ).astype(labels.dtype)

        if not np.array_equal(
            labels,
            expected_labels,
        ):
            errors.append(
                "sample label != positive_event_count>0"
            )

        if np.any(
            positive_counts > counts
        ):
            errors.append(
                "positive_event_count > event_count"
            )

        # Validate categorical IDs against frozen TRAIN maps.
        if (
            x_cat.ndim == 2
            and x_cat.shape[1] == len(active_cat)
        ):
            for j, field in enumerate(active_cat):
                max_allowed = max(
                    int(v)
                    for v in category_maps[
                        "fields"
                    ][field]["mapping"].values()
                )

                if len(x_cat) and int(
                    x_cat[:, j].max()
                ) > max_allowed:
                    errors.append(
                        f"{field} category id out of range"
                    )

        # Local graph IDs must stay within sample-local node counts.
        if len(offsets) == sample_count + 1:
            for i in range(sample_count):
                start = int(offsets[i])
                end = int(offsets[i + 1])

                if end <= start:
                    continue

                ac = int(app_counts[i])
                rc = int(remote_counts[i])

                if ac < 1 or rc < 1:
                    errors.append(
                        f"sample {i}: zero graph nodes"
                    )
                    break

                if int(
                    app[start:end].max()
                ) >= ac:
                    errors.append(
                        f"sample {i}: app_local_id out of range"
                    )
                    break

                if int(
                    remote[start:end].max()
                ) >= rc:
                    errors.append(
                        f"sample {i}: remote_local_id out of range"
                    )
                    break

    return {
        "file": str(path),
        "pass": not errors,
        "errors": errors[:50],
    }


def validate_shards(
    dataset_root: Path,
    *,
    active_cat: list[str],
    active_num: list[str],
    max_events: int,
    category_maps: dict[str, Any],
    max_shards: int | None,
) -> dict[str, Any]:
    shards = sorted(
        (
            dataset_root
            / "shards"
        ).glob("*/*/*.npz")
    )

    if not shards:
        raise RuntimeError("No NPZ shards found.")

    if max_shards is not None:
        shards = shards[:max_shards]

    failures = []

    for i, path in enumerate(
        shards,
        start=1,
    ):
        print(
            f"[SHARD {i}/{len(shards)}] "
            f"{path.relative_to(dataset_root)}"
        )

        result = validate_one_shard(
            path,
            active_cat=active_cat,
            active_num=active_num,
            max_events=max_events,
            category_maps=category_maps,
        )

        if not result["pass"]:
            failures.append(result)

    return {
        "checked_shards": len(shards),
        "failed_shards": len(failures),
        "failures": failures[:50],
        "pass": not failures,
    }


def compare_manifest_to_dataset_manifest(
    manifest_stats: dict[str, Any],
    dataset_manifest: dict[str, Any],
) -> dict[str, Any]:
    mismatch = []

    split_stats = dataset_manifest[
        "split_stats"
    ]

    for split in ("train", "val", "test"):
        expected = split_stats[split]

        checks = {
            "samples": manifest_stats[
                "samples_by_split"
            ].get(split, 0),
            "positive_samples":
                manifest_stats[
                    "positive_samples_by_split"
                ].get(split, 0),
            "events": manifest_stats[
                "events_by_split"
            ].get(split, 0),
            "shards": manifest_stats[
                "shards_by_split"
            ].get(split, 0),
        }

        for key, actual in checks.items():
            expected_value = int(
                expected[key]
            )

            if int(actual) != expected_value:
                mismatch.append({
                    "split": split,
                    "field": key,
                    "expected": expected_value,
                    "actual": int(actual),
                })

    return {
        "mismatch": mismatch,
        "pass": not mismatch,
    }


def write_md(
    path: Path,
    report: dict[str, Any],
) -> None:
    ms = report["manifest"]
    dm = report["dataset_manifest"]

    lines = [
        "# STEP 05A — Kaggle Dataset validation + DataLoader contract",
        "",
        "## Trạng thái",
        "",
        (
            "**PASS — READY TO UPLOAD/TRAIN**"
            if report["status"] == "PASS"
            else "**FAILED — DO NOT TRAIN**"
        ),
        "",
        "## Mục tiêu",
        "",
        "Validate dataset sinh bởi STEP 04D trước khi upload/train trên Kaggle.",
        "",
        "## Checks",
        "",
        f"- Integrity files: **{'PASS' if report['integrity']['pass'] else 'FAIL'}**",
        f"- Frozen preprocessing: **{'PASS' if report['preprocessing']['pass'] else 'FAIL'}**",
        f"- Manifest/split leakage: **{'PASS' if ms['pass'] else 'FAIL'}**",
        f"- Manifest vs dataset_manifest: **{'PASS' if report['manifest_vs_dataset_manifest']['pass'] else 'FAIL'}**",
        f"- NPZ shard structure/content: **{'PASS' if report['shards']['pass'] else 'FAIL'}**",
        "",
        "## Split summary",
        "",
    ]

    for split in ("train", "val", "test"):
        samples = ms[
            "samples_by_split"
        ].get(split, 0)
        positive = ms[
            "positive_samples_by_split"
        ].get(split, 0)
        events = ms[
            "events_by_split"
        ].get(split, 0)

        lines.extend([
            f"### {split.upper()}",
            "",
            f"- Samples: **{samples:,}**",
            f"- Positive: **{positive:,}**",
            f"- Events: **{events:,}**",
            "",
        ])

    train = dm["split_stats"]["train"]

    lines.extend([
        "## Training imbalance",
        "",
        f"- TRAIN sample-level `pos_weight`: **{train['pos_weight_neg_over_pos']}**",
        "",
        "Baseline recommendation:",
        "",
        "```text",
        "BCEWithLogitsLoss(pos_weight=TRAIN_NEG/TRAIN_POS)",
        "```",
        "",
        "Không kết hợp `pos_weight` lớn với aggressive oversampling trong baseline đầu tiên.",
        "",
        "## DataLoader contract",
        "",
        "Sequence batch:",
        "",
        "```text",
        "x_cat          [B,T,C]",
        "x_num          [B,T,N]",
        "x_num_missing  [B,T,N]",
        "x_bin          [B,T,1]",
        "delta_t_log1p  [B,T,1]",
        "attention_mask [B,T]",
        "labels         [B]",
        "```",
        "",
        "Padding chỉ thực hiện trong batch.",
        "",
        "Graph transport format:",
        "",
        "```text",
        "APP nodes + REMOTE_ENDPOINT nodes",
        "edge_index từ app_local_id -> remote_local_id",
        "reverse edges có thể thêm khi train GNN",
        "```",
        "",
        "## Leakage",
        "",
        f"- Distinct hostnames: **{ms['distinct_hostnames']:,}**",
        f"- Hostnames xuất hiện ở nhiều split: **{len(ms['hostname_split_leakage']):,}**",
        f"- Duplicate sample IDs: **{ms['duplicate_sample_id_count']:,}**",
        "",
        "## Next step",
        "",
        (
            "Upload private Kaggle Dataset và chạy DataLoader smoke test trên Kaggle, sau đó train BiLSTM baseline."
            if report["status"] == "PASS"
            else "Sửa lỗi validation trước khi upload/train."
        ),
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


def main():
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
        help=(
            "Hash toàn bộ files trong integrity manifest. "
            "Chậm hơn nhưng nên chạy một lần trước upload."
        ),
    )
    parser.add_argument(
        "--max-shards",
        type=int,
        default=None,
        help=(
            "Debug only: validate only first N shards. "
            "Omit for final full validation."
        ),
    )

    args = parser.parse_args()

    dataset_root = Path(
        args.dataset_root
    )
    output_root = Path(
        args.output_root
    )

    if not dataset_root.exists():
        raise FileNotFoundError(
            dataset_root
        )

    build_config_path = (
        dataset_root
        / "build_config.json"
    )
    dataset_manifest_path = (
        dataset_root
        / "dataset_manifest.json"
    )

    for path in (
        build_config_path,
        dataset_manifest_path,
    ):
        if not path.exists():
            raise FileNotFoundError(path)

    build_config = load_json(
        build_config_path
    )
    dataset_manifest = load_json(
        dataset_manifest_path
    )

    if (
        dataset_manifest[
            "build_config_sha256"
        ]
        != sha256_obj(build_config)
    ):
        raise RuntimeError(
            "build_config SHA mismatch."
        )

    window_minutes = int(
        build_config["window_minutes"]
    )
    window_seconds = int(
        build_config["window_seconds"]
    )
    max_events = int(
        build_config["max_events"]
    )

    artifact_dir = (
        output_root
        / "02_artifacts"
        / "05_kaggle_validation"
    )
    artifact_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 96)
    print("STEP 05A — Kaggle Dataset validation")
    print("=" * 96)
    print(f"[DATASET] {dataset_root}")
    print(
        f"[WINDOW] {window_minutes} min | "
        f"MAX_EVENTS={max_events}"
    )
    print(
        f"[SHA] {'FULL' if args.verify_sha else 'size/existence only'}"
    )
    print()

    print("[1/5] Validate integrity manifest...")
    integrity = validate_integrity(
        dataset_root,
        verify_sha=args.verify_sha,
    )

    print("[2/5] Validate frozen preprocessing...")
    preprocessing = validate_preprocessing(
        dataset_root
    )

    print("[3/5] Validate sample manifest/leakage...")
    manifest = validate_manifest(
        dataset_root,
        window_seconds=window_seconds,
        max_events=max_events,
    )

    print("[4/5] Compare manifest statistics...")
    manifest_vs_dataset_manifest = (
        compare_manifest_to_dataset_manifest(
            manifest,
            dataset_manifest,
        )
    )

    print("[5/5] Validate NPZ shards...")
    shards = validate_shards(
        dataset_root,
        active_cat=preprocessing[
            "active_categorical_features"
        ],
        active_num=preprocessing[
            "active_numerical_features"
        ],
        max_events=max_events,
        category_maps=preprocessing[
            "_maps"
        ],
        max_shards=args.max_shards,
    )

    pass_flags = {
        "integrity": integrity["pass"],
        "preprocessing":
            preprocessing["pass"],
        "manifest": manifest["pass"],
        "manifest_vs_dataset_manifest":
            manifest_vs_dataset_manifest[
                "pass"
            ],
        "shards": shards["pass"],
    }

    status = (
        "PASS"
        if all(pass_flags.values())
        else "FAIL"
    )

    # Remove internal objects before JSON.
    preprocessing_public = {
        key: value
        for key, value
        in preprocessing.items()
        if not key.startswith("_")
    }

    report = {
        "generated_at": now_iso(),
        "script_version":
            SCRIPT_VERSION,
        "status": status,
        "dataset_root":
            str(dataset_root),
        "build_config":
            build_config,
        "pass_flags":
            pass_flags,
        "integrity":
            integrity,
        "preprocessing":
            preprocessing_public,
        "manifest":
            manifest,
        "manifest_vs_dataset_manifest":
            manifest_vs_dataset_manifest,
        "shards":
            shards,
        "dataset_manifest":
            dataset_manifest,
        "training_baseline": {
            "loss":
                "BCEWithLogitsLoss",
            "train_pos_weight":
                dataset_manifest[
                    "split_stats"
                ]["train"][
                    "pos_weight_neg_over_pos"
                ],
            "do_not_double_compensate":
                (
                    "Do not combine large pos_weight "
                    "with aggressive positive oversampling "
                    "in the first baseline."
                ),
        },
    }

    report_path = (
        artifact_dir
        / "step05a_validation_report.json"
    )
    md_path = (
        artifact_dir
        / "STEP_05_KAGGLE_VALIDATION.md"
    )

    dump_json(
        report_path,
        report,
    )
    write_md(
        md_path,
        report,
    )

    print()
    print("=" * 96)
    print(f"[STATUS] {status}")
    print(
        "[SAMPLES] "
        f"train={manifest['samples_by_split'].get('train', 0):,} | "
        f"val={manifest['samples_by_split'].get('val', 0):,} | "
        f"test={manifest['samples_by_split'].get('test', 0):,}"
    )
    print(
        "[POSITIVE] "
        f"train={manifest['positive_samples_by_split'].get('train', 0):,} | "
        f"val={manifest['positive_samples_by_split'].get('val', 0):,} | "
        f"test={manifest['positive_samples_by_split'].get('test', 0):,}"
    )
    print(
        f"[HOST LEAKAGE] "
        f"{len(manifest['hostname_split_leakage']):,}"
    )
    print(
        f"[SHARDS] checked={shards['checked_shards']:,} | "
        f"failed={shards['failed_shards']:,}"
    )
    print(f"[REPORT] {report_path}")
    print(f"[MD] {md_path}")
    print("=" * 96)

    if status != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
