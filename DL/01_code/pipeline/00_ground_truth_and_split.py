from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


# ============================================================================
# STEP 02 v1.1 — Ground-truth inspection + leakage-safe host split
# ----------------------------------------------------------------------------
# Changes from v1.0:
#   1) Positive hosts are stratified PER SCENARIO, not only positive/nonpositive.
#   2) Mandatory "positive scenario coverage" checks are added.
#   3) Scenarios with >=3 positive hosts must appear in TRAIN, VAL, TEST.
#   4) Scenarios with exactly 2 positive hosts use TRAIN + TEST by policy.
#   5) Scenarios with exactly 1 positive host use TRAIN only and are reported
#      as intrinsically impossible to evaluate across multiple splits.
#   6) Freeze is blocked unless scenario-coverage policy passes.
#
# Leakage boundary:
#   - Split unit = hostname.
#   - All files for the same hostname remain in ONE split.
#   - Final ~12k Host vocabulary is later fitted ONLY from split=train.
# ============================================================================


SCRIPT_VERSION = "step02-v1.1"

RAW_SOURCE_MAP = {
    "host_benign": "host-begnin",   # physical folder really contains this typo
    "host_malicious": "host-malicious",
}

DEFAULT_GT_FOLDER = "a_new_hope_for_darpa_optc"

RAW_FILE_RE = re.compile(
    r"ecar-(?P<date>\d{4}-\d{2}-\d{2})-(?P<host>sysclient\d+)\.json\.gz$",
    re.IGNORECASE,
)

HOST_RE = re.compile(r"(sysclient\d+)", re.IGNORECASE)
SCENARIO_RE = re.compile(
    r"(?:^|[_-])sc(?:enario)?[_-]?(\d+)(?:[_-]|$)",
    re.IGNORECASE,
)

POSITIVE_VALUES = {
    "1", "true", "yes", "malicious", "attack", "apt", "positive",
}

NEGATIVE_VALUES = {
    "0", "false", "no", "benign", "negative",
}

SPLITS = ("train", "val", "test")


# ============================================================================
# Generic helpers
# ============================================================================

def norm(value: Any) -> str:
    return "" if value is None else str(value).strip()


def canonical_hostname(value: Any) -> str:
    text = norm(value).lower()
    match = HOST_RE.search(text)

    if match:
        return match.group(1).lower()

    return text.split(".", 1)[0]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)

    return h.hexdigest()


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {key: row.get(key, "") for key in fieldnames}
            )


# ============================================================================
# Raw host inventory
# ============================================================================

def parse_raw_file_metadata(
    path: Path,
    input_root: Path,
    logical_source: str,
) -> dict[str, str]:

    match = RAW_FILE_RE.search(path.name)

    if match:
        date = match.group("date")
        hostname = canonical_hostname(match.group("host"))
    else:
        date_match = re.search(
            r"\d{4}-\d{2}-\d{2}",
            str(path),
        )
        host_match = HOST_RE.search(path.name)

        if not date_match or not host_match:
            raise ValueError(
                f"Cannot parse raw host metadata from path: {path}"
            )

        date = date_match.group(0)
        hostname = canonical_hostname(
            host_match.group(1)
        )

    return {
        "raw_source": logical_source,
        "absolute_path": str(path),
        "relative_path": str(
            path.relative_to(input_root)
        ),
        "date": date,
        "hostname": hostname,
        "group_key": hostname,
    }


def list_raw_host_files(
    input_root: Path,
) -> list[dict[str, str]]:

    rows: list[dict[str, str]] = []

    for logical_source, physical_name in RAW_SOURCE_MAP.items():

        source_root = input_root / physical_name

        if not source_root.exists():
            raise FileNotFoundError(
                f"Required raw source folder not found: {source_root}"
            )

        for root, dirs, files in os.walk(source_root):

            dirs.sort()
            files.sort()

            for filename in files:

                if not filename.lower().endswith(".json.gz"):
                    continue

                path = Path(root) / filename

                try:
                    row = parse_raw_file_metadata(
                        path,
                        input_root,
                        logical_source,
                    )
                except ValueError as exc:
                    print(f"[WARN] {exc}")
                    continue

                rows.append(row)

    return sorted(
        rows,
        key=lambda r: (
            r["hostname"],
            r["date"],
            r["relative_path"],
        ),
    )


# ============================================================================
# Ground-truth discovery / profiling
# ============================================================================

def classify_gt_file(path: Path) -> dict[str, Any]:

    name = path.name.lower()

    host_match = HOST_RE.search(name)
    scenario_match = SCENARIO_RE.search(name)

    return {
        "path": str(path),
        "filename": path.name,
        "is_ground_truth_named": "ground_truth" in name,
        "is_corrected": "corrected" in name,
        "is_all_events": (
            "all_evts" in name
            or "all_events" in name
            or "allevts" in name
        ),
        "hostname_from_name": (
            canonical_hostname(
                host_match.group(1)
            )
            if host_match
            else ""
        ),
        "scenario_from_name": (
            f"scenario_{scenario_match.group(1)}"
            if scenario_match
            else ""
        ),
        "compressed_size_bytes": path.stat().st_size,
    }


def first_nonempty_line_gz(path: Path) -> str:

    with gzip.open(
        path,
        "rt",
        encoding="utf-8",
        errors="replace",
    ) as handle:

        for line in handle:
            stripped = line.strip()

            if stripped:
                return stripped

    return ""


def flatten_loaded_json(
    data: Any,
) -> Iterable[dict[str, Any]]:

    if isinstance(data, list):

        for item in data:
            if isinstance(item, dict):
                yield item

        return

    if isinstance(data, dict):

        eventish_keys = {
            "timestamp",
            "id",
            "action",
            "object",
            "actorID",
            "objectID",
            "hostname",
            "label",
        }

        if eventish_keys.intersection(
            data.keys()
        ):
            yield data
            return

        for key in (
            "events",
            "records",
            "data",
            "items",
        ):
            value = data.get(key)

            if isinstance(value, list):

                for item in value:
                    if isinstance(item, dict):
                        yield item

                return

        yielded = False

        for value in data.values():

            if isinstance(value, dict):
                yield value
                yielded = True

            elif isinstance(value, list):

                for item in value:
                    if isinstance(item, dict):
                        yield item
                        yielded = True

        if yielded:
            return


def iter_json_gz_records(
    path: Path,
) -> Iterable[dict[str, Any]]:

    first = first_nonempty_line_gz(path)

    if not first:
        return

    if first.startswith("{"):

        jsonl_ok = True
        produced = 0

        with gzip.open(
            path,
            "rt",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            for line in handle:

                stripped = line.strip()

                if not stripped:
                    continue

                try:
                    item = json.loads(stripped)
                except json.JSONDecodeError:
                    jsonl_ok = False
                    break

                if isinstance(item, dict):
                    produced += 1
                    yield item

        if jsonl_ok:
            return

        if produced == 0:

            with gzip.open(
                path,
                "rt",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                data = json.load(handle)

            yield from flatten_loaded_json(data)
            return

        raise ValueError(
            "Mixed/unsupported JSON structure "
            f"after {produced} JSONL records: {path}"
        )

    if first.startswith("["):

        with gzip.open(
            path,
            "rt",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            data = json.load(handle)

        yield from flatten_loaded_json(data)
        return

    raise ValueError(
        f"Unsupported JSON structure in ground-truth file: {path}"
    )


def extract_record_date(
    record: dict[str, Any],
) -> str:

    for key in (
        "timestamp",
        "time",
        "ts",
        "datetime",
    ):

        value = norm(record.get(key))

        if not value:
            continue

        match = re.search(
            r"\d{4}-\d{2}-\d{2}",
            value,
        )

        if match:
            return match.group(0)

    return ""


def extract_record_hostname(
    record: dict[str, Any],
) -> str:

    for key in (
        "hostname",
        "host",
        "computer",
        "computer_name",
    ):

        value = norm(record.get(key))

        if value:
            return canonical_hostname(value)

    return ""


def explicit_label(
    record: dict[str, Any],
) -> tuple[bool, bool | None]:

    for key in (
        "label",
        "is_malicious",
        "malicious",
        "ground_truth",
        "class",
    ):

        if key not in record:
            continue

        raw = norm(
            record.get(key)
        ).lower()

        if raw in POSITIVE_VALUES:
            return True, True

        if raw in NEGATIVE_VALUES:
            return True, False

        return True, None

    return False, None


def profile_ground_truth_file(
    path: Path,
    meta: dict[str, Any],
) -> dict[str, Any]:

    records = 0

    explicit_label_records = 0
    explicit_positive = 0
    explicit_negative = 0
    unknown_explicit_labels = 0
    implicit_positive = 0

    dates = Counter()
    hosts = Counter()
    top_level_fields = Counter()
    join_key_presence = Counter()

    join_keys_to_check = (
        "id",
        "event_id",
        "eventID",
        "actorID",
        "objectID",
        "timestamp",
        "hostname",
    )

    for record in iter_json_gz_records(path):

        records += 1
        top_level_fields.update(
            record.keys()
        )

        host = extract_record_hostname(
            record
        )

        date = extract_record_date(
            record
        )

        if host:
            hosts[host] += 1

        if date:
            dates[date] += 1

        for key in join_keys_to_check:

            if (
                key in record
                and record.get(key)
                not in (None, "")
            ):
                join_key_presence[key] += 1

        present, positive = explicit_label(
            record
        )

        if present:

            explicit_label_records += 1

            if positive is True:
                explicit_positive += 1

            elif positive is False:
                explicit_negative += 1

            else:
                unknown_explicit_labels += 1

        else:
            # Membership in a corrected ground_truth_*_evts_* file is
            # treated as positive for SPLIT STRATIFICATION only.
            implicit_positive += 1

    filename_host = meta.get(
        "hostname_from_name",
        "",
    )

    observed_hosts = set(hosts)

    if filename_host:
        observed_hosts.add(filename_host)

    positive_event_count = (
        explicit_positive
        + implicit_positive
    )

    return {
        **meta,
        "records": records,
        "explicit_label_records":
            explicit_label_records,
        "explicit_positive_records":
            explicit_positive,
        "explicit_negative_records":
            explicit_negative,
        "unknown_explicit_labels":
            unknown_explicit_labels,
        "implicit_positive_records_by_gt_membership":
            implicit_positive,
        "positive_event_count_for_stratification":
            positive_event_count,
        "observed_hosts":
            sorted(observed_hosts),
        "observed_dates":
            dict(dates.most_common()),
        "top_level_fields":
            dict(top_level_fields.most_common()),
        "join_key_presence":
            dict(join_key_presence.most_common()),
    }


def discover_ground_truth_files(
    gt_root: Path,
    *,
    allow_original_fallback: bool,
) -> tuple[
    list[Path],
    list[dict[str, Any]],
    str,
]:

    if not gt_root.exists():
        raise FileNotFoundError(
            f"Ground-truth folder not found: {gt_root}"
        )

    all_meta: list[
        dict[str, Any]
    ] = []

    for root, dirs, files in os.walk(gt_root):

        dirs.sort()
        files.sort()

        for filename in files:

            if not filename.lower().endswith(
                ".json.gz"
            ):
                continue

            path = Path(root) / filename

            meta = classify_gt_file(path)

            if meta[
                "is_ground_truth_named"
            ]:
                all_meta.append(meta)

    corrected_per_host = [
        Path(item["path"])
        for item in all_meta
        if item["is_corrected"]
        and not item["is_all_events"]
        and item["hostname_from_name"]
    ]

    if corrected_per_host:
        return (
            sorted(corrected_per_host),
            all_meta,
            "corrected_per_host",
        )

    corrected_non_all = [
        Path(item["path"])
        for item in all_meta
        if item["is_corrected"]
        and not item["is_all_events"]
    ]

    if corrected_non_all:
        return (
            sorted(corrected_non_all),
            all_meta,
            "corrected_non_all_events",
        )

    if allow_original_fallback:

        original_per_host = [
            Path(item["path"])
            for item in all_meta
            if not item["is_corrected"]
            and not item["is_all_events"]
            and item["hostname_from_name"]
        ]

        if original_per_host:
            return (
                sorted(original_per_host),
                all_meta,
                "original_per_host_fallback",
            )

    raise RuntimeError(
        "No suitable corrected ground-truth files were found. "
        "The script will not silently fall back to original labels. "
        "Use --allow-original-ground-truth only if intentionally accepted."
    )


# ============================================================================
# Deterministic split allocation
# ============================================================================

def deterministic_order(
    items: Iterable[str],
    seed: str,
    stratum: str,
) -> list[str]:

    def key(item: str) -> str:
        return sha256_text(
            f"{seed}|{stratum}|{item}"
        )

    return sorted(
        items,
        key=key,
    )


def allocate_counts(
    n: int,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[int, int, int]:
    """
    Standard largest-remainder allocation.

    Tie priority is VAL -> TEST -> TRAIN.
    This preserves the v1.0-ish 20/5/4 positive-host balance for the
    observed OpTC scenario sizes while still enforcing scenario coverage.
    """

    if n <= 0:
        return 0, 0, 0

    ratios = [
        train_ratio,
        val_ratio,
        test_ratio,
    ]

    raw = [
        n * x
        for x in ratios
    ]

    counts = [
        math.floor(x)
        for x in raw
    ]

    remainder = (
        n
        - sum(counts)
    )

    tie_priority = {
        1: 0,   # val
        2: 1,   # test
        0: 2,   # train
    }

    order = sorted(
        range(3),
        key=lambda i: (
            -(raw[i] - counts[i]),
            tie_priority[i],
        ),
    )

    for index in order[:remainder]:
        counts[index] += 1

    return (
        counts[0],
        counts[1],
        counts[2],
    )


def scenario_positive_counts(
    n: int,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[
    tuple[int, int, int],
    str,
]:
    """
    Coverage policy:

      n >= 3:
        ratio-based allocation, but every split MUST have >=1.

      n == 2:
        exactly 1 TRAIN + 1 TEST.
        VAL coverage is mathematically impossible and therefore is not required.

      n == 1:
        TRAIN only.
        Cross-split evaluation is impossible and is explicitly reported.

    This is a split-coverage policy, not a model-performance choice.
    """

    if n <= 0:
        return (
            (0, 0, 0),
            "no_positive_hosts",
        )

    if n == 1:
        return (
            (1, 0, 0),
            "single_host_train_only",
        )

    if n == 2:
        return (
            (1, 0, 1),
            "two_hosts_train_test",
        )

    counts = list(
        allocate_counts(
            n,
            train_ratio,
            val_ratio,
            test_ratio,
        )
    )

    # With n >= 3, force one host into every split if a rounding edge case
    # produced zero in any split.
    for target in (
        0,
        1,
        2,
    ):

        if counts[target] > 0:
            continue

        donor = max(
            range(3),
            key=lambda i: counts[i],
        )

        if counts[donor] <= 1:
            raise RuntimeError(
                "Cannot enforce scenario coverage "
                f"for n={n}, counts={counts}"
            )

        counts[donor] -= 1
        counts[target] += 1

    return (
        (
            counts[0],
            counts[1],
            counts[2],
        ),
        "three_way_required",
    )


def assign_positive_scenarios(
    host_to_scenarios: dict[
        str,
        set[str],
    ],
    *,
    seed: str,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[
    dict[str, str],
    dict[str, Any],
]:
    """
    Assign GT-positive host groups per scenario.

    v1.1 assumes a host belongs to one positive scenario. If the corrected GT
    associates one host with multiple scenarios, we stop instead of silently
    making an ambiguous split decision.
    """

    multi_scenario_hosts = {
        host: sorted(scenarios)
        for host, scenarios
        in host_to_scenarios.items()
        if len(scenarios) != 1
    }

    if multi_scenario_hosts:
        raise RuntimeError(
            "Some positive hosts map to zero/multiple scenarios; "
            "manual policy is required before splitting: "
            + json.dumps(
                multi_scenario_hosts,
                ensure_ascii=False,
            )
        )

    scenario_to_hosts: dict[
        str,
        list[str],
    ] = defaultdict(list)

    for host, scenarios in host_to_scenarios.items():

        scenario = next(
            iter(scenarios)
        )

        scenario_to_hosts[
            scenario
        ].append(host)

    assignment: dict[
        str,
        str,
    ] = {}

    scenario_summary: dict[
        str,
        Any,
    ] = {}

    for scenario in sorted(
        scenario_to_hosts
    ):

        hosts = sorted(
            scenario_to_hosts[
                scenario
            ]
        )

        ordered = deterministic_order(
            hosts,
            seed,
            f"positive:{scenario}",
        )

        (
            train_n,
            val_n,
            test_n,
        ), policy = scenario_positive_counts(
            len(ordered),
            train_ratio,
            val_ratio,
            test_ratio,
        )

        cursor = 0

        scenario_assignment = {
            "train": ordered[
                cursor:
                cursor + train_n
            ]
        }
        cursor += train_n

        scenario_assignment[
            "val"
        ] = ordered[
            cursor:
            cursor + val_n
        ]
        cursor += val_n

        scenario_assignment[
            "test"
        ] = ordered[
            cursor:
            cursor + test_n
        ]

        for split in SPLITS:

            for host in scenario_assignment[
                split
            ]:

                if host in assignment:
                    raise RuntimeError(
                        f"Positive host assigned twice: {host}"
                    )

                assignment[
                    host
                ] = split

        scenario_summary[
            scenario
        ] = {
            "positive_host_count":
                len(ordered),
            "coverage_policy":
                policy,
            "assigned_counts": {
                split: len(
                    scenario_assignment[
                        split
                    ]
                )
                for split in SPLITS
            },
            "assigned_hosts":
                scenario_assignment,
        }

    return (
        assignment,
        scenario_summary,
    )


def global_target_host_counts(
    total_hosts: int,
    *,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> dict[str, int]:

    train_n, val_n, test_n = allocate_counts(
        total_hosts,
        train_ratio,
        val_ratio,
        test_ratio,
    )

    return {
        "train": train_n,
        "val": val_n,
        "test": test_n,
    }


def assign_negative_hosts_to_fill_targets(
    negative_hosts: list[str],
    positive_assignment: dict[str, str],
    *,
    seed: str,
    target_counts: dict[str, int],
) -> dict[str, str]:
    """
    Fill remaining global host quotas with non-positive host groups.

    This keeps the overall split close to the requested 70/15/15 while
    preserving the scenario-specific positive allocation.
    """

    positive_counts = Counter(
        positive_assignment.values()
    )

    needed = {
        split: max(
            0,
            target_counts[split]
            - positive_counts[split],
        )
        for split in SPLITS
    }

    total_needed = sum(
        needed.values()
    )

    if total_needed != len(
        negative_hosts
    ):
        # This can happen if a very small dataset has more positive hosts in a
        # split than the global target. Rebalance remaining negatives without
        # touching positive-scenario assignments.
        base = {
            split: needed[split]
            for split in SPLITS
        }

        delta = (
            len(negative_hosts)
            - total_needed
        )

        if delta > 0:
            # Add residual negative groups to the split with the largest
            # remaining proportional capacity; deterministic fixed priority.
            priority = (
                "train",
                "val",
                "test",
            )

            for i in range(delta):
                split = priority[
                    i % len(priority)
                ]
                base[split] += 1

        elif delta < 0:
            # Remove excess from largest negative allocation.
            for _ in range(
                -delta
            ):
                split = max(
                    SPLITS,
                    key=lambda s: base[s],
                )

                if base[split] <= 0:
                    raise RuntimeError(
                        "Unable to rebalance negative host quotas."
                    )

                base[split] -= 1

        needed = base

    ordered = deterministic_order(
        negative_hosts,
        seed,
        "negative_hosts",
    )

    assignment: dict[
        str,
        str,
    ] = {}

    cursor = 0

    for split in SPLITS:

        count = needed[
            split
        ]

        for host in ordered[
            cursor:
            cursor + count
        ]:
            assignment[
                host
            ] = split

        cursor += count

    if len(assignment) != len(
        negative_hosts
    ):
        raise RuntimeError(
            "Negative-host assignment size mismatch."
        )

    return assignment


def build_split_assignment(
    raw_rows: list[dict[str, str]],
    host_to_scenarios: dict[
        str,
        set[str],
    ],
    *,
    seed: str,
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[
    dict[str, str],
    dict[str, Any],
]:
    """
    1) assign all positive hosts per scenario,
    2) fill the requested global split sizes with all remaining hosts.
    """

    all_hosts = sorted({
        row["hostname"]
        for row in raw_rows
    })

    positive_hosts = set(
        host_to_scenarios
    ).intersection(
        all_hosts
    )

    filtered_host_to_scenarios = {
        host: set(
            host_to_scenarios[
                host
            ]
        )
        for host in positive_hosts
    }

    (
        positive_assignment,
        scenario_summary,
    ) = assign_positive_scenarios(
        filtered_host_to_scenarios,
        seed=seed,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
    )

    negative_hosts = sorted(
        set(all_hosts)
        - set(
            positive_assignment
        )
    )

    target_counts = global_target_host_counts(
        len(all_hosts),
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
    )

    negative_assignment = assign_negative_hosts_to_fill_targets(
        negative_hosts,
        positive_assignment,
        seed=seed,
        target_counts=target_counts,
    )

    assignment = {
        **positive_assignment,
        **negative_assignment,
    }

    if set(assignment) != set(
        all_hosts
    ):
        raise RuntimeError(
            "Final split assignment does not cover exactly all raw host groups."
        )

    return (
        assignment,
        {
            "scenario_positive_assignment":
                scenario_summary,
            "global_target_host_counts":
                target_counts,
        },
    )


# ============================================================================
# Validation / freeze checks
# ============================================================================

def scenario_coverage_report(
    scenario_to_hosts: dict[
        str,
        set[str],
    ],
    assignment: dict[str, str],
) -> dict[str, Any]:

    report: dict[
        str,
        Any,
    ] = {}

    overall_pass = True

    for scenario in sorted(
        scenario_to_hosts
    ):

        hosts = sorted(
            scenario_to_hosts[
                scenario
            ]
        )

        counts = Counter(
            assignment[
                host
            ]
            for host in hosts
            if host in assignment
        )

        n = len(hosts)

        if n >= 3:

            required = {
                "train": True,
                "val": True,
                "test": True,
            }

            policy = (
                "require_train_val_test"
            )

        elif n == 2:

            required = {
                "train": True,
                "val": False,
                "test": True,
            }

            policy = (
                "require_train_and_test;"
                "val_not_possible"
            )

        elif n == 1:

            required = {
                "train": True,
                "val": False,
                "test": False,
            }

            policy = (
                "train_only;"
                "cross_split_evaluation_not_possible"
            )

        else:

            required = {
                "train": False,
                "val": False,
                "test": False,
            }

            policy = (
                "no_positive_hosts"
            )

        split_pass = {
            split: (
                counts[
                    split
                ] >= 1
                if required[
                    split
                ]
                else True
            )
            for split in SPLITS
        }

        passed = all(
            split_pass.values()
        )

        overall_pass = (
            overall_pass
            and passed
        )

        report[
            scenario
        ] = {
            "positive_host_count":
                n,
            "counts": {
                split: counts[
                    split
                ]
                for split in SPLITS
            },
            "hosts": {
                split: sorted(
                    host
                    for host in hosts
                    if assignment.get(
                        host
                    ) == split
                )
                for split in SPLITS
            },
            "coverage_policy":
                policy,
            "required_presence":
                required,
            "presence_check":
                split_pass,
            "pass":
                passed,
        }

    return {
        "overall_pass":
            overall_pass,
        "scenarios":
            report,
    }


def freeze_checks(
    manifest_rows: list[
        dict[str, Any]
    ],
    positive_hosts: set[str],
    gt_profiles: list[
        dict[str, Any]
    ],
    scenario_coverage: dict[
        str,
        Any
    ],
) -> dict[str, bool]:

    host_to_splits: dict[
        str,
        set[str],
    ] = defaultdict(set)

    for row in manifest_rows:

        host_to_splits[
            row["hostname"]
        ].add(
            row["split"]
        )

    positive_split_counts = Counter()

    for host in positive_hosts:

        splits = host_to_splits.get(
            host,
            set(),
        )

        for split in splits:
            positive_split_counts[
                split
            ] += 1

    return {
        "ground_truth_profiles_nonempty":
            bool(gt_profiles),

        "ground_truth_records_found":
            sum(
                int(
                    x.get(
                        "records",
                        0,
                    )
                )
                for x in gt_profiles
            ) > 0,

        "positive_hosts_found":
            len(positive_hosts) > 0,

        "all_raw_files_assigned":
            all(
                row.get(
                    "split"
                )
                in SPLITS
                for row in manifest_rows
            ),

        "no_hostname_cross_split":
            all(
                len(splits) == 1
                for splits
                in host_to_splits.values()
            ),

        "positive_train_present":
            positive_split_counts[
                "train"
            ] >= 1,

        "positive_val_present":
            positive_split_counts[
                "val"
            ] >= 1,

        "positive_test_present":
            positive_split_counts[
                "test"
            ] >= 1,

        # New mandatory v1.1 check:
        "positive_scenario_coverage":
            bool(
                scenario_coverage.get(
                    "overall_pass"
                )
            ),
    }


# ============================================================================
# Main
# ============================================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "STEP 02 v1.1: inspect corrected DARPA OpTC ground truth and "
            "build a deterministic hostname-level TRAIN/VAL/TEST split with "
            "mandatory positive-scenario coverage."
        )
    )

    parser.add_argument(
        "--input-root",
        required=True,
        help=r"Dataset root, e.g. E:\\",
    )

    parser.add_argument(
        "--output-root",
        required=True,
        help=r"Project root, e.g. D:\\UIT\\KLTN",
    )

    parser.add_argument(
        "--gt-folder",
        default=DEFAULT_GT_FOLDER,
    )

    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.70,
    )

    parser.add_argument(
        "--val-ratio",
        type=float,
        default=0.15,
    )

    parser.add_argument(
        "--test-ratio",
        type=float,
        default=0.15,
    )

    parser.add_argument(
        "--seed",
        default="KLTN_OPTC_SPLIT_V1_1",
    )

    parser.add_argument(
        "--allow-original-ground-truth",
        action="store_true",
    )

    parser.add_argument(
        "--freeze",
        action="store_true",
        help=(
            "Write split_manifest_frozen.csv only when ALL v1.1 checks, "
            "including positive_scenario_coverage, pass."
        ),
    )

    args = parser.parse_args()

    ratio_sum = (
        args.train_ratio
        + args.val_ratio
        + args.test_ratio
    )

    if abs(
        ratio_sum
        - 1.0
    ) > 1e-9:
        raise ValueError(
            "train + val + test ratios must equal 1.0"
        )

    input_root = Path(
        args.input_root
    )

    output_root = Path(
        args.output_root
    )

    gt_root = (
        input_root
        / args.gt_folder
    )

    if not input_root.exists():
        raise FileNotFoundError(
            f"Input root does not exist: {input_root}"
        )

    artifact_dir = (
        output_root
        / "02_artifacts"
        / "00_label_split_v1_1"
    )

    artifact_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    gt_inventory_path = (
        artifact_dir
        / "ground_truth_inventory.csv"
    )

    gt_profile_path = (
        artifact_dir
        / "ground_truth_profile.json"
    )

    positive_hosts_path = (
        artifact_dir
        / "ground_truth_positive_hosts.csv"
    )

    candidate_manifest_path = (
        artifact_dir
        / "split_manifest_candidate.csv"
    )

    candidate_summary_path = (
        artifact_dir
        / "split_manifest_candidate_summary.json"
    )

    scenario_report_path = (
        artifact_dir
        / "positive_scenario_coverage.json"
    )

    frozen_manifest_path = (
        artifact_dir
        / "split_manifest_frozen.csv"
    )

    frozen_sha_path = (
        artifact_dir
        / "split_manifest_frozen.sha256"
    )

    md_path = (
        artifact_dir
        / "STEP_00_LABEL_SPLIT_RUN.md"
    )

    md_path.write_text(
        "\n".join(
            [
                "# STEP 02 v1.1 — Ground truth + leakage-safe split",
                "",
                "## Status",
                "",
                "**RUNNING**",
                "",
                f"- Started: `{datetime.now().isoformat()}`",
                f"- Script version: `{SCRIPT_VERSION}`",
                f"- Dataset root: `{input_root}`",
                f"- Ground truth root: `{gt_root}`",
                "",
            ]
        ),
        encoding="utf-8",
    )

    started = time.time()

    print("=" * 82)
    print("STEP 02 v1.1 — Ground truth + leakage-safe scenario-aware split")
    print("=" * 82)
    print(f"[INPUT]  {input_root}")
    print(f"[GT]     {gt_root}")
    print("[SPLIT]  unit=hostname")
    print("[NEW]    positive GT hosts are stratified PER SCENARIO")
    print("[CHECK]  positive_scenario_coverage is mandatory")
    print("[LEAK]   final vocabulary may use split=train ONLY")
    print()

    # -----------------------------------------------------------------------
    # 1. Raw host inventory
    # -----------------------------------------------------------------------
    print("[1/4] Inventory ALL raw host files...")

    raw_rows = list_raw_host_files(
        input_root
    )

    if not raw_rows:
        raise RuntimeError(
            "No raw host .json.gz files were found."
        )

    raw_hosts = sorted({
        row["hostname"]
        for row in raw_rows
    })

    raw_host_set = set(
        raw_hosts
    )

    print(
        f"      raw host files: {len(raw_rows):,}"
    )

    print(
        f"      unique hostnames: {len(raw_hosts):,}"
    )

    # -----------------------------------------------------------------------
    # 2. GT discovery/profile
    # -----------------------------------------------------------------------
    print("[2/4] Discover corrected ground-truth files...")

    (
        selected_gt_files,
        all_gt_meta,
        gt_selection_mode,
    ) = discover_ground_truth_files(
        gt_root,
        allow_original_fallback=(
            args.allow_original_ground_truth
        ),
    )

    print(
        f"      GT files discovered: {len(all_gt_meta):,}"
    )

    print(
        f"      GT files selected: {len(selected_gt_files):,}"
    )

    print(
        f"      selection mode: {gt_selection_mode}"
    )

    gt_profiles: list[
        dict[str, Any]
    ] = []

    positive_hosts: set[
        str
    ] = set()

    host_scenarios: dict[
        str,
        set[str],
    ] = defaultdict(set)

    host_gt_files: dict[
        str,
        list[str],
    ] = defaultdict(list)

    scenario_to_hosts: dict[
        str,
        set[str],
    ] = defaultdict(set)

    for index, path in enumerate(
        selected_gt_files,
        start=1,
    ):

        meta = classify_gt_file(
            path
        )

        print(
            f"      [{index}/{len(selected_gt_files)}] {path.name}"
        )

        profile = profile_ground_truth_file(
            path,
            meta,
        )

        gt_profiles.append(
            profile
        )

        if (
            profile[
                "positive_event_count_for_stratification"
            ]
            <= 0
        ):
            continue

        scenario = profile.get(
            "scenario_from_name",
            "",
        )

        for host in profile[
            "observed_hosts"
        ]:

            if not host:
                continue

            positive_hosts.add(
                host
            )

            if scenario:
                host_scenarios[
                    host
                ].add(
                    scenario
                )

                scenario_to_hosts[
                    scenario
                ].add(
                    host
                )

            host_gt_files[
                host
            ].append(
                str(path)
            )

    positive_hosts_in_raw = (
        positive_hosts
        .intersection(
            raw_host_set
        )
    )

    gt_hosts_missing_raw = (
        positive_hosts
        - raw_host_set
    )

    # Restrict scenario mappings to host groups actually present in raw corpus.
    host_scenarios_in_raw = {
        host: set(
            host_scenarios[
                host
            ]
        )
        for host
        in positive_hosts_in_raw
    }

    scenario_to_hosts_in_raw: dict[
        str,
        set[str],
    ] = defaultdict(set)

    for host, scenarios in host_scenarios_in_raw.items():

        for scenario in scenarios:
            scenario_to_hosts_in_raw[
                scenario
            ].add(
                host
            )

    print(
        f"      positive GT host groups: {len(positive_hosts):,}"
    )

    print(
        f"      matched raw positive hosts: {len(positive_hosts_in_raw):,}"
    )

    for scenario in sorted(
        scenario_to_hosts_in_raw
    ):
        print(
            f"      {scenario}: "
            f"{len(scenario_to_hosts_in_raw[scenario]):,} positive hosts"
        )

    # GT inventory
    gt_inventory_rows = []

    for meta in all_gt_meta:

        gt_inventory_rows.append(
            {
                "filename":
                    meta["filename"],
                "path":
                    meta["path"],
                "is_corrected":
                    meta["is_corrected"],
                "is_all_events":
                    meta["is_all_events"],
                "hostname_from_name":
                    meta["hostname_from_name"],
                "scenario_from_name":
                    meta["scenario_from_name"],
                "compressed_size_bytes":
                    meta["compressed_size_bytes"],
                "selected_for_profile":
                    str(
                        Path(
                            meta["path"]
                        )
                        in selected_gt_files
                    ),
            }
        )

    write_csv(
        gt_inventory_path,
        gt_inventory_rows,
        [
            "filename",
            "path",
            "is_corrected",
            "is_all_events",
            "hostname_from_name",
            "scenario_from_name",
            "compressed_size_bytes",
            "selected_for_profile",
        ],
    )

    gt_profile_doc = {
        "generated_at":
            datetime.now().isoformat(),
        "script_version":
            SCRIPT_VERSION,
        "selection_mode":
            gt_selection_mode,
        "selected_files":
            gt_profiles,
        "positive_hosts_all_gt":
            sorted(positive_hosts),
        "positive_hosts_matched_raw":
            sorted(
                positive_hosts_in_raw
            ),
        "positive_hosts_missing_raw":
            sorted(
                gt_hosts_missing_raw
            ),
        "positive_hosts_by_scenario": {
            scenario: sorted(
                hosts
            )
            for scenario, hosts
            in sorted(
                scenario_to_hosts_in_raw.items()
            )
        },
    }

    gt_profile_path.write_text(
        json.dumps(
            gt_profile_doc,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    positive_host_rows = []

    for host in sorted(
        positive_hosts
    ):

        positive_host_rows.append(
            {
                "hostname":
                    host,
                "matched_raw":
                    host in raw_host_set,
                "scenarios":
                    ";".join(
                        sorted(
                            host_scenarios.get(
                                host,
                                set(),
                            )
                        )
                    ),
                "ground_truth_files":
                    ";".join(
                        host_gt_files.get(
                            host,
                            [],
                        )
                    ),
            }
        )

    write_csv(
        positive_hosts_path,
        positive_host_rows,
        [
            "hostname",
            "matched_raw",
            "scenarios",
            "ground_truth_files",
        ],
    )

    # -----------------------------------------------------------------------
    # 3. Scenario-aware split
    # -----------------------------------------------------------------------
    print("[3/4] Build scenario-aware hostname split...")

    (
        assignment,
        split_details,
    ) = build_split_assignment(
        raw_rows,
        host_scenarios_in_raw,
        seed=args.seed,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=args.test_ratio,
    )

    scenario_coverage = scenario_coverage_report(
        scenario_to_hosts_in_raw,
        assignment,
    )

    scenario_report_path.write_text(
        json.dumps(
            scenario_coverage,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    manifest_rows: list[
        dict[str, Any]
    ] = []

    for row in raw_rows:

        host = row[
            "hostname"
        ]

        scenarios = sorted(
            host_scenarios.get(
                host,
                set(),
            )
        )

        manifest_rows.append(
            {
                **row,
                "gt_positive_host_group":
                    host
                    in positive_hosts_in_raw,
                "gt_scenarios":
                    ";".join(
                        scenarios
                    ),
                "gt_primary_scenario": (
                    scenarios[0]
                    if len(scenarios) == 1
                    else (
                        "MULTI"
                        if scenarios
                        else ""
                    )
                ),
                "split":
                    assignment[
                        host
                    ],
            }
        )

    write_csv(
        candidate_manifest_path,
        manifest_rows,
        [
            "raw_source",
            "absolute_path",
            "relative_path",
            "date",
            "hostname",
            "group_key",
            "gt_positive_host_group",
            "gt_scenarios",
            "gt_primary_scenario",
            "split",
        ],
    )

    host_split_counts = Counter(
        assignment.values()
    )

    file_split_counts = Counter(
        row["split"]
        for row in manifest_rows
    )

    positive_host_split_counts = Counter(
        assignment[
            host
        ]
        for host in positive_hosts_in_raw
    )

    checks = freeze_checks(
        manifest_rows,
        positive_hosts_in_raw,
        gt_profiles,
        scenario_coverage,
    )

    freeze_ready = all(
        checks.values()
    )

    summary = {
        "generated_at":
            datetime.now().isoformat(),
        "script_version":
            SCRIPT_VERSION,
        "input_root":
            str(input_root),
        "gt_root":
            str(gt_root),
        "ground_truth_selection_mode":
            gt_selection_mode,
        "split_unit":
            "hostname",
        "seed":
            args.seed,
        "ratios": {
            "train":
                args.train_ratio,
            "val":
                args.val_ratio,
            "test":
                args.test_ratio,
        },
        "raw_file_count":
            len(raw_rows),
        "unique_hostname_count":
            len(raw_hosts),
        "positive_gt_hostname_count":
            len(
                positive_hosts_in_raw
            ),
        "positive_gt_hostname_by_scenario": {
            scenario: len(
                hosts
            )
            for scenario, hosts
            in sorted(
                scenario_to_hosts_in_raw.items()
            )
        },
        "host_split_counts":
            dict(
                host_split_counts
            ),
        "file_split_counts":
            dict(
                file_split_counts
            ),
        "positive_host_split_counts":
            dict(
                positive_host_split_counts
            ),
        "positive_scenario_coverage":
            scenario_coverage,
        "split_details":
            split_details,
        "checks":
            checks,
        "freeze_ready":
            freeze_ready,
        "candidate_manifest_sha256":
            sha256_file(
                candidate_manifest_path
            ),
        "leakage_rule": (
            "Only split=train may be used to fit the final Host vocabulary. "
            "Validation/test are transform-only with the frozen vocabulary."
        ),
    }

    candidate_summary_path.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    # -----------------------------------------------------------------------
    # 4. Optional freeze
    # -----------------------------------------------------------------------
    frozen = False
    frozen_sha = ""

    if args.freeze:

        print("[4/4] Freeze requested...")

        if not freeze_ready:

            failed = [
                name
                for name, passed
                in checks.items()
                if not passed
            ]

            raise RuntimeError(
                "Split cannot be frozen. Failed checks: "
                + ", ".join(
                    failed
                )
            )

        frozen_manifest_path.write_bytes(
            candidate_manifest_path.read_bytes()
        )

        frozen_sha = sha256_file(
            frozen_manifest_path
        )

        frozen_sha_path.write_text(
            frozen_sha + "\n",
            encoding="utf-8",
        )

        frozen = True

        print(
            f"      [FROZEN] {frozen_manifest_path}"
        )

        print(
            f"      [SHA256] {frozen_sha}"
        )

    else:

        print(
            "[4/4] Candidate only; NOT frozen."
        )

        print(
            "      Review positive_scenario_coverage first."
        )

    elapsed = (
        time.time()
        - started
    )

    if frozen:
        status_text = (
            "COMPLETED — FROZEN"
        )
    elif freeze_ready:
        status_text = (
            "COMPLETED — CANDIDATE READY FOR REVIEW"
        )
    else:
        status_text = (
            "COMPLETED — REVIEW REQUIRED"
        )

    # -----------------------------------------------------------------------
    # Markdown handoff
    # -----------------------------------------------------------------------
    lines = [
        "# STEP 02 v1.1 — Ground truth + leakage-safe split",
        "",
        "## Status",
        "",
        f"**{status_text}**",
        "",
        "## Purpose",
        "",
        (
            "Create a deterministic hostname-level TRAIN / VAL / TEST split "
            "over the complete Host corpus while enforcing positive attack "
            "scenario coverage."
        ),
        "",
        "## Version",
        "",
        f"- `{SCRIPT_VERSION}`",
        "",
        "## Leakage policy",
        "",
        "- Split unit: **hostname**.",
        "- All files for one hostname remain in exactly one split.",
        "- Final Host vocabulary is fitted from **TRAIN ONLY**.",
        "- VAL/TEST never affect vocabulary membership or frequency thresholds.",
        "",
        "## v1.1 positive scenario policy",
        "",
        (
            "- Scenario with >=3 positive hosts: must have positive host(s) "
            "in TRAIN, VAL and TEST."
        ),
        (
            "- Scenario with exactly 2 positive hosts: one goes to TRAIN and "
            "one to TEST; VAL coverage is mathematically impossible."
        ),
        (
            "- Scenario with exactly 1 positive host: TRAIN only; the limitation "
            "is explicitly reported."
        ),
        "",
        "## Corpus",
        "",
        f"- Raw Host files: **{len(raw_rows):,}**",
        f"- Unique hostnames: **{len(raw_hosts):,}**",
        f"- Positive corrected-GT host groups: **{len(positive_hosts_in_raw):,}**",
        "",
        "## Positive hosts by scenario",
        "",
    ]

    for scenario in sorted(
        scenario_to_hosts_in_raw
    ):

        lines.append(
            f"- `{scenario}`: **{len(scenario_to_hosts_in_raw[scenario]):,}**"
        )

    lines.extend(
        [
            "",
            "## Host split counts",
            "",
            f"- TRAIN: **{host_split_counts['train']:,}**",
            f"- VAL: **{host_split_counts['val']:,}**",
            f"- TEST: **{host_split_counts['test']:,}**",
            "",
            "## File split counts",
            "",
            f"- TRAIN: **{file_split_counts['train']:,}**",
            f"- VAL: **{file_split_counts['val']:,}**",
            f"- TEST: **{file_split_counts['test']:,}**",
            "",
            "## Positive host split counts",
            "",
            f"- TRAIN: **{positive_host_split_counts['train']:,}**",
            f"- VAL: **{positive_host_split_counts['val']:,}**",
            f"- TEST: **{positive_host_split_counts['test']:,}**",
            "",
            "## Positive scenario coverage",
            "",
        ]
    )

    for scenario, item in scenario_coverage[
        "scenarios"
    ].items():

        counts = item[
            "counts"
        ]

        lines.extend(
            [
                f"### {scenario}",
                "",
                f"- Positive hosts: **{item['positive_host_count']:,}**",
                f"- Policy: `{item['coverage_policy']}`",
                (
                    f"- TRAIN / VAL / TEST: "
                    f"**{counts['train']} / {counts['val']} / {counts['test']}**"
                ),
                f"- Coverage check: **{'PASS' if item['pass'] else 'FAIL'}**",
                f"- TRAIN hosts: `{', '.join(item['hosts']['train'])}`",
                f"- VAL hosts: `{', '.join(item['hosts']['val'])}`",
                f"- TEST hosts: `{', '.join(item['hosts']['test'])}`",
                "",
            ]
        )

    lines.extend(
        [
            "## Freeze checks",
            "",
        ]
    )

    for name, passed in checks.items():

        lines.append(
            f"- {'PASS' if passed else 'FAIL'} — `{name}`"
        )

    lines.extend(
        [
            "",
            f"- Freeze ready: **{freeze_ready}**",
            f"- Frozen in this run: **{frozen}**",
            "",
            "## Generated artifacts",
            "",
            f"- GT inventory: `{gt_inventory_path}`",
            f"- GT profile: `{gt_profile_path}`",
            f"- Positive hosts: `{positive_hosts_path}`",
            f"- Candidate manifest: `{candidate_manifest_path}`",
            f"- Candidate summary: `{candidate_summary_path}`",
            f"- Scenario coverage report: `{scenario_report_path}`",
        ]
    )

    if frozen:

        lines.extend(
            [
                f"- Frozen manifest: `{frozen_manifest_path}`",
                f"- Frozen SHA-256 file: `{frozen_sha_path}`",
                f"- Frozen SHA-256: `{frozen_sha}`",
            ]
        )

    lines.extend(
        [
            f"- Handoff: `{md_path}`",
            "",
            "## Important interpretation",
            "",
            (
                "`gt_positive_host_group=True` means that corrected GT lists "
                "one or more positive events for the hostname. It does NOT mean "
                "every event/file on that hostname is malicious."
            ),
            "",
            "## Next step",
            "",
            (
                "If this candidate is accepted, rerun the exact same command "
                "with `--freeze`. After freezing, STEP 03 will scan every event "
                "from every TRAIN host file to fit the single final ~12,000-token "
                "`vocab_host_v1.json`."
            ),
            "",
            f"Elapsed time: **{elapsed:.1f} seconds**.",
            "",
        ]
    )

    md_path.write_text(
        "\n".join(
            lines
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 82)
    print(f"[STATUS] {status_text}")
    print(
        f"[RAW]    {len(raw_rows):,} host files / "
        f"{len(raw_hosts):,} hostnames"
    )
    print(
        f"[GT+]    {len(positive_hosts_in_raw):,} positive GT host groups"
    )

    for scenario, item in scenario_coverage[
        "scenarios"
    ].items():

        c = item[
            "counts"
        ]

        print(
            f"[SCEN]   {scenario}: "
            f"train={c['train']} "
            f"val={c['val']} "
            f"test={c['test']} "
            f"pass={item['pass']}"
        )

    print(
        f"[HOSTS]  train={host_split_counts['train']:,} "
        f"val={host_split_counts['val']:,} "
        f"test={host_split_counts['test']:,}"
    )

    print(
        f"[GT+]    train={positive_host_split_counts['train']:,} "
        f"val={positive_host_split_counts['val']:,} "
        f"test={positive_host_split_counts['test']:,}"
    )

    print(
        f"[READY]  freeze_ready={freeze_ready}"
    )

    print(
        f"[MD]     {md_path}"
    )

    print("=" * 82)


if __name__ == "__main__":
    main()
