from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_VERSION = "step04c-network-preprocess-train-only-v1.1"

EXPECTED_V1 = "step04c-network-preprocess-train-only-v1.0"

RESERVED = {
    "<UNK>": 0,
    "<MISSING>": 1,
}

NUMERIC_BASE = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "missed_bytes",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
]


def now_iso() -> str:
    return datetime.now().isoformat()


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
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, obj: Any) -> None:
    path.write_text(
        json.dumps(obj, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def validate_v1(
    report: dict[str, Any],
    maps: dict[str, Any],
    numeric: dict[str, Any],
    state: dict[str, Any],
) -> None:
    if report.get("script_version") != EXPECTED_V1:
        raise RuntimeError(
            f"Expected v1.0 report, got {report.get('script_version')!r}"
        )

    if report.get("status") != "CANDIDATE_READY_FOR_REVIEW":
        raise RuntimeError(
            f"v1.0 candidate not ready: {report.get('status')!r}"
        )

    if not all(report.get("automatic_checks", {}).values()):
        raise RuntimeError("v1.0 automatic checks did not all pass.")

    if maps.get("fit_split") != "train":
        raise RuntimeError("Category maps are not TRAIN-only.")

    if numeric.get("fit_split") != "train":
        raise RuntimeError("Numeric stats are not TRAIN-only.")

    if int(state.get("joined_rows", -1)) != int(
        report["step04b_summary"]["joined_rows"]
    ):
        raise RuntimeError("Candidate state/report joined row mismatch.")


def build_v1_1(
    *,
    report_v1: dict[str, Any],
    maps_v1: dict[str, Any],
    numeric_v1: dict[str, Any],
    spec_v1: dict[str, Any],
    min_numeric_std: float,
    zscore_clip_abs: float,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    # ------------------------------------------------------------------
    # Categorical: keep maps for reproducibility, but mark only TRAIN-varying
    # fields as active predictive inputs.
    # ------------------------------------------------------------------
    maps = json.loads(json.dumps(maps_v1))
    maps["version"] = "network-category-maps-v1.1"

    active_cat: list[str] = []
    inactive_cat: dict[str, str] = {}

    for field, field_info in maps["fields"].items():
        diag = report_v1["category_diagnostics"][field]

        train_unique = int(
            diag["train_unique_values_including_missing"]
        )
        train_missing = int(
            diag["by_split"]["train"]["missing"]
        )
        train_rows = int(
            diag["by_split"]["train"]["rows"]
        )

        # A field with only one TRAIN-observed value cannot discriminate samples.
        # Missing is handled separately and should not rescue a constant field
        # unless missing/non-missing actually varies.
        varying_missing = 0 < train_missing < train_rows

        active = train_unique > 1 or varying_missing

        field_info["active_for_model"] = active

        if active:
            active_cat.append(field)
        else:
            inactive_cat[field] = (
                "constant_on_train; kept only for audit/reproducibility"
            )

    # ------------------------------------------------------------------
    # Numerical: raw missed_bytes is near-constant in this dataset.
    # Keep TRAIN stats, but do not feed unstable z-score when std is tiny.
    # Instead preserve signal as deterministic binary has_missed_bytes.
    # ------------------------------------------------------------------
    numeric = json.loads(json.dumps(numeric_v1))
    numeric["version"] = "network-numeric-stats-v1.1"
    numeric["zscore_clip_abs"] = float(zscore_clip_abs)

    active_num: list[str] = []
    inactive_num: dict[str, str] = {}

    for field in NUMERIC_BASE:
        info = numeric["features"][field]
        std = float(info["log1p_std"])

        active = std >= min_numeric_std
        info["active_for_model"] = active
        info["zscore_clip_abs"] = float(zscore_clip_abs)

        if active:
            active_num.append(field)
        else:
            inactive_num[field] = (
                f"TRAIN log1p std={std:.9f} < {min_numeric_std}; "
                "raw z-score would be unstable for rare non-zero values"
            )

    derived_binary = [
        {
            "name": "has_missed_bytes",
            "source": "missed_bytes",
            "rule": "1.0 if missed_bytes > 0 else 0.0",
            "fit_required": False,
            "reason": (
                "Preserve rare missed-bytes signal without dividing by "
                "near-zero TRAIN std."
            ),
        }
    ]

    # ------------------------------------------------------------------
    # Spec.
    # ------------------------------------------------------------------
    spec = json.loads(json.dumps(spec_v1))
    spec["version"] = "network-preprocess-spec-v1.1"
    spec["profiled_categorical_features"] = list(
        spec_v1["categorical_features"]
    )
    spec["active_categorical_features"] = active_cat
    spec["inactive_categorical_features"] = inactive_cat

    spec["profiled_numerical_features"] = list(
        spec_v1["numerical_features"]
    )
    spec["active_numerical_features"] = active_num
    spec["inactive_numerical_features"] = inactive_num
    spec["derived_binary_features"] = derived_binary

    spec["numeric_transform"] = (
        "log1p_nonnegative_then_train_zscore_then_clip"
    )
    spec["numeric_zscore_clip_abs"] = float(zscore_clip_abs)
    spec["numeric_missing_policy"] = {
        **spec_v1["numeric_missing_policy"],
        "clip_after_zscore": [
            -float(zscore_clip_abs),
            float(zscore_clip_abs),
        ],
    }

    spec["selection_policy"] = {
        "categorical_active_rule": (
            "Field must vary on TRAIN or have varying TRAIN missingness. "
            "No VAL/TEST values are used to decide whether the field is active."
        ),
        "numeric_active_rule": (
            f"TRAIN log1p std >= {min_numeric_std}. "
            "No VAL/TEST statistics are used to activate/drop fields."
        ),
        "label_used_for_feature_selection": False,
        "val_used_for_feature_selection": False,
        "test_used_for_feature_selection": False,
    }

    # ------------------------------------------------------------------
    # Report.
    # ------------------------------------------------------------------
    report = {
        "generated_at": now_iso(),
        "script_version": SCRIPT_VERSION,
        "status": "READY_TO_FREEZE",
        "source_v1_candidate_fingerprint_sha256":
            report_v1["candidate_fingerprint_sha256"],
        "fit_policy": {
            "fit_split": "train",
            "val_used_for_fit": False,
            "test_used_for_fit": False,
            "unmatched_split_used_for_fit": False,
            "label_used_for_feature_selection": False,
            "min_numeric_log1p_std": float(min_numeric_std),
            "zscore_clip_abs": float(zscore_clip_abs),
        },
        "active_categorical_features": active_cat,
        "inactive_categorical_features": inactive_cat,
        "active_numerical_features": active_num,
        "inactive_numerical_features": inactive_num,
        "derived_binary_features": derived_binary,
        "oov_audit": {
            field: {
                "val_UNK_rate":
                    report_v1["category_diagnostics"][field]
                    ["by_split"]["val"]["UNK_rate"],
                "test_UNK_rate":
                    report_v1["category_diagnostics"][field]
                    ["by_split"]["test"]["UNK_rate"],
            }
            for field in maps["fields"]
        },
        "notes": [
            (
                "v1.0 candidate passed leakage/OOV/missing checks but several "
                "categorical fields are constant on TRAIN."
            ),
            (
                "Raw missed_bytes has near-zero TRAIN variance; v1.1 replaces "
                "its unstable z-score input with deterministic has_missed_bytes."
            ),
            (
                "All active/inactive decisions use TRAIN statistics only. "
                "VAL/TEST OOV rates are audit-only."
            ),
        ],
    }

    return maps, numeric, spec, report


def write_md(
    path: Path,
    *,
    report: dict[str, Any],
    frozen: bool,
    fingerprint: str | None,
) -> None:
    lines = [
        "# STEP 04C v1.1 — Review và freeze Network preprocessing",
        "",
        "## Trạng thái",
        "",
        (
            "**FROZEN — READY FOR STEP 04D**"
            if frozen
            else "**READY_TO_FREEZE**"
        ),
        "",
        "## Vì sao không freeze thẳng candidate v1.0?",
        "",
        "Candidate v1.0 đã PASS leakage/OOV/missing checks, nhưng có nhiều categorical field không thay đổi trên TRAIN và `missed_bytes` có variance gần 0.",
        "",
        "Nếu giữ các field constant trong Mixed-Type Self-Attention, chúng không giúp phân biệt sample nhưng vẫn tạo feature token/embedding không cần thiết.",
        "",
        "Nếu z-score trực tiếp `missed_bytes`, các giá trị hiếm khác 0 có thể trở thành outlier rất lớn vì TRAIN std quá nhỏ.",
        "",
        "## Active categorical features",
        "",
    ]

    for field in report["active_categorical_features"]:
        lines.append(f"- `{field}`")

    lines.extend([
        "",
        "## Inactive categorical features",
        "",
    ])

    for field, reason in report["inactive_categorical_features"].items():
        lines.append(f"- `{field}` — {reason}")

    lines.extend([
        "",
        "## Active numerical features",
        "",
    ])

    for field in report["active_numerical_features"]:
        lines.append(f"- `{field}`")

    lines.extend([
        "",
        "## Inactive/raw numerical features",
        "",
    ])

    for field, reason in report["inactive_numerical_features"].items():
        lines.append(f"- `{field}` — {reason}")

    lines.extend([
        "",
        "## Derived binary feature",
        "",
        "```text",
        "has_missed_bytes = 1.0 if missed_bytes > 0 else 0.0",
        "```",
        "",
        "Feature này giữ lại thông tin `missed_bytes` hiếm nhưng tránh unstable z-score.",
        "",
        "## Numerical safety",
        "",
        f"- Active numerical: `log1p -> TRAIN z-score -> clip ±{report['fit_policy']['zscore_clip_abs']}`.",
        "- Missing numerical vẫn dùng normalized value `0.0` + parallel missing mask.",
        "",
        "## Leakage",
        "",
        "- Active/inactive decision chỉ dùng TRAIN cardinality/std.",
        "- Không dùng VAL/TEST để chọn feature.",
        "- Không dùng label để chọn feature.",
        "- VAL/TEST OOV chỉ dùng audit.",
        "",
    ])

    if fingerprint:
        lines.extend([
            "## Frozen fingerprint",
            "",
            f"`{fingerprint}`",
            "",
        ])

    lines.extend([
        "## Next step",
        "",
        (
            "STEP 04D — build shared `(hostname, 15-minute-window, chunk)` graph/sequence samples."
            if frozen
            else "Chạy lại command với `--freeze`. Không cần scan lại 92M joined rows."
        ),
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--source-dir", default=None)
    parser.add_argument("--min-numeric-std", type=float, default=0.01)
    parser.add_argument("--zscore-clip-abs", type=float, default=10.0)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args()

    output_root = Path(args.output_root)

    source_dir = (
        Path(args.source_dir)
        if args.source_dir
        else output_root / "02_artifacts" / "03_network_preprocess_v1"
    )

    out_dir = output_root / "02_artifacts" / "03_network_preprocess_v1_1"
    out_dir.mkdir(parents=True, exist_ok=True)

    src_report = source_dir / "network_preprocess_report.json"
    src_maps = source_dir / "network_category_maps_candidate.json"
    src_numeric = source_dir / "network_numeric_stats_candidate.json"
    src_spec = source_dir / "network_preprocess_spec_candidate.json"
    src_state = source_dir / "candidate_state.json"

    for path in (src_report, src_maps, src_numeric, src_spec, src_state):
        if not path.exists():
            raise FileNotFoundError(path)

    report_v1 = load_json(src_report)
    maps_v1 = load_json(src_maps)
    numeric_v1 = load_json(src_numeric)
    spec_v1 = load_json(src_spec)
    state_v1 = load_json(src_state)

    validate_v1(
        report=report_v1,
        maps=maps_v1,
        numeric=numeric_v1,
        state=state_v1,
    )

    maps, numeric, spec, report = build_v1_1(
        report_v1=report_v1,
        maps_v1=maps_v1,
        numeric_v1=numeric_v1,
        spec_v1=spec_v1,
        min_numeric_std=args.min_numeric_std,
        zscore_clip_abs=args.zscore_clip_abs,
    )

    candidate_payload = {
        "maps": maps,
        "numeric": numeric,
        "spec": spec,
        "source_v1_report_sha256": sha256_file(src_report),
        "source_v1_maps_sha256": sha256_file(src_maps),
        "source_v1_numeric_sha256": sha256_file(src_numeric),
        "source_v1_spec_sha256": sha256_file(src_spec),
    }

    candidate_fp = sha256_bytes(canonical_bytes(candidate_payload))
    report["candidate_v1_1_fingerprint_sha256"] = candidate_fp

    cand_maps = out_dir / "network_category_maps_candidate_v1_1.json"
    cand_num = out_dir / "network_numeric_stats_candidate_v1_1.json"
    cand_spec = out_dir / "network_preprocess_spec_candidate_v1_1.json"
    report_path = out_dir / "network_preprocess_review_v1_1.json"
    md_path = out_dir / "STEP_03B_NETWORK_PREPROCESS_REVIEW.md"

    dump_json(cand_maps, maps)
    dump_json(cand_num, numeric)
    dump_json(cand_spec, spec)
    dump_json(report_path, report)

    frozen_fp = None

    if args.freeze:
        final_maps = out_dir / "network_category_maps.json"
        final_num = out_dir / "network_numeric_stats.json"
        final_spec = out_dir / "network_preprocess_spec.json"
        fp_path = out_dir / "network_preprocess_fingerprint.json"

        shutil.copy2(cand_maps, final_maps)
        shutil.copy2(cand_num, final_num)
        shutil.copy2(cand_spec, final_spec)

        fingerprint_payload = {
            "generated_at": now_iso(),
            "script_version": SCRIPT_VERSION,
            "source_v1_candidate_fingerprint_sha256":
                report_v1["candidate_fingerprint_sha256"],
            "candidate_v1_1_fingerprint_sha256": candidate_fp,
            "category_maps_sha256": sha256_file(final_maps),
            "numeric_stats_sha256": sha256_file(final_num),
            "preprocess_spec_sha256": sha256_file(final_spec),
            "fit_split": "train",
            "val_used_for_fit": False,
            "test_used_for_fit": False,
            "unmatched_split_used_for_fit": False,
            "label_used_for_feature_selection": False,
        }

        frozen_fp = sha256_bytes(canonical_bytes(fingerprint_payload))
        fingerprint_payload["frozen_fingerprint_sha256"] = frozen_fp
        dump_json(fp_path, fingerprint_payload)

    write_md(
        md_path,
        report=report,
        frozen=args.freeze,
        fingerprint=frozen_fp,
    )

    print("=" * 92)
    print("STEP 04C v1.1 — finalize Network preprocessing")
    print("=" * 92)
    print("[SOURCE] v1.0 candidate reused — NO 92M-row rescan")
    print()
    print("[ACTIVE CAT]")
    for field in report["active_categorical_features"]:
        print(f"  + {field}")

    print()
    print("[INACTIVE CAT]")
    for field in report["inactive_categorical_features"]:
        print(f"  - {field}")

    print()
    print("[ACTIVE NUM]")
    for field in report["active_numerical_features"]:
        print(f"  + {field}")

    print()
    print("[REPLACED NUM]")
    for field in report["inactive_numerical_features"]:
        print(f"  - {field}")
    print("  + has_missed_bytes (binary)")

    print()
    print(
        "[STATUS] "
        + ("FROZEN — READY FOR STEP 04D" if args.freeze else "READY_TO_FREEZE")
    )
    print(f"[REPORT] {report_path}")
    print(f"[MD]     {md_path}")

    if args.freeze:
        print(f"[FP]     {out_dir / 'network_preprocess_fingerprint.json'}")
    else:
        print("[NEXT] Re-run SAME command with --freeze.")

    print("=" * 92)


if __name__ == "__main__":
    main()
