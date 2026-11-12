"""STEP 11 — Kiem tra network_event_schema_v1.json khop voi du lieu that (parquet, preprocessing, shard).

    python 11_check_schema.py --project-root D:\\UIT\\KLTNv2 --dataset-dir 03_datasets\\random_network_dl_v1_1_15m\\seed_1
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb
import numpy as np

import network_schema


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--dataset-dir", required=True, help="thu muc dataset da build (co preprocessing/, split/, shards/)")
    ap.add_argument("--out", default=None, help="ghi bao cao JSON (khong ghi de)")
    args = ap.parse_args()
    root = Path(args.project_root)
    ds = Path(args.dataset_dir)
    if not ds.is_absolute():
        ds = root / ds

    schema = network_schema.load_schema()
    checks: dict[str, dict] = {}

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks[name] = {"pass": bool(ok), "detail": detail}
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" | {detail}" if detail else ""))

    by_name = {f["name"]: f for f in schema["fields"]}
    source_fields = [f["name"] for f in schema["fields"] if "derived_from" not in f]

    # 1) cot parquet da join == field nguon trong schema
    glob = (root / "02_artifacts" / "02_network_joined_v1" / "joined" / "split=*" / "date=*" / "*.parquet").as_posix()
    cols = [r[0] for r in duckdb.connect().execute(f"DESCRIBE SELECT * FROM read_parquet('{glob}', hive_partitioning=true)").fetchall()]
    check("parquet_columns_match_schema_source_fields", cols == source_fields,
          f"parquet={len(cols)} cot, schema={len(source_fields)} field nguon; khac nhau: {sorted(set(cols) ^ set(source_fields))}")

    # 2) spec cua dataset
    pre = ds / "preprocessing"
    spec = json.loads((pre / "network_preprocess_spec.json").read_text(encoding="utf-8"))
    maps = json.loads((pre / "network_category_maps.json").read_text(encoding="utf-8"))["fields"]
    stats = json.loads((pre / "network_numeric_stats.json").read_text(encoding="utf-8"))["features"]
    cat_all = schema["categorical"]["base_fields"] + schema["categorical"]["derived_fields"]
    check("spec_profiled_categorical_equals_schema", spec["profiled_categorical_features"] == cat_all)
    check("spec_profiled_numerical_equals_schema", spec["profiled_numerical_features"] == schema["numeric"]["fields"])
    check("category_maps_fields_equal_schema", list(maps) == cat_all)
    check("numeric_stats_fields_equal_schema", list(stats) == schema["numeric"]["fields"])
    check("active_categorical_subset_of_schema", set(spec["active_categorical_features"]) <= set(cat_all),
          ",".join(spec["active_categorical_features"]))
    check("active_numerical_subset_of_schema", set(spec["active_numerical_features"]) <= set(schema["numeric"]["fields"]),
          ",".join(spec["active_numerical_features"]))
    bin_names = [b["name"] for b in spec["derived_binary_features"]]
    check("binary_features_have_role_binary", all(by_name[b]["role"] == "binary" for b in bin_names), ",".join(bin_names))
    check("reserved_ids_equal_schema", spec["categorical_reserved_ids"] == schema["categorical"]["reserved_ids"])
    check("common_ports_equal_schema",
          {int(k): v for k, v in spec["derived_rules"]["port_class_common_ports"].items()} == network_schema.common_ports(schema))
    check("all_schema_fields_documented", all(f["meaning_vi"] and f["source"] for f in schema["fields"]), f"{len(schema['fields'])} field")

    # 3) shard that: hinh dang mang khop so cot active
    man = json.loads((ds / "dataset_manifest.json").read_text(encoding="utf-8"))
    shard = next((ds / "shards" / "test").rglob("*.npz"))
    with np.load(shard, allow_pickle=False) as z:
        n = z["x_cat"].shape[0]
        shapes = {k: list(z[k].shape) for k in ("x_cat", "x_num", "x_num_missing", "x_bin", "delta_t_log1p")}
    n_cat, n_num = len(spec["active_categorical_features"]), len(spec["active_numerical_features"])
    ok = (shapes["x_cat"] == [n, n_cat] and shapes["x_num"] == [n, n_num] and shapes["x_num_missing"] == [n, n_num]
          and shapes["x_bin"] == [n, len(bin_names)] and shapes["delta_t_log1p"] == [n])
    check("shard_array_shapes_match_active_features", ok, f"{shard.name}: {shapes}")

    # 4) cac field khong phai feature khong lot vao danh sach active
    forbidden = {f["name"] for f in schema["fields"] if f["role"] in {"join_audit", "target", "graph_only", "cross_check", "not_used"}}
    leaked = forbidden & (set(spec["active_categorical_features"]) | set(spec["active_numerical_features"]))
    check("no_join_target_graph_field_in_active_features", not leaked, f"lot vao: {sorted(leaked)}")

    summary = {"schema_version": schema["schema_version"], "schema_sha256": schema["_sha256"], "dataset": str(ds),
               "dataset_version": man.get("dataset_version"), "all_pass": all(c["pass"] for c in checks.values()), "checks": checks}
    print("ALL PASS" if summary["all_pass"] else "SOME FAIL")
    if args.out:
        out = Path(args.out)
        if out.exists():
            raise FileExistsError(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")
        print("[WROTE]", out)
    raise SystemExit(0 if summary["all_pass"] else 1)


if __name__ == "__main__":
    main()
