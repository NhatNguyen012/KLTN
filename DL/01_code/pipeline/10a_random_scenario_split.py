"""STEP 10A — 3 split ngẫu nhiên host-disjoint, stratify host bị tấn công theo scenario.

Policy stratify lấy NGUYÊN từ 00_ground_truth_and_split.py (import bằng importlib, không copy):
  - scenario >= 3 host positive: có mặt ở train/val/test (chia theo tỉ lệ, largest remainder)
  - scenario = 2 host: 1 train + 1 test
  - scenario = 1 host: train
  - host benign: chia ngẫu nhiên để đạt quota toàn cục 70/15/15
Host + scenario lấy từ 02_artifacts/08a_loso_remap_v1/frozen (cột gt_positive_host_group,
gt_primary_scenario). Output cùng định dạng file mapping host -> split (cột split tên assigned_split) để 08b/08c/08d dùng lại.

    python 10a_random_scenario_split.py --project-root D:\\UIT\\KLTNv2
"""
from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

SCRIPT_VERSION = "step10a-random-scenario-split-v1.0"
SEED_PREFIX = "KLTN_OPTC_RANDOM_SCENARIO_SPLIT_V1"
ORIGINAL_SEED = "KLTN_OPTC_SPLIT_V1_1"
SPLITS = ("train", "val", "test")
LOSO_CONTRACT_VERSION = "step05f-b-loso-remap-audit-v1.1-zero-row-safe"
OUT_COLUMNS = [
    "hostname", "gt_positive_host_group", "gt_primary_scenario", "original_split",
    "assigned_split", "heldout_scenario", "role", "event_rows", "positive_event_rows",
    "min_ts", "max_ts",
]


def load_split_policy():
    path = Path(__file__).with_name("00_ground_truth_and_split.py")
    spec = importlib.util.spec_from_file_location("step00_split_policy", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


policy = load_split_policy()
sha256_file = policy.sha256_file
sha256_text = policy.sha256_text


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def load_source_hosts(frozen_dir: Path) -> tuple[pd.DataFrame, dict[str, Any], Path]:
    """Đọc host + scenario từ 3 fold LOSO đông cứng (đã verify sha), assert cột GT giống hệt nhau."""
    contract_path = frozen_dir / "loso_fold_contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    if contract.get("script_version") != LOSO_CONTRACT_VERSION:
        raise RuntimeError(f"Unexpected LOSO contract version: {contract.get('script_version')!r}")

    keep = ["hostname", "gt_positive_host_group", "gt_primary_scenario", "original_split",
            "event_rows", "positive_event_rows", "min_ts", "max_ts"]
    frames = []
    first_path = None
    for fold, info in sorted(contract["folds"].items()):
        p = frozen_dir / info["file"]
        if sha256_file(p) != info["sha256"]:
            raise RuntimeError(f"LOSO mapping SHA mismatch: {p}")
        df = pd.read_csv(p)
        df["gt_positive_host_group"] = df["gt_positive_host_group"].astype(bool)
        df["gt_primary_scenario"] = df["gt_primary_scenario"].fillna("").astype(str)
        frames.append(df[keep].sort_values("hostname").reset_index(drop=True))
        first_path = first_path or p

    for other in frames[1:]:
        if not frames[0].equals(other):
            raise RuntimeError("Các fold LOSO không có cột host/GT giống hệt nhau")

    hosts = frames[0]
    if hosts["hostname"].duplicated().any():
        raise RuntimeError("duplicate hostname in source mapping")
    return hosts, contract, first_path


def make_split(hosts: pd.DataFrame, seed_str: str, ratios: tuple[float, float, float]) -> dict[str, str]:
    pos = hosts[hosts["gt_positive_host_group"]]
    host_to_scen = {h: {s} for h, s in zip(pos["hostname"], pos["gt_primary_scenario"])}
    if any(not s for v in host_to_scen.values() for s in v):
        raise RuntimeError("positive host without scenario")
    assignment, _details = policy.build_split_assignment(
        [{"hostname": h} for h in hosts["hostname"]],
        host_to_scen,
        seed=seed_str,
        train_ratio=ratios[0], val_ratio=ratios[1], test_ratio=ratios[2],
    )
    return assignment


def build_split_table(hosts: pd.DataFrame, assignment: dict[str, str]) -> pd.DataFrame:
    df = hosts.copy()
    df["assigned_split"] = df["hostname"].map(assignment)
    df["heldout_scenario"] = "NONE"
    df["role"] = df["gt_positive_host_group"].map(
        {True: "RANDOM_SPLIT_POSITIVE_HOST", False: "RANDOM_SPLIT_BENIGN_HOST"})
    return df[OUT_COLUMNS]


def split_stats(df: pd.DataFrame) -> dict[str, Any]:
    stats: dict[str, Any] = {"by_split": {}, "positive_by_scenario_split": {}}
    for s in SPLITS:
        sub = df[df["assigned_split"] == s]
        stats["by_split"][s] = {
            "hosts": int(len(sub)),
            "positive_hosts_gt": int(sub["gt_positive_host_group"].sum()),
            "positive_hosts_with_positive_events": int((sub["positive_event_rows"] > 0).sum()),
            "events": int(sub["event_rows"].sum()),
            "positive_events": int(sub["positive_event_rows"].sum()),
        }
    pos = df[df["gt_positive_host_group"]]
    for scen in sorted(pos["gt_primary_scenario"].unique()):
        stats["positive_by_scenario_split"][scen] = {}
        for s in SPLITS:
            sub = pos[(pos["gt_primary_scenario"] == scen) & (pos["assigned_split"] == s)]
            stats["positive_by_scenario_split"][scen][s] = {
                "gt_positive_hosts": int(len(sub)),
                "hosts_with_positive_events": int((sub["positive_event_rows"] > 0).sum()),
                "positive_events": int(sub["positive_event_rows"].sum()),
                "hosts": sorted(sub["hostname"].tolist()),
                "positive_events_by_host": {r.hostname: int(r.positive_event_rows) for r in sub.itertuples()},
            }
    return stats


def validate(df: pd.DataFrame, src_contract: dict[str, Any], hosts: pd.DataFrame) -> dict[str, bool]:
    sets = {s: set(df.loc[df["assigned_split"] == s, "hostname"]) for s in SPLITS}
    pos = hosts[hosts["gt_positive_host_group"]]
    scen_to_hosts = {k: set(v) for k, v in pos.groupby("gt_primary_scenario")["hostname"]}
    assignment = dict(zip(df["hostname"], df["assigned_split"]))
    coverage = policy.scenario_coverage_report(scen_to_hosts, assignment)
    return {
        "hostname_unique": not df["hostname"].duplicated().any(),
        "split_values_valid": bool(df["assigned_split"].isin(SPLITS).all()),
        "covers_all_source_hosts": set(df["hostname"]) == set(hosts["hostname"]),
        "host_overlap_train_val_zero": not (sets["train"] & sets["val"]),
        "host_overlap_train_test_zero": not (sets["train"] & sets["test"]),
        "host_overlap_val_test_zero": not (sets["val"] & sets["test"]),
        "event_conservation": int(df["event_rows"].sum()) == int(src_contract["joined_supervised_events"]),
        "positive_event_conservation": int(df["positive_event_rows"].sum()) == int(src_contract["joined_positive_events"]),
        "scenario_coverage_policy": bool(coverage["overall_pass"]),
        "train_has_positive_events": int(df.loc[df["assigned_split"] == "train", "positive_event_rows"].sum()) > 0,
        "val_has_positive_events": int(df.loc[df["assigned_split"] == "val", "positive_event_rows"].sum()) > 0,
        "test_has_positive_events": int(df.loc[df["assigned_split"] == "test", "positive_event_rows"].sum()) > 0,
        "heldout_scenario_not_used": bool((df["heldout_scenario"] == "NONE").all()),
    }


def selftest_policy_fidelity(hosts: pd.DataFrame, ratios) -> dict[str, Any]:
    """Seed gốc của 00 phải tái tạo đúng split gốc của host positive (kiểm chứng import policy đúng)."""
    a = make_split(hosts, ORIGINAL_SEED, ratios)
    pos = hosts[hosts["gt_positive_host_group"]]
    ok = all(a[r.hostname] == r.original_split for r in pos.itertuples())
    return {"original_seed": ORIGINAL_SEED, "positive_hosts_reproduce_original_split": bool(ok),
            "positive_hosts_checked": int(len(pos))}


def write_seed(out_dir: Path, seed_k: int, seed_str: str, df: pd.DataFrame, checks: dict[str, bool],
               stats: dict[str, Any], src_contract: dict[str, Any], src_mapping: Path,
               frozen_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=False)  # không ghi đè seed đã có
    csv_path = out_dir / "host_split_frozen.csv"
    df.to_csv(csv_path, index=False)
    fold = f"seed_{seed_k}"
    contract = {
        "frozen_at": datetime.now().isoformat(),
        "script_version": SCRIPT_VERSION,
        "experiment": "random_scenario_host_split",
        "seed": seed_k,
        "seed_string": seed_str,
        "joined_root": src_contract["joined_root"],
        "joined_supervised_events": int(src_contract["joined_supervised_events"]),
        "joined_positive_events": int(src_contract["joined_positive_events"]),
        "source": {
            "remap_contract_sha256": src_contract["contract_sha256"],
            "remap_contract_file_sha256": sha256_file(frozen_dir / "loso_fold_contract.json"),
            "host_gt_source_file": src_mapping.name,
            "host_gt_source_sha256": sha256_file(src_mapping),
        },
        "folds": {fold: {"file": csv_path.name, "sha256": sha256_file(csv_path)}},
        "rules": {
            "unit": "hostname",
            "ratios": "70/15/15",
            "positive_hosts": "stratified per scenario (policy of 00_ground_truth_and_split.py)",
            "benign_hosts": "random fill to global 70/15/15 quota",
            "heldout_scenario": None,
            "physical_joined_copy": False,
            "next_step": "STEP 10B: refit preprocessing on this seed TRAIN only.",
        },
    }
    contract["contract_sha256"] = sha256_text(
        json.dumps(contract, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    dump_json(out_dir / "fold_contract.json", contract)
    report = {
        "generated_at": datetime.now().isoformat(),
        "script_version": SCRIPT_VERSION,
        "seed": seed_k,
        "seed_string": seed_str,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "gates": checks,
        **stats,
        "host_split_sha256": contract["folds"][fold]["sha256"],
        "contract_sha256": contract["contract_sha256"],
        "note": "Số positive WINDOW theo scenario x split chỉ có sau khi build shards (STEP 10D).",
    }
    dump_json(out_dir / "split_report.json", report)
    return report


def write_combined_contract(art: Path, seeds: list[int]) -> Path:
    """Contract gộp (folds = seed_k) cho 08b/08c: đọc lại contract từng seed, không đụng file seed."""
    path = art / "random_split_contract.json"
    if path.exists():
        raise FileExistsError(f"{path} đã tồn tại; không ghi đè")
    per_seed = {}
    for k in seeds:
        c = json.loads((art / f"seed_{k}" / "fold_contract.json").read_text(encoding="utf-8"))
        rel = f"seed_{k}/host_split_frozen.csv"
        sha = sha256_file(art / rel)
        if c["folds"][f"seed_{k}"]["sha256"] != sha:
            raise RuntimeError(f"seed_{k}: host_split_frozen.csv sha khác fold_contract.json")
        per_seed[k] = (c, rel, sha)
    first = per_seed[seeds[0]][0]
    for k in seeds:
        c = per_seed[k][0]
        for key in ("joined_root", "joined_supervised_events", "joined_positive_events"):
            if c[key] != first[key]:
                raise RuntimeError(f"seed_{k}: {key} khác seed đầu")
    contract = {
        "frozen_at": datetime.now().isoformat(),
        "script_version": SCRIPT_VERSION,
        "experiment": "random_scenario_host_split",
        "joined_root": first["joined_root"],
        "joined_supervised_events": first["joined_supervised_events"],
        "joined_positive_events": first["joined_positive_events"],
        "folds": {f"seed_{k}": {"file": rel, "sha256": sha, "seed_string": per_seed[k][0]["seed_string"],
                                "seed_contract_sha256": per_seed[k][0]["contract_sha256"]}
                  for k, (_c, rel, sha) in per_seed.items()},
        "rules": first["rules"],
    }
    contract["contract_sha256"] = sha256_text(
        json.dumps(contract, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    dump_json(path, contract)
    return path


def overlap_report(tables: dict[int, pd.DataFrame], hosts: pd.DataFrame, ratios) -> dict[str, Any]:
    def hs(df, split, positive=None):
        m = df["assigned_split"] == split
        if positive is not None:
            m &= df["gt_positive_host_group"] == positive
        return set(df.loc[m, "hostname"])

    orig = hosts.rename(columns={"original_split": "assigned_split"})
    tables_all = {**{f"seed_{k}": v for k, v in tables.items()}, "original": orig}
    n = len(hosts)
    exp_test = int(round(n * ratios[2]))
    pairs = []
    for (a, ta), (b, tb) in itertools.combinations(tables_all.items(), 2):
        row = {"a": a, "b": b}
        for s in ("train", "val", "test"):
            row[f"shared_{s}_hosts"] = len(hs(ta, s) & hs(tb, s))
        row["shared_test_positive_hosts"] = len(hs(ta, "test", True) & hs(tb, "test", True))
        row["shared_test_benign_hosts"] = len(hs(ta, "test", False) & hs(tb, "test", False))
        row["test_positive_hosts_identical"] = hs(ta, "test", True) == hs(tb, "test", True)
        row["test_hosts_jaccard"] = round(len(hs(ta, "test") & hs(tb, "test")) / max(1, len(hs(ta, "test") | hs(tb, "test"))), 4)
        pairs.append(row)
    return {
        "expected_shared_test_hosts_if_independent_random": round(exp_test * exp_test / n, 1),
        "test_hosts_per_seed": {k: len(hs(v, "test")) for k, v in tables_all.items()},
        "test_positive_hosts_per_seed": {k: sorted(hs(v, "test", True)) for k, v in tables_all.items()},
        "pairs": pairs,
        "splits_actually_differ": not all(p["test_hosts_jaccard"] == 1.0 for p in pairs if p["b"] != "original" and p["a"] != "original"),
    }


def write_md(path: Path, reports: dict[int, dict[str, Any]], overlap: dict[str, Any], selftest: dict[str, Any],
             seeds: list[int], hosts: pd.DataFrame) -> None:
    L = [
        "# STEP 10A — 3 split ngẫu nhiên host-disjoint, stratify theo scenario", "",
        "## Trạng thái", "",
        f"- Script: `{SCRIPT_VERSION}` (`01_code/pipeline/10a_random_scenario_split.py`)",
        f"- Sinh lúc: `{datetime.now().isoformat(timespec='seconds')}`",
        "- Trạng thái: **" + ("PASS" if all(r["status"] == "PASS" for r in reports.values()) else "FAIL") + "** (mọi gate của cả 3 seed)", "",
        "## Thiết kế", "",
        f"- Đơn vị: hostname; tỉ lệ 70/15/15; universe = {len(hosts)} host có dòng mạng trong joined data (nguồn: artifact remap STEP 08A, thư mục `frozen`; chỉ dùng cột host/scenario).",
        "- Policy host positive **import nguyên** từ `00_ground_truth_and_split.py` (`build_split_assignment`): scenario ≥3 host có mặt ở train/val/test; scenario 2 host → train + test; host benign chia ngẫu nhiên để đạt quota 70/15/15.",
        f"- Seed: chuỗi `{SEED_PREFIX}|seed=k`, k = {', '.join(map(str, seeds))}; xếp thứ tự bằng sha256 như 00 (tái lập được, không phụ thuộc numpy/OS).",
        f"- Kiểm chứng import policy: với seed gốc `{selftest['original_seed']}`, {selftest['positive_hosts_checked']} host positive "
        f"tái tạo đúng split gốc: **{selftest['positive_hosts_reproduce_original_split']}**.",
        "- `heldout_scenario = NONE` (không có scenario giữ riêng); cột split của mapping tên `assigned_split` (08b/08c/08d ở mode random đọc cột này).", "",
        "## Kết quả từng seed", "",
    ]
    for k in seeds:
        r = reports[k]
        L += [f"### seed_{k}  (`{r['seed_string']}`)", "", f"- Status: **{r['status']}**; contract sha256: `{r['contract_sha256']}`",
              f"- `host_split_frozen.csv` sha256: `{r['host_split_sha256']}`", "",
              "| split | host | host positive (GT) | host có positive event | event | positive event |", "|---|---:|---:|---:|---:|---:|"]
        for s in SPLITS:
            b = r["by_split"][s]
            L.append(f"| {s} | {b['hosts']} | {b['positive_hosts_gt']} | {b['positive_hosts_with_positive_events']} | {b['events']:,} | {b['positive_events']:,} |")
        L += ["", "Scenario × split (host positive / positive event):", "", "| scenario | train | val | test |", "|---|---|---|---|"]
        for scen, d in r["positive_by_scenario_split"].items():
            L.append(f"| {scen} | " + " | ".join(f"{d[s]['gt_positive_hosts']} host / {d[s]['positive_events']:,} ev" for s in SPLITS) + " |")
        L += ["", "Host positive của TEST: " + ", ".join(
            f"`{h}` ({scen}, {ev:,} ev)" for scen, d in r["positive_by_scenario_split"].items()
            for h, ev in d["test"]["positive_events_by_host"].items()) , "",
            "Gate: " + ", ".join(f"{'✅' if v else '❌'} {n}" for n, v in r["gates"].items()), ""]
    L += ["## 3 split có thực sự khác nhau không?", "",
          f"Nếu hai split độc lập hoàn toàn ngẫu nhiên, số host TEST chung kỳ vọng ≈ {overlap['expected_shared_test_hosts_if_independent_random']}.", "",
          "| A | B | chung train | chung val | chung test | chung test positive | chung test benign | Jaccard test | TEST positive giống hệt |",
          "|---|---|---:|---:|---:|---:|---:|---:|---|"]
    for p in overlap["pairs"]:
        L.append(f"| {p['a']} | {p['b']} | {p['shared_train_hosts']} | {p['shared_val_hosts']} | {p['shared_test_hosts']} | "
                 f"{p['shared_test_positive_hosts']} | {p['shared_test_benign_hosts']} | {p['test_hosts_jaccard']} | {p['test_positive_hosts_identical']} |")
    L += ["", f"- Các seed khác nhau ở tập TEST: **{overlap['splits_actually_differ']}**.", "",
          "TEST positive host mỗi seed:", ""]
    for k, v in overlap["test_positive_hosts_per_seed"].items():
        L.append(f"- {k}: {', '.join(v)}")
    L += ["", "## Lưu ý khi đọc kết quả", "",
          "- Policy cho SC2 (10 host) và SC3 (2 host) chỉ 1 host vào TEST ⇒ số positive window TEST dao động mạnh giữa các seed "
          "(ví dụ SC3: 163 vs 26 positive event tuỳ host nào vào TEST). Đây là đặc tính của policy, không phải lỗi; "
          "không so sánh tuyệt đối metric giữa các seed mà không báo cáo host TEST.",
          "- `sysclient0974` là host GT-positive nhưng có 0 positive event mạng; vẫn được stratify như host positive, "
          "nên `host positive (GT)` có thể lớn hơn `host có positive event` ở một split.",
          "- Positive window theo scenario × split sẽ có ở STEP 10D sau khi build shards.",
          "- Không có bước chọn lại seed sau khi xem kết quả: nếu gate fail, script dừng.", "",
          "## File", "",
          "- `02_artifacts/10a_random_split_v1/seed_{k}/host_split_frozen.csv`, `fold_contract.json`, `split_report.json`",
          "- `02_artifacts/10a_random_split_v1/split_overlap_report.json`", ""]
    path.write_text("\n".join(L), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="STEP 10A random scenario-stratified host splits")
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--train-ratio", type=float, default=0.70)
    ap.add_argument("--val-ratio", type=float, default=0.15)
    ap.add_argument("--test-ratio", type=float, default=0.15)
    ap.add_argument("--frozen-dir", default=None, help="default: 02_artifacts/08a_loso_remap_v1/frozen")
    ap.add_argument("--artifact-dir", default=None, help="default: 02_artifacts/10a_random_split_v1")
    ap.add_argument("--combine-only", action="store_true",
                    help="chỉ ghi random_split_contract.json từ các seed_k đã có (không sinh lại split)")
    args = ap.parse_args()

    ratios = (args.train_ratio, args.val_ratio, args.test_ratio)
    if abs(sum(ratios) - 1.0) > 1e-9:
        raise ValueError("ratios must sum to 1")
    root = Path(args.project_root)
    frozen_dir = Path(args.frozen_dir) if args.frozen_dir else root / "02_artifacts" / "08a_loso_remap_v1" / "frozen"
    art = Path(args.artifact_dir) if args.artifact_dir else root / "02_artifacts" / "10a_random_split_v1"
    if len(set(args.seeds)) != len(args.seeds):
        raise ValueError("duplicate seeds")
    if args.combine_only:
        print(f"[COMBINED CONTRACT] {write_combined_contract(art, args.seeds)}")
        return
    for k in args.seeds:
        if (art / f"seed_{k}").exists():
            raise FileExistsError(f"{art / f'seed_{k}'} đã tồn tại; không ghi đè (đổi --artifact-dir nếu cố ý)")

    hosts, src_contract, src_mapping = load_source_hosts(frozen_dir)
    print(f"[SOURCE] {len(hosts)} hosts | positive GT hosts={int(hosts['gt_positive_host_group'].sum())}")
    selftest = selftest_policy_fidelity(hosts, ratios)
    print(f"[SELFTEST] {selftest}")
    if not selftest["positive_hosts_reproduce_original_split"]:
        raise RuntimeError("Policy import không tái tạo split gốc của host positive; dừng.")

    art.mkdir(parents=True, exist_ok=True)
    tables: dict[int, pd.DataFrame] = {}
    reports: dict[int, dict[str, Any]] = {}
    for k in args.seeds:
        seed_str = f"{SEED_PREFIX}|seed={k}"
        df = build_split_table(hosts, make_split(hosts, seed_str, ratios))
        checks = validate(df, src_contract, hosts)
        stats = split_stats(df)
        if not all(checks.values()):
            bad = [n for n, v in checks.items() if not v]
            raise RuntimeError(f"seed_{k}: gate FAIL {bad}. Không tự resample; chọn seed khác một cách có chủ đích.")
        reports[k] = write_seed(art / f"seed_{k}", k, seed_str, df, checks, stats, src_contract, src_mapping, frozen_dir)
        tables[k] = df
        b = stats["by_split"]
        print(f"[seed_{k}] " + " | ".join(f"{s}: hosts={b[s]['hosts']} pos_hosts={b[s]['positive_hosts_gt']} pos_ev={b[s]['positive_events']:,}" for s in SPLITS))

    overlap = overlap_report(tables, hosts, ratios)
    dump_json(art / "split_overlap_report.json", overlap)
    write_md(art / "STEP_10A_RANDOM_SPLIT.md", reports, overlap, selftest, args.seeds, hosts)
    print(f"[COMBINED CONTRACT] {write_combined_contract(art, args.seeds)}")
    print(f"[OVERLAP] splits_actually_differ={overlap['splits_actually_differ']}")
    print(f"[DONE] {art}")


if __name__ == "__main__":
    main()
