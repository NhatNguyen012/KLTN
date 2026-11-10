#!/usr/bin/env python3
"""Build Host ML Shards for DARPA TC E3 THEIA Incremental Learning (Task 2).

Generates compressed binary sparse shards (.npz) and manifests matching the
Host ML contract from OpTC and ATLASv2 (host_shards.py, lgbm_atlasv2_theia.ipynb).
- Preserves pretrained vocabulary (12,337 features: OpTC 0..10,316 + ATLASv2 10,317..12,336) strictly immutable.
- Discovers new tokens on TRAIN and appends monotonically to vocab_extended.json (index 12,337+).
- Resolves weaponized browser spurious correlations via 2-tier LabelRefiner.
- Applies scenario-based split (Train / Val / Test) with 30:1 benign undersampling.
"""

from __future__ import annotations

import argparse
from functools import lru_cache
from bisect import bisect_left, bisect_right, insort
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import sys
import time
import tempfile
from typing import Any

import numpy as np
from scipy import sparse

# Add project roots
CODE_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_ROOT = Path("/mnt/SSD_Data/optc")
sys.path.insert(0, str(CODE_ROOT))
sys.path.insert(0, str(WORKSPACE_ROOT))

from preprocess.common_schema import (
    CanonicalEvent,
    classify_image_dir,
    classify_system_resource,
    classify_proc_resource,
    normalize_posix_path,
    path_under,
    classify_principal,
    extract_basename,
    parse_timestamp_micros,
)
from preprocess.label_refiner import LabelRefiner
from preprocess.theia_adapter import THEIAAdapter
from preprocess.host_context import FileSessionIndex, CONTEXT_TOKENS
from preprocess.raw_context import RawContext, ensure_raw_context
from event_replay import ordered_csv, freeze_cohort
from ML.code.preprocess.host_shards import decode_shard
from preprocess.split_config import (
    TRAIN_SCENARIOS,
    VAL_SCENARIOS,
    TEST_SCENARIOS,
    TARGET_BENIGN_RATIO,
    get_partition_for_scenario,
)
from ML.code.preprocess.ecar_tokenizer import (
    GROUPS,
    flatten_tokens,
    tokenize_record,
)
from ML.code.preprocess.host_shards import FORMAT, SCHEMA, SPLITS, ShardBuffer, sha256


# Finite directory categories from OpTC spec
DIR_CATEGORIES = (
    "SYSTEM32",
    "PROGRAM_FILES",
    "TEMP_OR_APPDATA",
    "WINDOWS_OTHER",
    "USERS_OTHER",
    "PSEUDO_FS",
    "OTHER",
)

PREDEFINED_DOMAIN_TOKENS = [
    *CONTEXT_TOKENS,
    "crossproc::incoming_netconn",
    "file_role::name_service_config",
    "file_role::dynamic_loader_config",
    # 1. Application self-cache structural indicator
    "temp_context::app_own_cache",
    # 2. File Extension Structural Categorization
    "file_ext::type=so",
    "file_ext::type=sh",
    "file_ext::type=py",
    "file_ext::type=bin",
    "file_ext::type=conf",
    "file_ext::type=log",
    "file_ext::type=tar",
    "file_ext::type=gz",
    "file_ext::type=tmp",
    "file_ext::type=sqlite",
    "file_ext::type=none_or_dir",
    "file_ext::type=other",
    # 3. POSIX Top-Level System Stem Categorization
    "file_path::stem=etc",
    "file_path::stem=proc",
    "file_path::stem=dev",
    "file_path::stem=sys",
    "file_path::stem=var_log",
    "file_path::stem=tmp",
    "file_path::stem=home",
    "file_path::stem=usr_lib",
    "file_path::stem=usr_bin",
    # 4. Causal Typed Incoming Interaction Context (Past-only [ts - 30s/300s, ts])
    "proc_context::has_netconn",
    # 5. Directory Categories & Cross-Directory Structural Transitions
    *[f"actor_dir::category={d}" for d in DIR_CATEGORIES],
    *[f"target_dir::category={d}" for d in DIR_CATEGORIES],
    *[f"parent_image::dir={d}" for d in DIR_CATEGORIES],
    *[f"grandparent_image::dir={d}" for d in DIR_CATEGORIES],
    *[f"relation::actor_dir->target_dir={d1}->{d2}" for d1 in DIR_CATEGORIES for d2 in DIR_CATEGORIES],
    *[f"relation::parent_dir->actor_dir={d1}->{d2}" for d1 in DIR_CATEGORIES for d2 in DIR_CATEGORIES],
    *[f"relation::grandparent_dir->actor_dir={d1}->{d2}" for d1 in DIR_CATEGORIES for d2 in DIR_CATEGORIES],
    *[f"crossproc::actor_dir={d}" for d in DIR_CATEGORIES],
    *[f"crossproc::dir={d1}->{d2}" for d1 in DIR_CATEGORIES for d2 in DIR_CATEGORIES],
    "grandparent_image::is_shell",
    # --- Run 7: Semantic resource role tokens (break exact-vector collisions) ---
    # 6. Extended system resource roles (via classify_system_resource)
    "file_role::auth_db",
    "file_role::tz_config",
    "file_role::browser_host_config",
    "file_role::system_log",
    # 7. /proc/* semantic roles (via classify_proc_resource)
    "file_role::proc_map::self_maps",
    "file_role::proc_map::self_fd",
    "file_role::proc_map::self_status",
    "file_role::proc_map::self_other",
    "file_role::proc_map::other_maps",
    "file_role::proc_map::other_fd",
    "file_role::proc_map::other_status",
    "file_role::proc_map::other_pid",
    "file_role::proc_map::sysinfo_read",
    "file_role::proc_map::sysctl",
    "file_role::proc_map::net_state",
    "file_role::proc_map::proc_root_read",
    "file_role::proc_map::other_named",
    # 8. Network endpoint type context (from theia_adapter Run 7 disambiguation)
    *[f"file_role::proc_map::unknown_{role}" for role in ("maps", "fd", "status", "pid")],
    *[f"principal_context::role={role}" for role in ("root", "service", "user", "unknown")],
    *[f"host_operation::{op}" for op in ("EVENT_OPEN", "EVENT_READ", "EVENT_WRITE", "EVENT_CLONE", "EVENT_EXECUTE", "EVENT_SHM", "EVENT_UNLINK", "EVENT_MODIFY_FILE_ATTRIBUTES")],
    "proc_context::has_netconn_30s",
    "proc_context::has_netconn_300s",
    "crossproc::net_endpoint=netlink",
    "crossproc::net_endpoint=unix_domain",
    # 9. Parent-is-shell structural token
    "parent_image::is_shell",
    # 10. Bounded contextual reconnaissance & routine network config interactions
    "proc_context::net_actor_proc_read",
    "crossproc::shell_actor_proc_read",
    "proc_context::routine_dns_lookup",
]


@lru_cache(maxsize=4096)
def command_context_tokens(command, image):
    grouped, _ = tokenize_record({"object": "process", "action": "start",
                                 "properties": {"image_path": image, "command_line": command}})
    return tuple(grouped["command_line"])


def extract_domain_shift_tokens(event: CanonicalEvent, session: FileSessionIndex) -> list[str]:
    """Extract interpretable, structure-aware domain adaptation tokens for THEIA (Linux).

    Adheres strictly to the OpTC / ATLASv2 feature contract:
    - Purely objective structural and dynamic semantic properties.
    - No heuristic anomaly rules, no hardcoded malware names or IP lists.
    - Captures parent lineage, path categories, structural transitions, and causal typed interactions.

    Run 7 additions:
    - classify_proc_resource: semantic roles for /proc/* paths to break exact-vector collisions
      (proc_map::sysinfo_read vs proc_map::other_maps vs proc_map::self_maps etc.)
    - Extended classify_system_resource: auth_db, tz_config, browser_host_config, system_log
    - parent_image::is_shell token for shell-spawned processes (structural lineage signal)
    - crossproc::net_endpoint=loopback / unix_domain from net_endpoint_type field
    """
    tokens: list[str] = list(command_context_tokens(event.process_cmdline, event.process_path))
    tokens.extend(session.tokens(event))
    tokens.append(f"principal_context::role={event.principal_role}")
    if event.raw_operation:
        tokens.append(f"host_operation::{event.raw_operation}")
    proc_base = extract_basename(event.process_path).lower()
    self_dir = classify_image_dir(event.process_path)
    target_raw = event.target_path or ""
    target_norm = normalize_posix_path(target_raw)
    target_base = extract_basename(target_raw).lower()
    et = event.event_type

    # Causal Typed Incoming Interaction Context (Past-only [ts - W, ts])
    has_30 = session.has_netconn(event.process_guid, event.timestamp, window_micros=30_000_000)
    has_300 = True if has_30 else session.has_netconn(event.process_guid, event.timestamp, window_micros=300_000_000)

    # 1. Structural Directory Categorization of the Actor Process
    if self_dir:
        tokens.append(f"actor_dir::category={self_dir}")

    # 2. Immediate Parent Process Lineage (Causally resolved)
    _SHELL_BASENAMES = frozenset({"sh", "bash", "dash", "zsh", "csh", "tcsh", "ksh", "fish"})
    p_base = extract_basename(event.parent_path).lower()
    p_dir = classify_image_dir(event.parent_path) if event.parent_path else ""
    if not p_base and event.process_guid:
        _, p_base_cached, p_dir_cached = session.get_parent(event.process_guid, event.timestamp)
        p_base = p_base_cached
        p_dir = p_dir_cached

    if p_base:
        tokens.append(f"parent_image::basename={p_base}")
        # Run 7: structural shell-parent token — process spawned from interactive shell
        if p_base in _SHELL_BASENAMES:
            tokens.append("parent_image::is_shell")
    if p_dir and p_dir != "OTHER":
        tokens.append(f"parent_image::dir={p_dir}")
        if self_dir:
            tokens.append(f"relation::parent_dir->actor_dir={p_dir}->{self_dir}")
    if p_base and proc_base:
        tokens.append(f"structure::process_lineage={p_base}->{proc_base}")

    ancestors = session.ancestors(event.process_guid, event.timestamp, max_depth=2) if event.process_guid else []
    if len(ancestors) >= 2:
        _, gp_base, gp_dir = ancestors[1]
        if gp_base in _SHELL_BASENAMES:
            tokens.append("grandparent_image::is_shell")
        if gp_dir and gp_dir != "OTHER":
            tokens.append(f"grandparent_image::dir={gp_dir}")
            if self_dir:
                tokens.append(f"relation::grandparent_dir->actor_dir={gp_dir}->{self_dir}")

    # 3. Object Target Semantics (File or Cross-Process)
    if target_raw:
        target_dir = classify_image_dir(target_raw)
        if target_dir:
            tokens.append(f"target_dir::category={target_dir}")
        if self_dir and target_dir:
            tokens.append(f"relation::actor_dir->target_dir={self_dir}->{target_dir}")

    # 4. File Extension & System Stem Structural Categorization
    if et in ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE", "FILE_OPEN", "FILE_READ", "FILE_MODIFY"):
        # Application Self-Cache / Profile Structural Relationship
        # Objective geometric check: Process touching its own application state / cache
        # An application's name inside /etc or another user's cache is not ownership.
        proc_path = normalize_posix_path(event.process_path)
        parts = proc_path.split("/")
        user_home = "/".join(parts[:3]) if proc_path.startswith("/home/") and len(parts) > 3 else ""
        if proc_path.startswith("/root/"):
            user_home = "/root"
        own_roots = []
        if user_home and proc_base not in ("sh", "bash", "dash", "python", "python2.7", "python3"):
            own_roots = [f"{user_home}/.cache/{proc_base}", f"{user_home}/.config/{proc_base}",
                         f"{user_home}/.local/share/{proc_base}"]
            if proc_base == "firefox":
                own_roots.append(f"{user_home}/.mozilla/firefox")
        if any(path_under(target_norm, r) for r in own_roots):
            tokens.append("temp_context::app_own_cache")

        # Run 7 & 10: /proc/* semantic role before general system resource role
        if path_under(target_norm, "/proc"):
            proc_role = classify_proc_resource(target_norm, event.process_pid)
            if proc_role:
                tokens.append(f"file_role::{proc_role}")
            # Causal host context: networked or shell process performing cross-process introspection
            if proc_role.startswith(("proc_map::other_", "proc_map::unknown_")):
                if has_300:
                    tokens.append("proc_context::net_actor_proc_read")
                gp_base = ancestors[1][1] if len(ancestors) >= 2 else ""
                if p_base in _SHELL_BASENAMES or gp_base in _SHELL_BASENAMES:
                    tokens.append("crossproc::shell_actor_proc_read")
        else:
            role = classify_system_resource(target_norm)
            if role:
                tokens.append(f"file_role::{role}")
                if role == "name_service_config" and has_300:
                    tokens.append("proc_context::routine_dns_lookup")

        # POSIX Top-Level System Stem
        if path_under(target_norm, "/etc"):
            tokens.append("file_path::stem=etc")
        elif path_under(target_norm, "/proc"):
            tokens.append("file_path::stem=proc")
        elif path_under(target_norm, "/dev"):
            tokens.append("file_path::stem=dev")
        elif path_under(target_norm, "/sys"):
            tokens.append("file_path::stem=sys")
        elif path_under(target_norm, "/var/log"):
            tokens.append("file_path::stem=var_log")
        elif path_under(target_norm, "/tmp") or path_under(target_norm, "/var/tmp"):
            tokens.append("file_path::stem=tmp")
        elif path_under(target_norm, "/home") or path_under(target_norm, "/root"):
            tokens.append("file_path::stem=home")
        elif path_under(target_norm, "/usr/lib") or path_under(target_norm, "/lib"):
            tokens.append("file_path::stem=usr_lib")
        elif path_under(target_norm, "/bin") or path_under(target_norm, "/sbin") or path_under(target_norm, "/usr/bin"):
            tokens.append("file_path::stem=usr_bin")

        # File Extension Categorization (aligned with OpTC & ATLASv2)
        ext = ("." + target_base.rsplit(".", 1)[-1]) if "." in target_base else ""
        if ext in (".so",):
            tokens.append("file_ext::type=so")
        elif ext in (".sh", ".bash", ".csh", ".zsh"):
            tokens.append("file_ext::type=sh")
        elif ext in (".py", ".pyc"):
            tokens.append("file_ext::type=py")
        elif ext in (".bin", ".elf", ".exe"):
            tokens.append("file_ext::type=bin")
        elif ext in (".conf", ".cfg", ".ini"):
            tokens.append("file_ext::type=conf")
        elif ext in (".log",):
            tokens.append("file_ext::type=log")
        elif ext in (".tar",):
            tokens.append("file_ext::type=tar")
        elif ext in (".gz", ".bz2", ".xz", ".zip"):
            tokens.append("file_ext::type=gz")
        elif ext in (".tmp",):
            tokens.append("file_ext::type=tmp")
        elif ext in (".sqlite", ".db"):
            tokens.append("file_ext::type=sqlite")
        elif not ext or ext == "." or target_norm.endswith("/"):
            tokens.append("file_ext::type=none_or_dir")
        else:
            tokens.append("file_ext::type=other")

    # 5. Cross-Process Structural Transitions (IPC)
    if et == "CROSS_PROCESS":
        tokens.append(f"crossproc::actor_dir={self_dir}")
        if any(session.has_netconn(guid, event.timestamp, window_micros=300_000_000, check_parent=False)
               for guid in (event.process_guid, event.target_guid)):
            tokens.append("crossproc::incoming_netconn")
        if target_raw:
            target_dir = classify_image_dir(target_raw)
            tokens.append(f"crossproc::dir={self_dir}->{target_dir}")
        # Run 7: emit network endpoint subtype when known from adapter disambiguation
        if event.net_endpoint_type in ("netlink", "unix_domain"):
            tokens.append(f"crossproc::net_endpoint={event.net_endpoint_type}")

    # 6. Typed Incoming Interaction Context (Past-only Causal Interaction: [ts - W, ts])
    if ("firefox" in proc_base and has_30) or ("firefox" not in proc_base and has_300):
        tokens.append("proc_context::has_netconn")
    if has_30:
        tokens.append("proc_context::has_netconn_30s")
    if has_300:
        tokens.append("proc_context::has_netconn_300s")
    return tokens


def canonical_ecar_record(event: CanonicalEvent) -> dict[str, Any]:
    """Convert CanonicalEvent into standard eCAR dictionary for tokenize_record."""
    et = event.event_type
    props = {}
    obj = "process"
    act = "unknown"

    if et == "PROCESS_START":
        obj = "process"
        act = "start"
        props = {
            "image_path": event.target_path or event.process_path,
            "parent_image_path": event.parent_path,
            "command_line": event.process_cmdline,
        }
    elif et == "PROCESS_END":
        obj = "process"
        act = "terminate"
        props = {"image_path": event.process_path}
    elif et in ("FILE_WRITE", "FILE_CREATE", "FILE_MODIFY"):
        obj = "file"
        act = "write" if et == "FILE_WRITE" else "create"
        props = {"image_path": event.process_path, "file_path": event.target_path}
    elif et == "FILE_DELETE":
        obj = "file"
        act = "delete"
        props = {"image_path": event.process_path, "file_path": event.target_path}
    elif et in ("FILE_OPEN", "FILE_READ"):
        obj = "file"
        act = "read"
        props = {"image_path": event.process_path, "file_path": event.target_path}
    elif et == "CROSS_PROCESS":
        obj = "process"
        act = "open"
        props = {"image_path": event.process_path}
    elif et == "FLOW_START":
        obj = "flow"
        act = "start"
        props = {"image_path": event.process_path}

    return {
        "object": obj,
        "action": act,
        "principal": event.username,
        "properties": props,
    }


def get_split_from_event(scenario: str, timestamp_micros: int) -> str:
    """Determine train/val/test split partition from scenario or timestamp date."""
    sc = scenario.lower().strip()
    for s in TRAIN_SCENARIOS:
        if s == sc or s in sc:
            return "train"
    for s in VAL_SCENARIOS:
        if s == sc or s in sc:
            return "val"
    for s in TEST_SCENARIOS:
        if s == sc or s in sc:
            return "test"

    dt = datetime.fromtimestamp(timestamp_micros / 1_000_000, tz=timezone.utc)
    day_str = dt.strftime("%Y-%m-%d")
    if day_str in ("2018-04-03", "2018-04-04", "2018-04-05", "2018-04-06", "2018-04-09", "2018-04-10", "2018-04-11"):
        return "train"
    elif day_str == "2018-04-13":
        return "val"
    else:
        return "test"


def _build_host_shards(
    data_dir: Path,
    reapr_dir: Path,
    base_vocab_path: Path,
    output_dir: Path,
    max_events: int | None = None,
    events_per_shard: int = 50_000,
    target_benign_ratio: int = TARGET_BENIGN_RATIO,
    raw_context_path: Path | None = None,
    replay_path: Path | None = None,
    retained_source_lines=None,
) -> dict[str, Any]:
    print("=" * 80)
    print("BUILD HOST ML SHARDS FOR DARPA TC E3 THEIA (TASK 2 CONTINUAL LEARNING)")
    print("=" * 80)
    print(f"Data Dir:            {data_dir}")
    print(f"REAPr Dir:           {reapr_dir}")
    print(f"Base Vocab:          {base_vocab_path}")
    print(f"Output Dir:          {output_dir}")
    print(f"Events per Shard:    {events_per_shard:,}")
    print(f"Benign Keep Rate:    1/{target_benign_ratio}")

    output_dir = output_dir.resolve()
    protected = [data_dir.resolve(), reapr_dir.resolve(), WORKSPACE_ROOT / "DATASET"]
    if any(output_dir == p or p in output_dir.parents for p in protected):
        raise ValueError("Output must be outside read-only dataset roots")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("Use a new empty output directory; completed artifacts must remain immutable")
    if target_benign_ratio < 1 or events_per_shard < 1:
        raise ValueError("Sampling modulus and shard size must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    shards_dir = output_dir / "shards"
    assets_dir = output_dir / "assets"
    shards_dir.mkdir(parents=True, exist_ok=True)
    assets_dir.mkdir(parents=True, exist_ok=True)
    for s in ("train", "val", "test"):
        (shards_dir / s).mkdir(parents=True, exist_ok=True)

    # 1. Load frozen base vocabulary (12,337 features from ATLASv2 incremental model)
    print("\n[1/5] Loading Frozen Base Vocabulary (ATLASv2 Task 1)...")
    with base_vocab_path.open("r", encoding="utf-8") as f:
        base_vocab: dict[str, int] = json.load(f)
    n_base = len(base_vocab)
    print(f"  Loaded {n_base:,} frozen base features (indices 0..{n_base-1}).")

    extended_vocab = dict(base_vocab)
    next_col_id = n_base

    # Pre-seed predefined domain structural schema tokens (matching ATLASv2 Task 1 design)
    predefined_admitted = 0
    for tok in PREDEFINED_DOMAIN_TOKENS:
        if tok not in extended_vocab:
            extended_vocab[tok] = next_col_id
            next_col_id += 1
            predefined_admitted += 1
    print(f"  Pre-seeded {predefined_admitted} predefined domain schema tokens into extended vocabulary.")

    # 2. Initialize ground truth and adapter
    print("\n[2/5] Initializing THEIA Telemetry Adapter & LabelRefiner...")
    refiner = LabelRefiner(reapr_dir)
    raw_context = RawContext(raw_context_path) if raw_context_path else None
    adapter = THEIAAdapter(refiner, data_dir, raw_context=raw_context)

    # 3. Pass 1: Stream TRAIN partition for Token Discovery (TF >= 2)
    print("\n[3/5] Pass 1: Streaming TRAIN Events for Monotonic Token Discovery...")
    train_token_counts: Counter[str] = Counter()
    session = FileSessionIndex(raw_context=raw_context, source_stream=True)
    t0 = time.time()
    n_scanned = 0

    for event in adapter.stream_canonical_events(
        max_events=max_events, undersample_benign_ratio=target_benign_ratio,
        context_observer=session.observe_row, event_csv_path=replay_path,
        retained_source_lines=retained_source_lines,
    ):
        n_scanned += 1
        session.add_event(event)

        # Strictly skip FLOW_START and NETWORK_UNKNOWN rows for Host ML.
        # NETWORK_UNKNOWN: Run 7 — EVENT_CONNECT with missing/NA endpoint that cannot be classified
        # as either Unix IPC or external network flow. Skipping removes the ambiguous IPC inference
        # that produced the 500-FN /var/log/mail cohort (RUN6_RESULTS.md Section 5).
        if event.event_type in ("FLOW_START", "NETWORK_UNKNOWN"):
            continue

        split = get_split_from_event(event.scenario, event.timestamp)
        if split == "train":            # Undersample benign events to match train ratio while keeping all attacks
            if event.label == 0:
                try:
                    h_val = int(event.event_id[:8], 16)
                except (ValueError, TypeError):
                    h_val = int.from_bytes(hashlib.sha256(event.event_id.encode()).digest()[:8], "big")
                if h_val % target_benign_ratio != 0:
                    continue

            ecar_rec = canonical_ecar_record(event)
            grouped, _ = tokenize_record(ecar_rec)
            raw_tokens = flatten_tokens(grouped)
            domain_tokens = extract_domain_shift_tokens(event, session)
            all_tokens = set(raw_tokens) | set(domain_tokens)
            for tok in all_tokens:
                if tok not in extended_vocab:
                    train_token_counts[tok] += 1

        if n_scanned % 1_000_000 == 0:
            print(f"  Scanned {n_scanned:,} events in {time.time()-t0:.1f}s...")

    # Admit new tokens: TF >= 2 on TRAIN
    new_tokens_admitted = [
        tok for tok, count in train_token_counts.items()
        if count >= 2 and tok not in extended_vocab
    ]
    new_tokens_admitted.sort()  # Deterministic order
    for tok in new_tokens_admitted:
        extended_vocab[tok] = next_col_id
        next_col_id += 1

    print(f"  Discovered and monotonically admitted {len(new_tokens_admitted):,} new THEIA domain tokens.")
    print(f"  Total Vocab Width: {len(extended_vocab):,} (Base: {n_base:,} + Predefined: {predefined_admitted} + Discovered: {len(new_tokens_admitted):,}).")

    # Save assets: vocab.json (base copy), vocab_extended.json, vocab_metadata.json
    out_vocab = assets_dir / "vocab.json"
    shutil.copy2(base_vocab_path, out_vocab)

    out_vocab_ext = assets_dir / "vocab_extended.json"
    out_vocab_ext.write_text(json.dumps(extended_vocab, indent=2), encoding="utf-8")

    # Also save in root output_dir for convenience
    (output_dir / "vocab_extended.json").write_text(json.dumps(extended_vocab, indent=2), encoding="utf-8")

    from preprocess.split_config import PARTITIONS
    from dataclasses import asdict
    split_spec = {k: asdict(v) for k, v in PARTITIONS.items()}
    split_sha = hashlib.sha256(json.dumps(split_spec, sort_keys=True).encode()).hexdigest()
    vocab_metadata = {
        "base_vocabulary_source": str(base_vocab_path),
        "base_vocabulary_sha256": sha256(out_vocab),
        "vocabulary_sha256": sha256(out_vocab_ext),
        "split_sha256": split_sha,
        "base_width": n_base,
        "predefined_width": predefined_admitted,
        "extended_width": len(extended_vocab),
        "new_train_tokens_count": len(new_tokens_admitted),
        "split_policy": "scenario_holdout_with_day_background_not_strict_temporal",
        "split_spec": split_spec,
        "sampling": {"benign_keep_modulus": target_benign_ratio, "not_a_class_ratio": True,
                     "legacy_positive_cap": "500 per process/type for IPC/read/open; retained for comparison"},
        "raw_context_identity": raw_context.identity if raw_context else None,
        "feature_policy": "bounded causal two-hop host context, pre-sampling label-free activity, incoming SHM and prior-write/execute relations; no endpoint features",
        "host_context_policy": {"windows_seconds": [30, 300], "max_ancestors": 2,
                                "max_processes": session.max_processes, "max_files": session.max_files,
                                "max_history_per_kind": session.max_history,
                                "activity_time": "strictly earlier timestamp; same-time events excluded",
                                "sampling": "observe all valid source rows before labels/sampling/caps",
                                "counts": "bounded recent distinct activity timestamps; saturated buckets",
                                "late_events": "no retroactive feature changes; ignore history beyond window",
                                "socket_bit": "prior observed socket operation, not proven successful connection"},
        "event_replay": {"order": "stable event timestamp, then original CSV order",
                         "original_source_lines_preserved": True,
                         "retained_cohort": "published Run-7 row identities" if retained_source_lines is not None else "new selection",
                         "retained_rows": len(retained_source_lines) if retained_source_lines is not None else None},
        "context_window_micros": {"firefox": 30000000, "default": 300000000},
        "minimum_train_document_frequency": 2,
        "code_sha256": {str(p.relative_to(WORKSPACE_ROOT)): sha256(p) for p in
                        [Path(__file__), Path(__file__).with_name("event_replay.py"), *sorted((CODE_ROOT / "preprocess").glob("*.py")),
                         WORKSPACE_ROOT / "ML/code/preprocess/ecar_tokenizer.py"]},
        "sources_sha256": {str(p): sha256(p) for p in
                           [*sorted((data_dir / "CSV").glob("*.csv")),
                            *sorted(reapr_dir.glob("theia*"))] if p.is_file()},
    }
    out_meta = assets_dir / "vocab_metadata.json"
    out_meta.write_text(json.dumps(vocab_metadata, indent=2), encoding="utf-8")

    # 4. Pass 2: Stream and Build Shards with Undersampling
    print("\n[4/5] Pass 2: Encoding Sparse Shards (.npz) across Train, Val, Test...")
    vocab_width = len(extended_vocab)
    rows_per_shard = events_per_shard

    split_buffers: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    shard_counts: dict[str, int] = {"train": 0, "val": 0, "test": 0}
    manifest_shards: list[dict[str, Any]] = []

    splits_totals = {s: dict(rows=0, nnz=0, label_0=0, label_1=0, bytes=0) for s in ("train", "val", "test")}

    def flush_shard(sp: str, chunk_events: list[dict[str, Any]]) -> None:
        if not chunk_events:
            return
        chunk_events.sort(key=lambda item: item["source_line"])
        buf = ShardBuffer(vocab_width)
        for item in chunk_events:
            buf.append(item["columns"], item["label"], item["source_line"])

        payload, meta = buf.encode()
        shard_idx = shard_counts[sp]
        shard_rel = f"shards/{sp}/shard_{shard_idx:04d}.npz"
        shard_path = output_dir / shard_rel
        shard_path.write_bytes(payload)

        provenance_rel = f"shards/{sp}/shard_{shard_idx:04d}.provenance.npz"
        np.savez_compressed(output_dir / provenance_rel,
                            label_basis=np.asarray([x["label_basis"] for x in chunk_events]),
                            process_guid=np.asarray([x["process_guid"] for x in chunk_events]),
                            scenario=np.asarray([x["scenario"] for x in chunk_events]),
                            timestamp=np.asarray([x["timestamp"] for x in chunk_events], dtype=np.int64),
                            source_line=np.asarray([x["source_line"] for x in chunk_events], dtype=np.int64))
        manifest_shards.append({
            "provenance_path": provenance_rel,
            "provenance_sha256": sha256(output_dir / provenance_rel),
            "source_id": "theia_host_telemetry",
            "split": sp,
            "volume": "local",
            "path": shard_rel,
            "rows": meta["rows"],
            "nnz": meta["nnz"],
            "label_0": meta["label_0"],
            "label_1": meta["label_1"],
            "bytes": meta["bytes"],
            "sha256": meta["sha256"],
            "source_line_first": int(meta["source_line_first"]),
            "source_line_last": int(meta["source_line_last"]),
        })

        splits_totals[sp]["rows"] += meta["rows"]
        splits_totals[sp]["nnz"] += meta["nnz"]
        splits_totals[sp]["label_0"] += meta["label_0"]
        splits_totals[sp]["label_1"] += meta["label_1"]
        splits_totals[sp]["bytes"] += meta["bytes"]

        shard_counts[sp] += 1
        chunk_events.clear()

    session = FileSessionIndex(raw_context=raw_context, source_stream=True)
    adapter.enrichment_counts.clear()
    cohort_exclusions = Counter()
    label_basis_counts = Counter()
    split_stats = {
        s: {"attack": 0, "benign_kept": 0, "benign_skipped": 0, "total": 0}
        for s in ("train", "val", "test")
    }
    # Run 7: count NETWORK_UNKNOWN events separately per split (not included in shard rows)
    network_unknown_counts: dict[str, int] = {"train": 0, "val": 0, "test": 0}

    t1 = time.time()
    n_encoded = 0

    for event in adapter.stream_canonical_events(
        max_events=max_events, undersample_benign_ratio=target_benign_ratio,
        context_observer=session.observe_row, event_csv_path=replay_path,
        retained_source_lines=retained_source_lines,
    ):
        session.add_event(event)

        # Strictly skip FLOW_START and NETWORK_UNKNOWN rows for Host ML.
        # NETWORK_UNKNOWN: Run 7 — EVENT_CONNECT with missing/NA endpoint that cannot be classified
        # as either Unix IPC or external network flow. Skipping removes the ambiguous IPC inference
        # that produced the 500-FN /var/log/mail cohort (RUN6_RESULTS.md Section 5).
        if event.event_type in ("NETWORK_UNKNOWN", "FLOW_START"):
            cohort_exclusions[f"{get_split_from_event(event.scenario, event.timestamp)}|{event.net_endpoint_type}|label={event.label}"] += 1
        if event.event_type == "NETWORK_UNKNOWN":
            split_key = get_split_from_event(event.scenario, event.timestamp)
            network_unknown_counts[split_key] += 1
            continue
        if event.event_type == "FLOW_START":
            continue

        split = get_split_from_event(event.scenario, event.timestamp)
        label = event.label

        # Negative undersampling for high-volume background across all splits
        if label == 0:
            try:
                h_val = int(event.event_id[:8], 16)
            except (ValueError, TypeError):
                h_val = int.from_bytes(hashlib.sha256(event.event_id.encode()).digest()[:8], "big")
            if h_val % target_benign_ratio != 0:
                split_stats[split]["benign_skipped"] += 1
                continue
            split_stats[split]["benign_kept"] += 1
        else:
            split_stats[split]["attack"] += 1

        split_stats[split]["total"] += 1

        ecar_rec = canonical_ecar_record(event)
        grouped, _ = tokenize_record(ecar_rec)
        raw_tokens = flatten_tokens(grouped)
        domain_tokens = extract_domain_shift_tokens(event, session)
        event_tokens = set(raw_tokens) | set(domain_tokens)

        # Map to sparse column indices
        col_indices = sorted([extended_vocab[t] for t in event_tokens if t in extended_vocab])
        if not col_indices:
            continue
        basis = ("reapr_edge_membership" if event.event_id in refiner.attack_edge_uuids
                 else "process_heuristic" if label else "negative_or_refined_out")
        label_basis_counts[f"{split}|{basis}"] += 1
        split_buffers[split].append({"label_basis": basis, "columns": col_indices, "label": label, "source_line": event.source_line,
                                    "process_guid": event.process_guid, "scenario": event.scenario,
                                    "timestamp": event.timestamp})

        if len(split_buffers[split]) >= rows_per_shard:
            flush_shard(split, split_buffers[split])

        n_encoded += 1
        if n_encoded % 200_000 == 0:
            print(f"  Encoded {n_encoded:,} rows in {time.time()-t1:.1f}s...")

    # Flush remaining in buffers
    for sp in ("train", "val", "test"):
        if split_buffers[sp]:
            flush_shard(sp, split_buffers[sp])
        print(f"  [{sp.upper()}] Written {shard_counts[sp]} shards ({splits_totals[sp]['rows']:,} rows, {splits_totals[sp]['label_1']:,} attack).")

    # Copy host_shards.py and shard_metrics.py to output root for standalone notebook execution
    if (WORKSPACE_ROOT / "ML/code/preprocess/host_shards.py").exists():
        shutil.copy2(WORKSPACE_ROOT / "ML/code/preprocess/host_shards.py", output_dir / "host_shards.py")
    if (WORKSPACE_ROOT / "ML/code/preprocess/shard_metrics.py").exists():
        shutil.copy2(WORKSPACE_ROOT / "ML/code/preprocess/shard_metrics.py", output_dir / "shard_metrics.py")

    # 5. Build and Save Overall Manifest
    print("\n[5/5] Building Shard Manifest...")
    manifest_data = {
        "format": FORMAT,
        "schema": SCHEMA,
        "complete": max_events is None,
        "vocab_size": vocab_width,
        "base_vocab_size": n_base,
        "extended_vocab_size": vocab_width,
        "volumes": {"local": "."},
        "assets_sha256": {
            "vocab.json": sha256(out_vocab),
            "vocab_metadata.json": sha256(out_meta),
        },
        "split_sha256": split_sha,
        "vocabulary_sha256": sha256(out_vocab_ext),
        "sources": [
            {
                "source_id": "theia_host_telemetry",
                "name": "DARPA TC E3 THEIA Telemetry",
            }
        ],
        "shards": manifest_shards,
        "splits": splits_totals,
        "stats": split_stats,
        # Run 7: NETWORK_UNKNOWN events are excluded from Host ML shards.
        # These are EVENT_CONNECT rows with missing/NA destination endpoint.
        # Count preserved for cohort auditing (RUN6_RESULTS.md Section 5).
        "host_context_stats": dict(session.stats),
        "label_basis_counts": dict(label_basis_counts),
        "label_policy": "inherited REAPr edge-membership priority, then local process/IOC heuristics; not independently verified event-level truth",
        "network_unknown_skipped": network_unknown_counts,
        "network_exclusions_before_host_sampling": dict(cohort_exclusions),
        "raw_enrichment_counts_before_host_sampling": dict(adapter.enrichment_counts),
    }

    manifest_path = output_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"Saved manifest to {manifest_path}")

    print("\n" + "=" * 80)
    print("HOST ML PREPROCESSING COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    return manifest_data


def publish_output(staged: Path, output: Path) -> None:
    """Replace the fixed output after success, keeping frozen dependencies."""
    managed = {"shards", "assets", "manifest.json", "vocab_extended.json", "host_shards.py", "shard_metrics.py", "retained_cohort.npz"}
    if output.exists():
        for item in output.iterdir():
            if item.name in managed or (staged / item.name).exists():
                continue
            if item.is_symlink():
                target = item.readlink()
                (staged / item.name).symlink_to(target)
            elif item.is_dir():
                shutil.copytree(item, staged / item.name, symlinks=True)
            else:
                shutil.copy2(item, staged / item.name, follow_symlinks=False)
    backup = staged.parent / "previous"
    if output.exists():
        output.rename(backup)
    try:
        staged.rename(output)
    except BaseException:
        if backup.exists():
            backup.rename(output)
        raise


def build_host_shards(data_dir: Path, reapr_dir: Path, base_vocab_path: Path,
                      output_dir: Path, max_events: int | None = None,
                      events_per_shard: int = 50_000,
                      target_benign_ratio: int = TARGET_BENIGN_RATIO) -> dict[str, Any]:
    output = output_dir.resolve()
    protected = [data_dir.resolve(), reapr_dir.resolve(), WORKSPACE_ROOT / "DATASET"]
    if any(output == p or p in output.parents or output in p.parents for p in protected):
        raise ValueError("Output must be outside read-only dataset roots")
    if max_events is not None and (output / "manifest.json").exists():
        raise ValueError("A limited preview must not replace a published full corpus")
    output.parent.mkdir(parents=True, exist_ok=True)
    retained = freeze_cohort(output, decode_shard) if (output / "manifest.json").exists() else None
    replay_path = ordered_csv(data_dir / "CSV/event_table.csv", output.parent / "event_replay_cache")
    raw_context_path = ensure_raw_context(data_dir, output.parent / "raw_context.sqlite")
    with tempfile.TemporaryDirectory(prefix=".host-build-", dir=output.parent) as temp:
        staged = Path(temp) / "payload"
        result = _build_host_shards(data_dir, reapr_dir, base_vocab_path, staged,
                                    max_events, events_per_shard, target_benign_ratio, raw_context_path, replay_path, retained)
        actual = []
        for part in result["shards"]:
            _, y, lines = decode_shard(staged / part["path"], result["vocab_size"], part)
            actual.extend(zip(lines.tolist(), y.tolist(), [part["split"]]*len(y)))
        actual.sort()
        if retained is not None:
            expected = np.load(output / "retained_cohort.npz", allow_pickle=False)
            actual_lines = [line for line, y, sp in actual]
            reference_lines = expected["source_line"].tolist()
            if actual_lines != reference_lines:
                raise ValueError("Retained row cohort changed; publication rejected")
        lines_arr = np.array([x[0] for x in actual], dtype=np.int64)
        labels_arr = np.array([x[1] for x in actual], dtype=np.uint8)
        splits_arr = np.array([x[2] for x in actual])
        np.savez_compressed(staged / "retained_cohort.npz", source_line=lines_arr, label=labels_arr, split=splits_arr)
        publish_output(staged, output)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Host ML Shards for DARPA TC E3 THEIA")
    parser.add_argument(
        "--data-dir",
        default="/mnt/SSD_Data/optc/DATASET/DARPA-TC-E3-THEIA",
        type=Path,
        help="Path to THEIA dataset root",
    )
    parser.add_argument(
        "--reapr-dir",
        default="/mnt/SSD_Data/optc/DATASET/ATLASv2/reapr-ground-truth/darpa-tc-engagement3",
        type=Path,
        help="Path to REAPr ground truth directory",
    )
    parser.add_argument(
        "--base-vocab",
        dest="optc_vocab",
        default=Path(__file__).resolve().parent.parent / "pretrained_optc_model" / "vocab_atlasv2.json",
        type=Path,
        help="Path to base vocabulary (inherits 12,337 features from ATLASv2 incremental model)",
    )
    parser.add_argument(
        "--output-dir",
        default=Path(__file__).resolve().parent / "output",
        type=Path,
        help="Output directory for shards and manifests",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum events to process (default: all)",
    )
    parser.add_argument(
        "--events-per-shard",
        type=int,
        default=50_000,
        help="Number of events per shard (default: 50,000)",
    )
    parser.add_argument(
        "--target-benign-ratio",
        type=int,
        default=TARGET_BENIGN_RATIO,
        help="Benign sampling modulus: keep 1/N (default: 30)",
    )
    args = parser.parse_args()

    build_host_shards(
        data_dir=args.data_dir,
        reapr_dir=args.reapr_dir,
        base_vocab_path=args.optc_vocab,
        output_dir=args.output_dir,
        max_events=args.max_events,
        events_per_shard=args.events_per_shard,
        target_benign_ratio=args.target_benign_ratio,
    )


if __name__ == "__main__":
    main()
