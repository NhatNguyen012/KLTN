#!/usr/bin/env python3
"""Build Causal Triplet Shards (L=3) for ATLASv2 Domain-Incremental Learning.

Transforms raw CBC-EDR JSONL telemetry into causal sequences:
  - Line 0: E_incoming token bag (Incoming network flows, payload drops, cross-process access)
  - Line 1: E_parent   token bag (Parent process lineage, directory, command switches, user)
  - Line 2: E_current  token bag (Current event type, actor, target object, command semantics)

Labels:
  - is_malicious: int (0: Benign, 1: Attack) via Two-Tier LabelRefiner
  - scenario_id:  int (0: Benign, 1: Single-Host S1-S4, 2: Multi-Host M1-M6)
  - stage_id:     int (0: Benign, 1: Initial_Compromise, 2: Execution_Discovery,
                       3: Lateral_Movement, 4: Exfiltration)

Vocab:
  - Extends OpTC base dl_vocab.json (10,496 tokens) with ATLASv2 TRAIN tokens.
  - Generates 100% compatible PyTorch shards (.pt) and split_manifest.json.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import resource
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import torch

# Path resolution
CURRENT_DIR = Path(__file__).resolve().parent
CODE_DIR = CURRENT_DIR.parent  # /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code
IL_ROOT = CURRENT_DIR.parents[1]  # /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2
PROJECT_ROOT = CURRENT_DIR.parents[3]  # /mnt/SSD_Data/optc

for p in (
    CODE_DIR,
    CURRENT_DIR,
    PROJECT_ROOT / "DL" / "code" / "preprocess",
):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from preprocess.common_schema import (
    CanonicalEvent,
    INITIAL_ATTACK_TIMESTAMPS,
    KNOWN_IOCS,
    extract_basename,
    classify_image_dir,
    classify_principal,
    parse_timestamp_micros,
)
from preprocess.label_refiner import LabelRefiner
from preprocess.cbc_adapter import CBCAdapter
from preprocess.split_config import (
    TRAIN_SCENARIOS,
    VAL_SCENARIOS,
    TEST_SCENARIOS,
)


# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

class FlushingStreamHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("build_atlasv2_causal_shards")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    ch = FlushingStreamHandler(sys.stdout)
    ch.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(ch)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except Exception:
            pass
    return logger


logger = setup_logger()


def get_rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


# ---------------------------------------------------------------------------
# Semantic Tokenization Constants & Helpers
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    20: "FTP_DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 139: "NETBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRES", 5985: "WINRM_HTTP", 5986: "WINRM_HTTPS",
    8000: "HTTP_ALT", 8080: "HTTP_ALT", 8443: "HTTPS_ALT", 9999: "METERPRETER_C2",
}

CMD_FLAGS = [
    ("enc", re.compile(r"\s-(e|ec|en|enc|enco|encodedcommand)\s", re.I)),
    ("hidden", re.compile(r"(-w(indowstyle)?\s+h(idden)?\b)", re.I)),
    ("bypass", re.compile(r"(-nop\b|-noprofile|bypass|-noni\b|-noninteractive)", re.I)),
    ("url", re.compile(r"https?://", re.I)),
    ("script", re.compile(r"\.(ps1|vbs|js|hta|sct|bat|cmd)\b", re.I)),
    ("download", re.compile(r"(downloadstring|downloadfile|invoke-|iex\b|webclient|bitsadmin|certutil)", re.I)),
    ("regsvr", re.compile(r"(/i:|scrobj|/s\s)", re.I)),
    ("cmd_c", re.compile(r"\s/c\s", re.I)),
]


def port_class(p: int) -> str:
    if p in COMMON_PORTS:
        return f"PORT_{p}_{COMMON_PORTS[p]}"
    if 0 <= p <= 1023:
        return "WELL_KNOWN_OTHER"
    if 1024 <= p <= 49151:
        return "REGISTERED"
    if 49152 <= p <= 65535:
        return "EPHEMERAL"
    return "OTHER"


def ip_scope(ip: str) -> str:
    if not ip:
        return "NONE"
    if ":" in ip:
        return "IPV6"
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return "BAD"
        a, b, c, _ = parts
    except ValueError:
        return "BAD"
    if a == 127:
        return "LOOPBACK"
    if a == 192 and b == 168 and c == 223:
        return "LOCAL_SUBNET"
    if a == 10:
        return "PRIV_10"
    if (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return "PRIV_OTHER"
    if a == 169 and b == 254:
        return "LINK_LOCAL"
    if a >= 224 or ip == "255.255.255.255":
        return "MULTICAST"
    if a == 0:
        return "ZERO"
    return "EXTERNAL"


def file_ext_class(name: str) -> str:
    n = name.lower()
    for cls, exts in (
        ("EXE", (".exe",)),
        ("DLL", (".dll",)),
        ("SCRIPT", (".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sct")),
        ("ARCHIVE", (".zip", ".rar", ".7z", ".tar", ".gz")),
        ("DOC", (".doc", ".docx", ".xls", ".xlsx", ".rtf", ".pdf")),
        ("HTML", (".html", ".htm")),
    ):
        if n.endswith(exts):
            return cls
    return "OTHER"


def extract_cmd_tokens(cmd: str) -> List[str]:
    if not cmd:
        return []
    toks = []
    c = f" {cmd} "
    for name, rx in CMD_FLAGS:
        if rx.search(c):
            toks.append(f"cmd::flag={name}")
    if len(cmd) > 256:
        toks.append("cmd::flag=long")
    return toks


# ---------------------------------------------------------------------------
# Causal Context Tracker for CBC-EDR Events
# ---------------------------------------------------------------------------

class AtlasCausalContextTracker:
    """Maintains past-only bounded causal context for processes and hosts.

    Tracks:
      1. Process parent-child lineage (Parent image, dir, cmdline, principal)
      2. Incoming network flows, payload file writes, and cross-process accesses
    """

    def __init__(self, max_history_per_proc: int = 10):
        self.max_history = max_history_per_proc
        # guid -> dict of process attributes
        self.procs: Dict[str, Dict[str, Any]] = {}
        # guid -> list of incoming trigger tokens
        self.incoming: Dict[str, List[str]] = defaultdict(list)

    def register_process_start(self, event: CanonicalEvent):
        guid = event.process_guid.lower().strip()
        pguid = event.parent_guid.lower().strip()
        actor = extract_basename(event.process_path) or "<none>"
        parent = extract_basename(event.parent_path) or "<none>"
        actor_dir = classify_image_dir(event.process_path)
        parent_dir = classify_image_dir(event.parent_path)
        user_cls = classify_principal(event.username)

        parent_cmd_toks = extract_cmd_tokens(event.parent_cmdline)

        self.procs[guid] = {
            "actor": actor,
            "actor_dir": actor_dir,
            "parent": parent,
            "parent_dir": parent_dir,
            "pguid": pguid,
            "user_cls": user_cls,
            "parent_cmd_toks": parent_cmd_toks,
        }

    def register_event(self, event: CanonicalEvent):
        guid = event.process_guid.lower().strip()
        et = event.event_type

        # Track incoming network connection (e.g. C2 or external inbound/outbound)
        if et == "FLOW_START":
            pr = event.proto.lower()
            scope = ip_scope(event.remote_ip)
            pclass = port_class(event.remote_port if not event.inbound else event.local_port)
            toks = [
                f"incoming::flow::proto={pr}",
                f"incoming::flow::port_class={pclass}",
                f"incoming::flow::ip_scope={scope}",
            ]
            self._add_incoming(guid, toks)

        # Track payload file writes/creations
        elif et in ("FILE_CREATE", "FILE_WRITE"):
            fext = file_ext_class(event.target_path)
            fdir = classify_image_dir(event.target_path)
            if fext in ("EXE", "DLL", "SCRIPT", "ARCHIVE", "DOC"):
                toks = [
                    f"incoming::file::action={et}",
                    f"incoming::file::ext={fext}",
                    f"incoming::file::dir={fdir}",
                ]
                self._add_incoming(guid, toks)

        # Track cross-process touches
        elif et == "CROSS_PROCESS":
            target_guid = event.target_guid.lower().strip()
            actor = extract_basename(event.process_path) or "<none>"
            toks = [
                f"incoming::crossproc::source={actor}",
                f"incoming::crossproc::action={event.target_path or 'ACCESS'}",
            ]
            if target_guid:
                self._add_incoming(target_guid, toks)

    def _add_incoming(self, guid: str, tokens: List[str]):
        if not guid:
            return
        inc_list = self.incoming[guid]
        for t in tokens:
            if t not in inc_list:
                inc_list.append(t)
        if len(inc_list) > self.max_history:
            self.incoming[guid] = inc_list[-self.max_history:]

    def get_causal_lines(self, event: CanonicalEvent) -> Tuple[List[str], List[str], List[str]]:
        guid = event.process_guid.lower().strip()
        proc_info = self.procs.get(guid)

        # ---------------- Line 0: E_incoming ----------------
        inc_toks = list(self.incoming.get(guid, []))
        if not inc_toks:
            inc_toks = ["<none>"]

        # ---------------- Line 1: E_parent ------------------
        parent_toks: List[str] = []
        if proc_info:
            parent_toks.append(f"parent::name={proc_info['parent']}")
            parent_toks.append(f"parent::dir={proc_info['parent_dir']}")
            parent_toks.append(f"user::class={proc_info['user_cls']}")
            for ct in proc_info["parent_cmd_toks"]:
                parent_toks.append(f"parent::{ct}")
        else:
            parent_name = extract_basename(event.parent_path) or "<none>"
            parent_dir = classify_image_dir(event.parent_path)
            user_cls = classify_principal(event.username)
            parent_toks.append(f"parent::name={parent_name}")
            parent_toks.append(f"parent::dir={parent_dir}")
            parent_toks.append(f"user::class={user_cls}")

        if not parent_toks:
            parent_toks = ["<none>"]

        # ---------------- Line 2: E_current -----------------
        curr_toks: List[str] = []
        actor = extract_basename(event.process_path) or "<none>"
        actor_dir = classify_image_dir(event.process_path)
        curr_toks.append(f"event::type={event.event_type}")
        curr_toks.append(f"actor::name={actor}")
        curr_toks.append(f"actor::dir={actor_dir}")

        et = event.event_type
        if et == "FLOW_START":
            pr = event.proto.lower()
            scope = ip_scope(event.remote_ip)
            pclass = port_class(event.remote_port if not event.inbound else event.local_port)
            curr_toks.append(f"net::proto={pr}")
            curr_toks.append(f"net::port_class={pclass}")
            curr_toks.append(f"net::ip_scope={scope}")
        elif et in ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE"):
            fext = file_ext_class(event.target_path)
            fdir = classify_image_dir(event.target_path)
            curr_toks.append(f"target::file_ext={fext}")
            curr_toks.append(f"target::dir={fdir}")
        elif et == "CROSS_PROCESS":
            target_proc = extract_basename(event.target_path) or "<none>"
            curr_toks.append(f"target::proc={target_proc}")
        elif et == "MODULE_LOAD":
            target_mod = extract_basename(event.target_path) or "<none>"
            curr_toks.append(f"target::module={target_mod}")
        elif et == "REGISTRY_WRITE":
            curr_toks.append("target::reg=write")

        # Command flags for current process
        for ct in extract_cmd_tokens(event.process_cmdline):
            curr_toks.append(ct)

        return inc_toks, parent_toks, curr_toks


# ---------------------------------------------------------------------------
# Shard Writer with Atomic Publication
# ---------------------------------------------------------------------------

class ShardWriter:
    """Buffers samples per split and writes compressed .pt shards upon capacity."""

    def __init__(self, out_dir: Path, shard_size: int = 10_000):
        self.out_dir = out_dir
        self.shard_size = shard_size
        self.buffers: Dict[str, List[Dict[str, Any]]] = {
            "train": [],
            "val": [],
            "test": [],
        }
        self.shard_counts: Dict[str, int] = {"train": 0, "val": 0, "test": 0}
        self.total_samples: Dict[str, int] = {"train": 0, "val": 0, "test": 0}
        self.manifest_shards: Dict[str, List[str]] = {
            "train": [],
            "val": [],
            "test": [],
        }

        for s in ("train", "val", "test"):
            (self.out_dir / s).mkdir(parents=True, exist_ok=True)

    def add(self, split_name: str, sample: Dict[str, Any]):
        buf = self.buffers[split_name]
        buf.append(sample)
        self.total_samples[split_name] += 1

        if len(buf) >= self.shard_size:
            self._flush(split_name)

    def _flush(self, split_name: str):
        buf = self.buffers[split_name]
        if not buf:
            return

        shard_num = self.shard_counts[split_name]
        shard_path = self.out_dir / split_name / f"shard_{shard_num:04d}.pt"
        rel_path = f"{split_name}/shard_{shard_num:04d}.pt"

        fd, tmp = tempfile.mkstemp(dir=shard_path.parent, suffix=".tmp.pt")
        os.close(fd)
        try:
            torch.save(buf, tmp)
            os.replace(tmp, shard_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

        self.manifest_shards[split_name].append(rel_path)
        self.shard_counts[split_name] += 1
        self.buffers[split_name] = []

    def flush_all(self):
        for s in ("train", "val", "test"):
            self._flush(s)


def get_split_from_event(scenario: str, timestamp_micros: int) -> str:
    """Determine train/val/test split partition from scenario or timestamp date."""
    sc = scenario.lower().strip()
    for s in TRAIN_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "train"
    for s in VAL_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "val"
    for s in TEST_SCENARIOS:
        if s == sc or f"-{s}" in sc:
            return "test"

    dt = datetime.fromtimestamp(timestamp_micros / 1_000_000, tz=timezone.utc)
    day_str = dt.strftime("%Y-%m-%d")
    if day_str <= "2022-07-16":
        return "train"
    elif day_str == "2022-07-17":
        return "val"
    elif day_str == "2022-07-18":
        return "test"
    else:
        return "train"


def scenario_to_id(sc: str) -> int:
    """Map scenario name to multi-task scenario ID."""
    s = sc.lower().strip()
    if not s or "benign" in s:
        return 0
    if s.startswith("s"):
        return 1  # Single-host scenario (S1-S4)
    if s.startswith("m"):
        return 2  # Multi-host scenario (M1-M6)
    return 1


# ---------------------------------------------------------------------------
# Main Pipeline
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Build ATLASv2 Causal Triplet Shards (L=3) for Domain-Incremental Learning"
    )
    parser.add_argument(
        "--data-dir",
        default=str(IL_ROOT / "output" / "raw_cbc" / "atlasv2" / "data"),
        help="Path to directory containing CBC-EDR JSONL files",
    )
    parser.add_argument(
        "--reapr-dir",
        default=str(PROJECT_ROOT / "DATASET" / "ATLASv2_staged" / "reapr-ground-truth" / "atlasv2"),
        help="Path to REAPr staged ground truth directory (*.labels, *.seeds)",
    )
    parser.add_argument(
        "--base-vocab",
        default=str(PROJECT_ROOT / "DL" / "code" / "output" / "dl_vocab.json"),
        help="Path to base OpTC dl_vocab.json (10,496 tokens)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(IL_ROOT / "output" / "dl_shards"),
        help="Path to output dl_shards directory",
    )
    parser.add_argument(
        "--shard-size",
        type=int,
        default=10_000,
        help="Number of samples per shard file",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="Optional max events limit for testing (0 = full)",
    )

    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    reapr_dir = Path(args.reapr_dir)
    base_vocab_path = Path(args.base_vocab)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 78)
    logger.info("BUILD ATLASv2 CAUSAL TRIPLET SHARDS (L=3)")
    logger.info("=" * 78)
    logger.info(f"Data directory:    {data_dir}")
    logger.info(f"REAPr directory:   {reapr_dir}")
    logger.info(f"Base Vocab path:   {base_vocab_path}")
    logger.info(f"Output directory:  {out_dir}")
    logger.info(f"Shard size:        {args.shard_size}")

    # 1. Load Base OpTC Vocabulary
    logger.info("\n[1/5] Loading Base OpTC Vocabulary...")
    with open(base_vocab_path, "r", encoding="utf-8") as f:
        base_vocab: Dict[str, int] = json.load(f)
    logger.info(f"  Loaded {len(base_vocab):,} base OpTC tokens.")

    # In CausalTripletDataset, tokens 0=<pad>, 1=<unk>, 2=<none> are reserved.
    # Base vocab IDs map to token_id = raw_id + 3.
    # New ATLASv2 tokens will start at len(base_vocab) + 3.
    tok2id: Dict[str, int] = {"<pad>": 0, "<unk>": 1, "<none>": 2, "incoming::status=none": 2}
    for tok, raw_id in base_vocab.items():
        tok2id[tok] = raw_id + 3

    # 2. Discover CBC-EDR Files
    logger.info("\n[2/5] Discovering CBC-EDR Files...")
    all_files = sorted(list(data_dir.rglob("*.jsonl")))
    edr_files = [f for f in all_files if "cbc-edr" in str(f) and "alerts" not in str(f)]
    logger.info(f"  Found {len(edr_files)} raw CBC-EDR telemetry files.")
    for f in edr_files:
        logger.info(f"    - {f.name} ({f.stat().st_size / (1024*1024):.1f} MB)")

    # 3. Initialize Ground Truth Label Refiner & Tracker
    logger.info("\n[3/5] Initializing Ground Truth Label Refiner...")
    refiner = LabelRefiner(reapr_dir)
    adapter = CBCAdapter(refiner)
    logger.info(f"  Scenarios mapped: {len(refiner.scenario_attack_guids)}")

    # Pass 1: Build extended vocabulary on TRAIN events (min_count >= 2)
    logger.info("\n[4/5] Scanning TRAIN partition to extend vocabulary with ATLASv2 tokens...")
    train_token_counts: Counter[str] = Counter()
    t_vocab_start = time.time()
    train_scan_events = 0

    for f in edr_files:
        # Determine file scenario
        stem = f.stem.lower()
        parts = stem.split("-")
        sc = parts[-1] if len(parts) >= 3 else stem
        # Only scan if file contributes to train
        for line in f.open("r", encoding="utf-8", errors="replace"):
            try:
                raw = json.loads(line)
            except Exception:
                continue
            ev = adapter.parse_record(raw, sc)
            if ev is None:
                continue
            split = get_split_from_event(sc, ev.timestamp)
            if split != "train":
                continue

            train_scan_events += 1
            # Track proc starts
            if ev.event_type == "PROCESS_START":
                pass
            # Collect potential tokens
            # Line 1 parent tokens
            p_name = extract_basename(ev.parent_path) or "<none>"
            p_dir = classify_image_dir(ev.parent_path)
            u_cls = classify_principal(ev.username)
            train_token_counts[f"parent::name={p_name}"] += 1
            train_token_counts[f"parent::dir={p_dir}"] += 1
            train_token_counts[f"user::class={u_cls}"] += 1
            for ct in extract_cmd_tokens(ev.parent_cmdline):
                train_token_counts[f"parent::{ct}"] += 1

            # Line 2 current tokens
            a_name = extract_basename(ev.process_path) or "<none>"
            a_dir = classify_image_dir(ev.process_path)
            train_token_counts[f"event::type={ev.event_type}"] += 1
            train_token_counts[f"actor::name={a_name}"] += 1
            train_token_counts[f"actor::dir={a_dir}"] += 1
            for ct in extract_cmd_tokens(ev.process_cmdline):
                train_token_counts[ct] += 1

            if ev.event_type == "FLOW_START":
                pr = ev.proto.lower()
                scope = ip_scope(ev.remote_ip)
                pclass = port_class(ev.remote_port if not ev.inbound else ev.local_port)
                train_token_counts[f"incoming::flow::proto={pr}"] += 1
                train_token_counts[f"incoming::flow::port_class={pclass}"] += 1
                train_token_counts[f"incoming::flow::ip_scope={scope}"] += 1
                train_token_counts[f"net::proto={pr}"] += 1
                train_token_counts[f"net::port_class={pclass}"] += 1
                train_token_counts[f"net::ip_scope={scope}"] += 1
            elif ev.event_type in ("FILE_CREATE", "FILE_WRITE", "FILE_DELETE"):
                fext = file_ext_class(ev.target_path)
                fdir = classify_image_dir(ev.target_path)
                train_token_counts[f"incoming::file::action={ev.event_type}"] += 1
                train_token_counts[f"incoming::file::ext={fext}"] += 1
                train_token_counts[f"incoming::file::dir={fdir}"] += 1
                train_token_counts[f"target::file_ext={fext}"] += 1
                train_token_counts[f"target::dir={fdir}"] += 1
            elif ev.event_type == "CROSS_PROCESS":
                target_proc = extract_basename(ev.target_path) or "<none>"
                train_token_counts[f"incoming::crossproc::source={a_name}"] += 1
                train_token_counts[f"target::proc={target_proc}"] += 1
            elif ev.event_type == "MODULE_LOAD":
                target_mod = extract_basename(ev.target_path) or "<none>"
                train_token_counts[f"target::module={target_mod}"] += 1

            if args.max_events and train_scan_events >= args.max_events:
                break
        if args.max_events and train_scan_events >= args.max_events:
            break

    # Add tokens with min_count >= 2
    new_tokens_added = 0
    start_id = len(tok2id)
    for tok, cnt in sorted(train_token_counts.items(), key=lambda x: (-x[1], x[0])):
        if cnt >= 2 and tok not in tok2id:
            tok2id[tok] = len(tok2id)
            new_tokens_added += 1

    logger.info(
        f"  TRAIN scan completed in {time.time() - t_vocab_start:.1f}s. "
        f"Scanned {train_scan_events:,} events."
    )
    logger.info(
        f"  New ATLASv2 tokens added: {new_tokens_added:,}. Total Vocab Size: {len(tok2id):,}"
    )

    # Save extended vocab
    atlas_vocab_path = out_dir / "atlasv2_vocab.json"
    with open(atlas_vocab_path, "w", encoding="utf-8") as f:
        # Save mapping from string -> id - 3 (raw index offset)
        raw_export = {t: idx - 3 for t, idx in tok2id.items() if idx >= 3}
        json.dump(raw_export, f, indent=2)
    logger.info(f"  Persisted extended vocab to {atlas_vocab_path}")

    # Pass 2: Generate Shards
    logger.info("\n[5/5] Generating Shards across Train / Val / Test...")
    writer = ShardWriter(out_dir, shard_size=args.shard_size)
    tracker = AtlasCausalContextTracker(max_history_per_proc=10)

    total_events = 0
    split_counts: Counter[str] = Counter()
    malicious_counts: Counter[str] = Counter()
    stage_counts: Counter[Tuple[str, int]] = Counter()
    scenario_counts: Counter[Tuple[str, int]] = Counter()

    t_shards_start = time.time()

    for file_idx, f in enumerate(edr_files, 1):
        stem = f.stem.lower()
        parts = stem.split("-")
        sc = parts[-1] if len(parts) >= 3 else stem
        f_events = 0
        t_file_start = time.time()

        for line in f.open("r", encoding="utf-8", errors="replace"):
            try:
                raw = json.loads(line)
            except Exception:
                continue

            ev = adapter.parse_record(raw, sc)
            if ev is None:
                continue

            split_name = get_split_from_event(sc, ev.timestamp)

            # Update causal context tracker
            if ev.event_type == "PROCESS_START":
                tracker.register_process_start(ev)
            tracker.register_event(ev)

            # Get 3 causal lines
            inc_toks, parent_toks, curr_toks = tracker.get_causal_lines(ev)

            # Map tokens to IDs (padding/unknown safe)
            inc_ids = [tok2id.get(t, 1) for t in inc_toks] or [2]
            parent_ids = [tok2id.get(t, 1) for t in parent_toks] or [2]
            curr_ids = [tok2id.get(t, 1) for t in curr_toks] or [2]

            # Resolve labels
            is_mal = int(refiner.is_event_malicious(ev))
            sc_id = scenario_to_id(sc)
            st_id = refiner.get_event_stage_id(ev)

            sample = {
                "incoming_ids": inc_ids,
                "parent_ids": parent_ids,
                "current_ids": curr_ids,
                "is_malicious": is_mal,
                "scenario_id": sc_id,
                "stage_id": st_id,
            }

            writer.add(split_name, sample)

            total_events += 1
            f_events += 1
            split_counts[split_name] += 1
            if is_mal:
                malicious_counts[split_name] += 1
            stage_counts[(split_name, st_id)] += 1
            scenario_counts[(split_name, sc_id)] += 1

            if total_events % 100_000 == 0:
                el = time.time() - t_shards_start
                logger.info(
                    f"  [Progress] {total_events:,} events processed "
                    f"in {el:.1f}s ({total_events/max(el, 1):.0f} ev/s) | RSS: {get_rss_mb():.1f} MB"
                )

            if args.max_events and total_events >= args.max_events:
                break
        el_file = time.time() - t_file_start
        logger.info(f"  [{file_idx}/{len(edr_files)}] Finished {f.name}: {f_events:,} events in {el_file:.1f}s")
        if args.max_events and total_events >= args.max_events:
            logger.info("Reached max_events limit. Stopping.")
            break

    # Flush remaining samples
    writer.flush_all()
    total_time = time.time() - t_shards_start
    logger.info(f"\nAll shards generated in {total_time:.1f}s! Total events: {total_events:,}")

    # Build split manifest
    manifest = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "ATLASv2",
        "total_events": total_events,
        "shard_size": args.shard_size,
        "total_vocab_size": len(tok2id),
        "base_vocab_size": len(base_vocab),
        "new_tokens_added": new_tokens_added,
        "split_summary": {
            s: {
                "total_samples": split_counts[s],
                "malicious_samples": malicious_counts[s],
                "benign_samples": split_counts[s] - malicious_counts[s],
                "malicious_ratio": malicious_counts[s] / max(1, split_counts[s]),
                "num_shards": writer.shard_counts[s],
            }
            for s in ("train", "val", "test")
        },
        "stage_distribution": {
            f"{s}_stage_{st}": count for (s, st), count in sorted(stage_counts.items())
        },
        "scenario_distribution": {
            f"{s}_sc_{sc}": count for (s, sc), count in sorted(scenario_counts.items())
        },
        "shards": writer.manifest_shards,
    }

    manifest_path = out_dir / "split_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Saved manifest to {manifest_path}")
    logger.info("=" * 78)
    logger.info("SUMMARY:")
    for s in ("train", "val", "test"):
        summary = manifest["split_summary"][s]
        logger.info(
            f"  {s.upper():5s}: {summary['total_samples']:,} samples | "
            f"{summary['malicious_samples']:,} attack ({summary['malicious_ratio']*100:.2f}%) | "
            f"{summary['num_shards']} shards"
        )
    logger.info("=" * 78)


if __name__ == "__main__":
    main()
