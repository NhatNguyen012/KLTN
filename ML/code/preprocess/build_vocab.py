#!/usr/bin/env python3
"""Build a Host-ML vocabulary from both classes of a persisted TRAIN split.

Use --split with build_split.py's manifest for supervised 75/10/15 preprocessing.
Only assigned TRAIN events contribute TF/DF; validation/test never add columns.
Automatic per-file checkpoints support this full-scan path.

The explicit --roots/--fit-purpose path is retained for historical benign-only
experiments and tests. It is not the current supervised workflow.
Source datasets are read-only; publication is atomic per JSON with pair checksum.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ML.code.preprocess.ecar_tokenizer import GROUPS, HOST_OBJECTS, TOKENIZER_POLICY, token_layers, tokenize_record
from ML.code.preprocess.pipeline_contract import TRAIN_BENIGN_DAYS, code_hashes, sync_directory, validate_fit_input_path, validate_output_path

try:
    import orjson
except ImportError:
    orjson = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENIGN_DAYS = frozenset(f"2019-09-{day:02d}" for day in range(16, 23))
FILE_PATTERN = re.compile(
    r"(?:^|\.)ecar-(?P<day>\d{4}-\d{2}-\d{2})-"
    r"(?P<host>sysclient\d+)(?:[._-].*)?\.json\.gz$", re.IGNORECASE,
)
DAY_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")
ALLOWED_OBJECTS = frozenset(name.upper() for name in HOST_OBJECTS)
CHECKPOINT_SCHEMA_VERSION = 1
SCAN_LOGIC_VERSION = 1
VOCABULARY_LAYERS = ("structure", "semantic", "anchor", "syntax", "context", "lexical")


@dataclass(frozen=True)
class HostDay:
    day: str
    host: str
    files: tuple[Path, ...]


def discover_files(roots: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for root in roots:
        validate_fit_input_path(root)
        if not root.is_dir():
            raise FileNotFoundError(f"dataset root does not exist: {root}")
        files.update(validate_fit_input_path(path) for path in root.rglob("*.json.gz") if path.is_file())
    return sorted(files)


def discover_host_days(roots: Iterable[Path], days: Iterable[str] | None = None) -> list[HostDay]:
    """Group shards by SOURCE partition day, not UTC calendar day."""
    selected_days = set(days) if days is not None else None
    if selected_days is not None and not selected_days <= BENIGN_DAYS:
        raise ValueError("--days must be benign OpTC partitions: 2019-09-16 through 2019-09-22")
    groups: dict[tuple[str, str], list[Path]] = {}
    for path in discover_files(roots):
        match = FILE_PATTERN.search(path.name)
        if not match:
            raise ValueError(f"cannot identify host/day from filename: {path}")
        day, host = match["day"], match["host"].lower()
        date.fromisoformat(day)
        if day not in BENIGN_DAYS:
            raise ValueError(f"non-benign partition {day}: {path}; use host-begnin only")
        ancestor_days = {part for part in path.parts[:-1] if DAY_PATTERN.fullmatch(part)}
        if ancestor_days and ancestor_days != {day}:
            raise ValueError(f"filename day {day} disagrees with directory day: {path}")
        if selected_days is None or day in selected_days:
            groups.setdefault((day, host), []).append(path)
    return [HostDay(day, host, tuple(sorted(paths)))
            for (day, host), paths in sorted(groups.items())]


def _new_group_counters() -> dict[str, Counter[str]]:
    return {group: Counter() for group in GROUPS}


def _stable_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _group_identity(group: HostDay) -> dict[str, Any]:
    """Cheaply identify immutable source inputs without re-reading multi-GB gzip files."""
    files = []
    for path in group.files:
        stat = path.stat()
        files.append({"path": str(path.resolve()), "size": stat.st_size,
                      "mtime_ns": stat.st_mtime_ns})
    return {"day": group.day, "host": group.host, "files": files}


def _scan_signature(line_budget: int | None, source_hashes: dict[str, str]) -> str:
    """Identify every code/config input that can change one host/day result."""
    return _stable_digest({
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "scan_logic_version": SCAN_LOGIC_VERSION,
        "line_budget": line_budget,
        "source_sha256": source_hashes,
        "python": list(sys.version_info[:3]),
    })


def _checkpoint_path(checkpoint_run_dir: Path, group: HostDay,
                     group_signature: str) -> Path:
    return checkpoint_run_dir / f"{group.day}__{group.host}__{group_signature}.json.gz"


def _write_checkpoint(path: Path, scan_signature: str, group_signature: str,
                      result: dict[str, Any]) -> None:
    """Atomically publish one complete host/day result and make it power-loss durable."""
    path = validate_output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    validate_output_path(temporary)
    payload = {
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "scan_signature": scan_signature,
        "group_signature": group_signature,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "result": result,
    }
    try:
        with gzip.open(temporary, "wt", encoding="utf-8", compresslevel=1) as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Some filesystems do not support syncing directory descriptors.
            pass
    finally:
        temporary.unlink(missing_ok=True)


def _valid_counter_mapping(value: Any) -> bool:
    return (isinstance(value, dict)
            and all(isinstance(token, str) and type(count) is int and count >= 0
                    for token, count in value.items()))


def _validate_checkpoint_result(result: Any, group: HostDay) -> bool:
    if not isinstance(result, dict):
        return False
    for name in ("term_frequency", "document_frequency"):
        counters = result.get(name)
        if not isinstance(counters, dict) or set(counters) != set(GROUPS):
            return False
        if not all(_valid_counter_mapping(counters[group_name]) for group_name in GROUPS):
            return False
    stats = result.get("stats")
    if not isinstance(stats, dict) or not all(_valid_counter_mapping(value)
                                               for value in stats.values()):
        return False
    summary = result.get("host_day")
    return (isinstance(summary, dict) and summary.get("day") == group.day
            and summary.get("host") == group.host
            and all(type(summary.get(name)) is int and summary[name] >= 0 for name in (
                "lines_read", "records", "host_records", "command_records", "blank_lines")))


def _load_checkpoint(path: Path, scan_signature: str, group_signature: str,
                     group: HostDay) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        if (not isinstance(payload, dict)
                or payload.get("checkpoint_schema_version") != CHECKPOINT_SCHEMA_VERSION
                or payload.get("scan_signature") != scan_signature
                or payload.get("group_signature") != group_signature
                or not _validate_checkpoint_result(payload.get("result"), group)):
            raise ValueError("schema, signature, or result validation failed")
        return payload["result"]
    except (OSError, EOFError, UnicodeError, ValueError, TypeError) as exc:
        print(f"Ignoring invalid checkpoint {path}: {exc}", file=sys.stderr, flush=True)
        return None


def _cleanup_checkpoint_run(checkpoint_run_dir: Path) -> None:
    """Remove only files owned by this signature-specific checkpoint run."""
    if not checkpoint_run_dir.is_dir():
        return
    for path in checkpoint_run_dir.iterdir():
        if path.is_file() and (path.name.endswith(".json.gz") or path.name.endswith(".tmp")):
            path.unlink(missing_ok=True)
    try:
        checkpoint_run_dir.rmdir()
        checkpoint_run_dir.parent.rmdir()
    except OSError:
        # Preserve unexpected/concurrent files and non-empty shared parents.
        pass


def _read_prefix(path: Path, quota: int | None, host: str, consume: Any) -> dict[str, Any]:
    summary = {"path": str(path), "line_budget": quota, "lines_read": 0,
               "blank_lines": 0, "records": 0, "eof_observed": False}
    loads = orjson.loads if orjson is not None else json.loads
    try:
        with gzip.open(path, "rb") as handle:
            line_number = 0
            while quota is None or line_number < quota:
                line = handle.readline()
                if not line:
                    summary["eof_observed"] = True
                    break
                line_number += 1
                summary["lines_read"] += 1
                if not line.strip():
                    summary["blank_lines"] += 1
                    continue
                try:
                    record = loads(line)
                except (ValueError, UnicodeError) as exc:
                    raise ValueError(f"{path}:{line_number}: invalid JSON/encoding") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"{path}:{line_number}: expected an event object")
                record_host = record.get("hostname")
                if record_host is not None:
                    if not isinstance(record_host, str) or record_host.split(".", 1)[0].casefold() != host:
                        raise ValueError(f"{path}:{line_number}: hostname disagrees with filename host {host}")
                summary["records"] += 1
                consume(record)
    except (OSError, EOFError, UnicodeError) as exc:
        raise RuntimeError(f"cannot read {path} near source line {summary['lines_read']}: {exc}") from exc
    return summary


def _scan_host_day(group: HostDay, line_budget: int | None, progress_every: int = 0) -> dict[str, Any]:
    tf, df = _new_group_counters(), _new_group_counters()
    stats = {name: Counter() for name in (
        "objects_read", "objects_tokenized", "actions_tokenized", "labels_read",
        "command_families", "powershell_decode", "parser_status", "filtered_tokens", "excluded_records",
    )}
    host_records = command_records = records = 0

    def consume(record: dict[str, Any]) -> None:
        nonlocal host_records, command_records, records
        records += 1
        if progress_every and records % progress_every == 0:
            print(f"reading {group.day}/{group.host}: {records:,} JSON records; "
                  f"{host_records:,} Host records retained", file=sys.stderr, flush=True)
        object_type = record.get("object")
        object_type = object_type.strip().upper() if isinstance(object_type, str) else "<missing_or_invalid>"
        stats["objects_read"][object_type] += 1
        label = record.get("label")
        if label is None:
            stats["labels_read"]["missing"] += 1
        elif type(label) is int and label in (0, 1):
            stats["labels_read"][str(label)] += 1
            if label == 1:
                stats["excluded_records"]["label_1"] += 1
                return
        else:
            raise ValueError(f"{group.day}/{group.host}, record {records}: label must be integer 0/1 or absent/null")
        # FLOW does not enter any lexical/parser work.
        if object_type not in ALLOWED_OBJECTS:
            stats["excluded_records"]["network_flow" if object_type == "FLOW" else "unsupported_object"] += 1
            return
        grouped, audit = tokenize_record(record)
        if not audit["eligible"]:
            stats["excluded_records"][audit["excluded_reason"] or "tokenizer_excluded"] += 1
            return
        host_records += 1
        stats["objects_tokenized"][object_type] += 1
        action = record.get("action")
        stats["actions_tokenized"][action.upper() if isinstance(action, str) else "<missing>"] += 1
        for name in GROUPS:
            tokens = grouped[name]
            if tokens:
                tf[name].update(tokens)
                df[name].update(set(tokens))
        if audit["command_family"]:
            command_records += 1
            stats["command_families"][audit["command_family"]] += 1
        stats["powershell_decode"].update(audit["decode_status"])
        stats["parser_status"].update(audit.get("parse_status", {}))
        stats["filtered_tokens"].update(audit.get("filtered_tokens", {}))

    remaining = line_budget
    file_summaries = []
    for index, path in enumerate(group.files):
        if line_budget is not None and remaining <= 0:
            break
        # Split quota across sorted shards, carry unused short-shard quota forward.
        if line_budget is None:
            quota = None
        else:
            files_left = len(group.files) - index
            quota = (remaining + files_left - 1) // files_left
        summary = _read_prefix(path, quota, group.host, consume)
        file_summaries.append(summary)
        if remaining is not None:
            remaining -= summary["lines_read"]
    lines_read = sum(item["lines_read"] for item in file_summaries)
    return {
        "term_frequency": tf, "document_frequency": df, "stats": stats,
        "host_day": {"day": group.day, "host": group.host,
                     "files_discovered": len(group.files), "files": file_summaries,
                     "lines_read": lines_read,
                     "records": records, "host_records": host_records,
                     "command_records": command_records,
                     "blank_lines": sum(item["blank_lines"] for item in file_summaries)},
    }


def select_vocabulary(
    document_frequency: dict[str, Counter[str]],
    term_frequency: dict[str, Counter[str]],
    min_frequency: int = 2,
    min_document_frequency: int = 1,
    max_vocab_size: int | None = None,
    rank_by: str = "term-frequency",
    layer_minimums: dict[str, int] | None = None,
) -> tuple[dict[str, int], dict[str, str]]:
    """Filter, reserve requested evidence layers, then apply a deterministic cap."""
    if min_frequency < 1 or min_document_frequency < 1:
        raise ValueError("minimum term/document frequency must be positive")
    if max_vocab_size is not None and max_vocab_size < 1:
        raise ValueError("maximum vocabulary size must be positive")
    if rank_by not in {"term-frequency", "document-frequency"}:
        raise ValueError("rank_by must be term-frequency or document-frequency")
    layer_minimums = dict(layer_minimums or {})
    if any(layer not in VOCABULARY_LAYERS for layer in layer_minimums):
        raise ValueError(f"layer minimum must name one of: {', '.join(VOCABULARY_LAYERS)}")
    if any(type(count) is not int or count < 1 for count in layer_minimums.values()):
        raise ValueError("layer minimums must be positive integers")
    token_group = {
        token: group for group in GROUPS
        for token, frequency in term_frequency[group].items()
        if (frequency >= min_frequency
            and document_frequency[group][token] >= min_document_frequency)
    }
    if rank_by == "document-frequency":
        ranked = sorted(token_group, key=lambda token: (
            -document_frequency[token_group[token]][token],
            -term_frequency[token_group[token]][token], token,
        ))
    else:
        ranked = sorted(token_group, key=lambda token: (
            -term_frequency[token_group[token]][token],
            -document_frequency[token_group[token]][token], token,
        ))

    selected: list[str] = []
    selected_set: set[str] = set()
    # Canonical order makes results independent of repeated CLI option order.
    for layer in VOCABULARY_LAYERS:
        minimum = layer_minimums.get(layer, 0)
        if not minimum:
            continue
        candidates = [token for token in ranked if layer in token_layers(token)]
        if len(candidates) < minimum:
            raise ValueError(
                f"layer minimum {layer}={minimum:,} cannot be met; "
                f"only {len(candidates):,} eligible tokens"
            )
        have = sum(layer in token_layers(token) for token in selected)
        for token in candidates:
            if have >= minimum:
                break
            if token not in selected_set:
                selected.append(token)
                selected_set.add(token)
                have += 1
        if max_vocab_size is not None and len(selected) > max_vocab_size:
            raise ValueError("layer minimums cannot fit within maximum vocabulary size")

    for token in ranked:
        if max_vocab_size is not None and len(selected) >= max_vocab_size:
            break
        if token not in selected_set:
            selected.append(token)
            selected_set.add(token)
    rank_position = {token: index for index, token in enumerate(ranked)}
    selected.sort(key=rank_position.__getitem__)
    return {token: index for index, token in enumerate(selected)}, token_group


def parse_layer_minimum(value: str) -> tuple[str, int]:
    """Parse repeatable CLI values such as structure=1800."""
    layer, separator, raw_count = value.partition("=")
    if not separator or layer not in VOCABULARY_LAYERS:
        raise argparse.ArgumentTypeError(
            f"expected LAYER=COUNT where LAYER is one of: {', '.join(VOCABULARY_LAYERS)}"
        )
    try:
        count = int(raw_count)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("layer minimum COUNT must be an integer") from exc
    if count < 1:
        raise argparse.ArgumentTypeError("layer minimum COUNT must be positive")
    return layer, count


def layer_minimum_mapping(values: Iterable[tuple[str, int]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for layer, count in values:
        if layer in result:
            raise ValueError(f"duplicate --layer-minimum for {layer}")
        result[layer] = count
    return result


def _publish(vocabulary: dict[str, int], metadata: dict[str, Any], output: Path, metadata_output: Path) -> None:
    """Stage both JSONs, then replace outputs; manifest with checksum comes last."""
    output, metadata_output = validate_output_path(output), validate_output_path(metadata_output)
    stages = []
    try:
        for path, data in ((output, vocabulary), (metadata_output, metadata)):
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
            validate_output_path(temporary)
            stages.append((temporary, path))
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if path == output:
                with temporary.open("rb") as handle:
                    metadata["vocabulary_sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
        for temporary, path in stages:
            os.replace(temporary, path)
            sync_directory(path.parent)
    finally:
        for temporary, _ in stages:
            temporary.unlink(missing_ok=True)


def _enrich_metadata(meta: dict) -> dict:
    """Add token_provenance and weird_token_hints to metadata in place."""
    stats = meta.get("selected_token_statistics", {})
    host_days = meta.get("host_days", [])

    near_cutoff = sorted(t for t, info in stats.items()
                         if info.get("term_frequency", 0) == 2)
    single_document = sorted(t for t, info in stats.items()
                             if info.get("document_frequency", 0) == 1)
    meta["weird_token_hints"] = {
        "near_cutoff_tf2": near_cutoff,
        "near_cutoff_tf2_count": len(near_cutoff),
        "single_document_only": single_document,
        "single_document_only_count": len(single_document),
        "coverage_note": "DF=1 identifies one event; exact per-token host/day coverage is not recorded.",
    }

    scanned_hosts = sorted(set(hd.get("host", "") for hd in host_days))
    scanned_days = sorted(set(hd.get("day", "") for hd in host_days))
    meta["token_provenance"] = {
        "note": "Token provenance based on aggregate scan; individual record IDs "
                "require a full corpus re-scan. Use weird_token_hints to identify "
                "tokens worth investigating.",
        "scanned_hosts_count": len(scanned_hosts),
        "scanned_days": scanned_days,
        "group_distribution": dict(sorted(
            Counter(info.get("group", "unknown") for info in stats.values()).items()
        )),
    }
    meta["enrichment_utc"] = datetime.now(timezone.utc).isoformat()
    return meta


def reuse_existing(vocab_path: Path, meta_path: Path) -> int:
    """Enrich existing metadata without re-scanning the corpus."""
    meta_path = validate_output_path(meta_path)
    if vocab_path.resolve() == meta_path:
        raise ValueError("vocabulary and metadata output paths must differ")
    if not vocab_path.exists():
        raise SystemExit(f"vocab not found at {vocab_path}")
    if not meta_path.exists():
        raise SystemExit(f"metadata not found at {meta_path}")

    print(f"Loading existing vocab from {vocab_path}…", file=sys.stderr, flush=True)
    vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if hashlib.sha256(vocab_path.read_bytes()).hexdigest() != meta.get("vocabulary_sha256"):
        raise ValueError("vocabulary checksum does not match metadata")
    print(f"Vocab size: {len(vocab):,} tokens", file=sys.stderr, flush=True)
    print("Enriching metadata with provenance + weird-token hints…",
          file=sys.stderr, flush=True)

    meta = _enrich_metadata(meta)

    temp = validate_output_path(meta_path.with_name(f".{meta_path.name}.{os.getpid()}.tmp"))
    try:
        with temp.open("w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(temp, meta_path)
    finally:
        temp.unlink(missing_ok=True)

    hints = meta["weird_token_hints"]
    print(f"Done. Enriched metadata written to {meta_path}", file=sys.stderr)
    print(f"  near_cutoff_tf2: {hints['near_cutoff_tf2_count']:,} tokens",
          file=sys.stderr)
    print(f"  single_document_only: {hints['single_document_only_count']:,} tokens",
          file=sys.stderr)
    return 0


def select_from_existing_train_statistics(args: argparse.Namespace) -> int:
    """Publish a stricter/capped TRAIN vocabulary without rescanning telemetry."""
    from ML.code.preprocess.pipeline_contract import load_vocabulary
    from ML.code.preprocess.stratified_pipeline import file_hash, implementation, load_manifest

    manifest, split_sha = load_manifest(args.split, 'host_random_split')
    source_vocab_path = args.selection_source_vocab.resolve()
    source_meta_path = args.selection_source_metadata.resolve()
    output = validate_output_path(args.output)
    metadata_output = validate_output_path(args.metadata_output)
    if len({source_vocab_path, source_meta_path, output, metadata_output}) != 4:
        raise ValueError('selection sources and outputs must be four different files')
    if any(path.is_relative_to(args.split.resolve().parent) for path in (output, metadata_output)):
        raise ValueError('vocabulary outputs must be outside the immutable split directory')

    source_vocab, source_meta = load_vocabulary(
        source_vocab_path, source_meta_path, split_sha256=split_sha)
    policy = source_meta.get('frequency_policy', {})
    source_min_tf = policy.get('min_term_frequency')
    source_min_df = policy.get('min_document_frequency', 1)
    if (type(source_min_tf) is not int or type(source_min_df) is not int
            or source_min_tf > args.min_frequency
            or source_min_df > args.min_document_frequency
            or policy.get('max_tokens') is not None):
        raise ValueError(
            'selection source is not an uncapped superset of the requested TF/DF candidates'
        )
    statistics = source_meta.get('token_statistics')
    if not isinstance(statistics, dict) or set(statistics) != set(source_vocab):
        raise ValueError('selection source must contain statistics for every source vocabulary token')

    tf, df = _new_group_counters(), _new_group_counters()
    for token, values in statistics.items():
        if not isinstance(values, dict):
            raise ValueError(f'invalid source token statistics: {token}')
        group = values.get('group')
        term = values.get('term_frequency')
        documents = values.get('document_frequency')
        if (group not in GROUPS or type(term) is not int or type(documents) is not int
                or term < 1 or documents < 1 or documents > term):
            raise ValueError(f'invalid source token statistics: {token}')
        tf[group][token] = term
        df[group][token] = documents

    vocabulary, groups = select_vocabulary(
        df, tf, args.min_frequency, args.min_document_frequency,
        args.max_vocab_size, args.rank_by, args.layer_minimums,
    )
    if not vocabulary:
        raise ValueError('empty vocabulary')
    selected_by_layer = Counter(layer for token in vocabulary for layer in token_layers(token))
    eligible_by_layer = Counter(
        layer for token in groups for layer in token_layers(token)
    )
    metadata = dict(
        schema_version=7,
        created_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256=code_hashes(),
        implementation=implementation(),
        tokenizer_policy=TOKENIZER_POLICY,
        fit_purpose='supervised_training',
        fit_classes=[0, 1],
        split_sha256=split_sha,
        split_file=str(args.split.resolve()),
        split_seed=manifest['seed'],
        split_counts=manifest['counts'],
        fit_counts=source_meta.get('fit_counts'),
        vocab_size=len(vocabulary),
        scan=source_meta.get('scan'),
        frequency_policy=dict(
            min_term_frequency=args.min_frequency,
            min_document_frequency=args.min_document_frequency,
            document_unit='one TRAIN Host event; repeated occurrences in an event count once',
            max_tokens=args.max_vocab_size,
            rank_by=args.rank_by,
            tie_break='secondary frequency, then lexical token order',
            layer_minimums=args.layer_minimums,
            layer_order=list(VOCABULARY_LAYERS),
            eligible_tokens=len(groups),
            selected_tokens_by_group=dict(sorted(Counter(groups[token] for token in vocabulary).items())),
            eligible_tokens_by_layer=dict(sorted(eligible_by_layer.items())),
            selected_tokens_by_layer=dict(sorted(selected_by_layer.items())),
            layer_counts_overlap=True,
            test_used_for_selection=False,
        ),
        checkpoint=dict(
            mode='selection_from_complete_train_statistics',
            telemetry_rescanned=False,
            validation='source vocabulary SHA256, metadata SHA256, split SHA256, tokenizer SHA256, uncapped source policy',
        ),
        selection_source=dict(
            vocabulary_file=str(source_vocab_path),
            vocabulary_sha256=source_meta['vocabulary_sha256'],
            metadata_file=str(source_meta_path),
            metadata_sha256=file_hash(source_meta_path),
            source_min_term_frequency=source_min_tf,
            source_min_document_frequency=source_min_df,
            source_max_tokens=None,
        ),
        token_statistics={
            token: dict(
                group=groups[token], layers=token_layers(token),
                term_frequency=tf[groups[token]][token],
                document_frequency=df[groups[token]][token],
            )
            for token in vocabulary
        },
    )
    if args.dry_run:
        print(json.dumps(dict(
            split_sha256=split_sha,
            source_vocab_size=len(source_vocab),
            eligible_tokens=len(groups),
            selected_tokens=len(vocabulary),
            selected_tokens_by_layer=dict(sorted(selected_by_layer.items())),
        ), indent=2))
        return 0
    _publish(vocabulary, metadata, output, metadata_output)
    print(f'wrote {len(vocabulary):,} tokens to {output}', flush=True)
    print(f'wrote metadata to {metadata_output}', flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', type=Path, help='shared manifest from build_split.py; fit BOTH classes assigned to TRAIN')
    parser.add_argument('--selection-source-vocab', type=Path,
                        help='complete uncapped TRAIN vocabulary to filter without rescanning telemetry')
    parser.add_argument('--selection-source-metadata', type=Path,
                        help='metadata containing complete TF/DF for --selection-source-vocab')
    parser.add_argument("--roots", type=Path, nargs="+", default=[PROJECT_ROOT / "host-begnin"],
                        help="benign roots only; dates outside 2019-09-16..22 are rejected")
    parser.add_argument("--lines-per-host-day", "--records-per-host-day", type=int, default=100_000,
                        help="SOURCE lines per host/day, including FLOW/excluded/blank lines (default: 100000; 0 for full/unlimited)")
    parser.add_argument("--read-to-eof", "--full", action="store_true",
                        help="read all files to EOF without source-line quota (overrides --lines-per-host-day)")
    parser.add_argument("--days", nargs="+", help="optional subset of benign source partition dates")
    parser.add_argument("--fit-purpose", choices=("discovery", "training"), default="discovery",
                        help="training restricts the benign fit to September 16–20; discovery may use all benign days")
    parser.add_argument("--min-frequency", type=int, default=2, help="minimum total token occurrences (TF, not DF)")
    parser.add_argument("--min-document-frequency", type=int, default=1,
                        help="minimum TRAIN events containing the token (DF; default: 1)")
    parser.add_argument("--max-vocab-size", type=int,
                        help="maximum feature columns after filtering and layer reservations")
    parser.add_argument("--rank-by", choices=("term-frequency", "document-frequency"),
                        default="term-frequency",
                        help="primary ranking used for layer reservations and cap (default: term-frequency)")
    parser.add_argument("--layer-minimum", action="append", type=parse_layer_minimum, default=[],
                        metavar="LAYER=COUNT",
                        help="repeatable minimum selected tokens for an evidence layer")
    parser.add_argument("--workers", type=int, default=10, help="parallel host/day processes (default: 10)")
    parser.add_argument("--progress-every", type=int, default=0,
                        help="extra worker progress every N JSON records; 0 prints group completions only")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "code/output/vocab.json")
    parser.add_argument("--metadata-output", type=Path, default=PROJECT_ROOT / "code/output/vocab_metadata.json")
    parser.add_argument("--checkpoint-dir", type=Path,
                        help="checkpoint root (default: hidden directory beside --output)")
    parser.add_argument("--no-resume", action="store_true",
                        help="ignore compatible checkpoints from an interrupted run; newly completed groups are still checkpointed")
    parser.add_argument("--no-checkpoint", action="store_true",
                        help="disable both checkpoint writes and automatic resume")
    parser.add_argument("--dry-run", action="store_true", help="discovery only; no gzip contents read or outputs written")
    parser.add_argument("--reuse-existing", action="store_true",
                        help="skip corpus re-scan; only enrich existing metadata with "
                             "weird_token_hints and token_provenance")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.layer_minimums = layer_minimum_mapping(args.layer_minimum)
    if (args.min_frequency < 1 or args.min_document_frequency < 1
            or (args.max_vocab_size is not None and args.max_vocab_size < 1)):
        raise ValueError('term/document frequency and maximum vocabulary size must be positive')
    if args.split is not None:
        if args.days or args.reuse_existing or args.no_checkpoint or args.no_resume:
            raise ValueError('--split uses the immutable TRAIN assignment with automatic checkpoints; legacy options cannot override it')
        if bool(args.selection_source_vocab) != bool(args.selection_source_metadata):
            raise ValueError('--selection-source-vocab and --selection-source-metadata must be used together')
        if args.selection_source_vocab is not None:
            return select_from_existing_train_statistics(args)
        from ML.code.preprocess.stratified_pipeline import vocab_main
        return vocab_main(args)
    if args.selection_source_vocab is not None or args.selection_source_metadata is not None:
        raise ValueError('--selection-source-* requires --split')
    for path in (args.output, args.metadata_output):
        validate_output_path(path, args.roots)
    if args.reuse_existing:
        return reuse_existing(args.output, args.metadata_output)
    if args.fit_purpose == "training":
        if args.days is not None and not set(args.days) <= TRAIN_BENIGN_DAYS:
            raise ValueError("training vocabulary must use benign training days September 16–20 only")
        args.days = args.days or sorted(TRAIN_BENIGN_DAYS)
    read_to_eof = args.read_to_eof or (args.lines_per_host_day == 0)
    line_budget = None if read_to_eof else args.lines_per_host_day
    if args.workers < 1 or (not read_to_eof and args.lines_per_host_day < 1) or args.progress_every < 0:
        raise SystemExit("frequency/workers must be positive; progress interval must be nonnegative; lines-per-host-day must be >= 0")
    if args.output.resolve() == args.metadata_output.resolve():
        raise SystemExit("vocabulary and metadata output paths must differ")
    checkpoint_root = (args.checkpoint_dir if args.checkpoint_dir is not None else
                       args.output.parent / f".{args.output.stem}.checkpoints")
    validate_output_path(checkpoint_root, args.roots)
    if (not args.no_checkpoint
            and checkpoint_root.resolve() in {args.output.resolve(), args.metadata_output.resolve()}):
        raise SystemExit("checkpoint directory must differ from vocabulary and metadata outputs")
    if not args.no_checkpoint and checkpoint_root.exists() and not checkpoint_root.is_dir():
        raise SystemExit("checkpoint path exists but is not a directory")
    for output in (args.output, args.metadata_output):
        if output.suffix.lower() != ".json":
            raise SystemExit("output paths must end in .json")
        if any(output.resolve().is_relative_to(root.resolve()) for root in args.roots):
            raise SystemExit("outputs must be outside source dataset roots, including days excluded by --days")
    if (not args.no_checkpoint
            and any(checkpoint_root.resolve().is_relative_to(root.resolve()) for root in args.roots)):
        raise SystemExit("checkpoint directory must be outside source dataset roots")
    groups = discover_host_days(args.roots, args.days)
    if not groups:
        raise SystemExit("no benign host/day .json.gz files found")
    inputs = {path for group in groups for path in group.files}
    if {args.output.resolve(), args.metadata_output.resolve()} & inputs:
        raise SystemExit("outputs must not overwrite source data")
    discovery = {"host_days": len(groups), "hosts": len({group.host for group in groups}),
                 "files": len(inputs), "days": dict(sorted(Counter(group.day for group in groups).items())),
                 "source_lines_per_host_day": None if read_to_eof else args.lines_per_host_day,
                 "source_line_upper_bound": None if read_to_eof else len(groups) * args.lines_per_host_day,
                 "workers": min(args.workers, len(groups)),
                 "sampling": "full_corpus_read_to_eof" if read_to_eof else "bounded_shard_prefix",
                 "read_to_eof": read_to_eof,
                 "json_parser": "orjson" if orjson is not None else "stdlib_json"}
    if args.dry_run:
        print(json.dumps(discovery, indent=2))
        return 0
    if read_to_eof:
        print(f"Benign full scan (EOF): {len(groups):,} host/days, {len(inputs):,} files; "
              f"unlimited lines/group; {discovery['workers']} workers; "
              f"TF >= {args.min_frequency}, DF >= {args.min_document_frequency}, "
              f"vocab cap {args.max_vocab_size or 'none'}", file=sys.stderr, flush=True)
    else:
        print(f"Benign prefixes: {len(groups):,} host/days, {len(inputs):,} files; "
              f"up to {args.lines_per_host_day:,} SOURCE lines/group "
              f"({discovery['source_line_upper_bound']:,} total); {discovery['workers']} workers; "
              f"TF >= {args.min_frequency}, DF >= {args.min_document_frequency}, "
              f"vocab cap {args.max_vocab_size or 'none'}", file=sys.stderr, flush=True)
        print("Sampling is bounded-prefix, not uniform over a day. FLOW and blank/excluded rows consume the read budget.",
              file=sys.stderr, flush=True)
    source_hashes = code_hashes(("build_vocab.py", "ecar_tokenizer.py", "command_syntax.py", "pipeline_contract.py"))
    scan_signature = _scan_signature(line_budget, source_hashes)
    checkpoint_run_dir = checkpoint_root.resolve() / scan_signature
    started = time.monotonic()
    tf, df = _new_group_counters(), _new_group_counters()
    aggregate_stats: dict[str, Counter[str]] = {}
    host_days = []
    total_lines = total_records = total_host_records = 0
    group_state = [(group, _stable_digest(_group_identity(group))) for group in groups]
    remaining: list[tuple[HostDay, str]] = []

    def merge_result(result: dict[str, Any]) -> None:
        nonlocal total_lines, total_records, total_host_records
        for group_name in GROUPS:
            tf[group_name].update(result["term_frequency"][group_name])
            df[group_name].update(result["document_frequency"][group_name])
        for name, counter in result["stats"].items():
            aggregate_stats.setdefault(name, Counter()).update(counter)
        summary = result["host_day"]
        host_days.append(summary)
        total_lines += summary["lines_read"]
        total_records += summary["records"]
        total_host_records += summary["host_records"]

    resumed_host_days = 0
    if not args.no_checkpoint and not args.no_resume:
        for group, group_signature in group_state:
            path = _checkpoint_path(checkpoint_run_dir, group, group_signature)
            result = _load_checkpoint(path, scan_signature, group_signature, group)
            if result is None:
                remaining.append((group, group_signature))
            else:
                merge_result(result)
                resumed_host_days += 1
    else:
        remaining = group_state.copy()
    if not args.no_checkpoint:
        print(f"Checkpoint resume: reused {resumed_host_days:,}/{len(groups):,} host/days; "
              f"{len(remaining):,} left to scan; directory {checkpoint_run_dir}",
              file=sys.stderr, flush=True)

    todo = iter(remaining)
    executor: concurrent.futures.ProcessPoolExecutor | None = None
    pending: set[concurrent.futures.Future] = set()
    future_groups: dict[concurrent.futures.Future, tuple[HostDay, str]] = {}
    scanned_this_run = 0
    session_lines = 0
    try:
        if remaining:
            executor = concurrent.futures.ProcessPoolExecutor(max_workers=discovery["workers"])
        for _ in range(min(discovery["workers"], len(remaining))):
            group, group_signature = next(todo)
            future = executor.submit(_scan_host_day, group, line_budget, args.progress_every)
            pending.add(future)
            future_groups[future] = (group, group_signature)
        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                result = future.result()
                group, group_signature = future_groups.pop(future)
                if not args.no_checkpoint:
                    current_signature = _stable_digest(_group_identity(group))
                    if current_signature != group_signature:
                        raise RuntimeError(f"source files changed while scanning {group.day}/{group.host}")
                    _write_checkpoint(
                        _checkpoint_path(checkpoint_run_dir, group, group_signature),
                        scan_signature, group_signature, result,
                    )
                merge_result(result)
                summary = result["host_day"]
                scanned_this_run += 1
                session_lines += summary["lines_read"]
                elapsed = max(time.monotonic() - started, 0.001)
                print(f"[{len(host_days):,}/{len(groups):,}] {summary['day']}/{summary['host']}: "
                      f"{summary['lines_read']:,} lines, {summary['host_records']:,} Host records; "
                      f"total {total_lines:,} lines / {total_host_records:,} Host records "
                      f"({session_lines / elapsed:,.0f} new lines/s)", file=sys.stderr, flush=True)
                del result
                next_item = next(todo, None)
                if next_item is not None:
                    next_group, next_signature = next_item
                    next_future = executor.submit(
                        _scan_host_day, next_group, line_budget, args.progress_every)
                    pending.add(next_future)
                    future_groups[next_future] = (next_group, next_signature)
            done.clear()
    except BaseException:
        for future in pending:
            future.cancel()
        # Python 3.12 has no public terminate_workers; don't keep decoding on failure.
        if executor is not None:
            for process in list((getattr(executor, "_processes", None) or {}).values()):
                process.terminate()
            executor.shutdown(wait=True, cancel_futures=True)
        raise
    else:
        if executor is not None:
            executor.shutdown(wait=True)
    host_days.sort(key=lambda item: (item["day"], item["host"]))
    source_manifest = []
    for group, expected_identity in group_state:
        identity = _group_identity(group)
        if _stable_digest(identity) != expected_identity:
            raise ValueError(f"source identity changed during scan: {group.day}/{group.host}; no final publication")
        source_manifest.append(identity)
    vocabulary, token_group = select_vocabulary(
        df, tf, args.min_frequency, args.min_document_frequency,
        args.max_vocab_size, args.rank_by, args.layer_minimums,
    )
    if not vocabulary:
        raise SystemExit("no tokens meet the threshold; no outputs written. Check Host coverage or increase the prefix budget.")
    empty_groups = sum(item["host_records"] == 0 for item in host_days)
    if empty_groups:
        print(f"Note: {empty_groups:,} sampled host/days contributed no eligible Host records; "
              "the source-line budget was not extended.", file=sys.stderr, flush=True)
    metadata = {
        "schema_version": 6, "created_utc": datetime.now(timezone.utc).isoformat(),
        "vocabulary_file": str(args.output), "source_sha256": source_hashes,
        "representation": "Host-ML structure, anchor, syntax, semantic and lexical tokens; sparse binary/count columns",
        "fit_purpose": args.fit_purpose,
        "split_assumptions": {"fit_classes": "benign only", "training_days": sorted(TRAIN_BENIGN_DAYS),
                              "held_out_use": "forbidden for training fit; discovery artifacts require refitting"},
        "source_identity": {"method": "resolved path, compressed size, mtime_ns; not a content hash",
                            "host_days": source_manifest},
        "fit_scope": "full benign source partitions (read to EOF)" if read_to_eof else "sampled benign source partitions only; not full corpus",
        "sample_unit": "one eligible eCAR event; document frequency is event-level",
        "classifier_note": "Benign-only vocabulary is distinct from supervised classifier training, which still needs both classes.",
        "vocabulary_size_actual": len(vocabulary),
        "ranking": ("document frequency, then term frequency, then lexical token order"
                    if args.rank_by == "document-frequency" else
                    "total term frequency, then document frequency, then lexical token order"),
        "selection": {
            "frequency_measure": "TF counts repetitions; DF counts distinct eligible events",
            "minimum_frequency": args.min_frequency,
            "minimum_document_frequency": args.min_document_frequency,
            "maximum_vocabulary_size": args.max_vocab_size,
            "rank_by": args.rank_by,
            "layer_minimums": args.layer_minimums,
            "layer_minimum_policy": "reserve by canonical layer order, then fill from global ranking",
            "minimum_hosts": None, "minimum_days": None, "group_quotas": None,
            "mandatory_token_exceptions": bool(args.layer_minimums),
            "unique_candidates": sum(len(counter) for counter in tf.values()),
            "rejected_below_minimum_frequency": sum(
                frequency < args.min_frequency for counter in tf.values() for frequency in counter.values()),
            "rejected_below_minimum_document_frequency_after_tf": sum(
                frequency >= args.min_frequency and df[group][token] < args.min_document_frequency
                for group in GROUPS for token, frequency in tf[group].items()),
        },
        "tokenizer_policy": TOKENIZER_POLICY,
        "selected_tokens_by_group": dict(sorted(Counter(token_group[token] for token in vocabulary).items())),
        "selected_tokens_by_layer": dict(sorted(Counter(layer for token in vocabulary for layer in token_layers(token)).items())),
        "layer_count_note": "overlapping tags; totals may exceed vocabulary size; tags do not create columns",
        "scan": {
            **discovery, "mode": "full" if read_to_eof else "sampled", "roots": [str(root.resolve()) for root in args.roots],
            "file_pattern": "**/*.json.gz", "host_days_completed": len(host_days),
            "read_to_eof": read_to_eof, "source_day_definition": "filename/directory partition day, not UTC calendar date",
            "sampling_details": "full files read to EOF; no source-line budget" if read_to_eof else "sorted shard prefixes share one host/day source-line budget; unused short-shard quota carries forward",
            "sampling_bias": "none (full day coverage)" if read_to_eof else "not uniform across the day; later behavior may be absent; no temporal coverage guarantee",
            "label_policy": "skip label=1; reject invalid labels; absent/null label accepted by trusted benign partition membership",
            "invalid_record_policy": "fail on invalid records/read errors encountered" if read_to_eof else "fail on invalid records/read errors encountered; unvisited suffixes are not validated",
            "gzip_validation": "full read to EOF; whole-file CRC/trailer validated" if read_to_eof else "prefix read only; whole-file CRC/trailer validation is not guaranteed",
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "checkpoint": {
                "enabled": not args.no_checkpoint,
                "resumed_host_days": resumed_host_days,
                "scanned_host_days_this_run": scanned_this_run,
                "compatibility_signature": scan_signature if not args.no_checkpoint else None,
                "cleanup_policy": "remove after successful artifact publication",
            },
        },
        "aggregate": {
            "source_lines": total_lines, "records": total_records, "host_records": total_host_records,
            "command_records": sum(item["command_records"] for item in host_days),
            "blank_lines": sum(item["blank_lines"] for item in host_days),
            "host_days_without_host_records": empty_groups,
            **{name: dict(sorted(counter.items())) for name, counter in sorted(aggregate_stats.items())},
        },
        "host_days": host_days,
        "selected_token_statistics": {
            token: {"group": token_group[token], "layers": token_layers(token), "term_frequency": tf[token_group[token]][token],
                    "document_frequency": df[token_group[token]][token]}
            for token in vocabulary
        },
    }
    _publish(vocabulary, metadata, args.output, args.metadata_output)
    print(f"wrote {len(vocabulary):,} tokens to {args.output}\nwrote metadata to {args.metadata_output}",
          file=sys.stderr)

    # Enrich metadata in place after a full build
    print("Enriching metadata with provenance + weird-token hints…",
          file=sys.stderr, flush=True)
    meta_fresh = json.loads(args.metadata_output.read_text(encoding="utf-8"))
    meta_fresh = _enrich_metadata(meta_fresh)
    temp = validate_output_path(args.metadata_output.with_name(f".{args.metadata_output.name}.{os.getpid()}.tmp"))
    try:
        with temp.open("w", encoding="utf-8") as f:
            json.dump(meta_fresh, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(temp, args.metadata_output)
    finally:
        temp.unlink(missing_ok=True)
    hints = meta_fresh["weird_token_hints"]
    print(f"  near_cutoff_tf2: {hints['near_cutoff_tf2_count']:,} tokens",
          file=sys.stderr)
    print(f"  single_document_only: {hints['single_document_only_count']:,} tokens",
          file=sys.stderr)
    if not args.no_checkpoint:
        _cleanup_checkpoint_run(checkpoint_run_dir)
        print("Checkpoint cleanup complete after successful publication.",
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
