#!/usr/bin/env python3
"""Build binary/count CSR with --split and a frozen supervised TRAIN vocabulary.

Bounded row chunks and per-file manifests support resume. Disk-backed arrays
assemble the final matrices. Publish a new directory only after all inputs pass;
never overwrite existing artifacts. Without --split the historical date/host
prototype remains available; it is not the current supervised workflow.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy import sparse

from ML.code.preprocess.ecar_tokenizer import flatten_tokens, token_layers, tokenize_record
from ML.code.preprocess.pipeline_contract import PROJECT_ROOT, TRAIN_BENIGN_DAYS, code_hashes, load_vocabulary, sync_directory, validate_output_path

VAL_BENIGN_DAYS = {"2019-09-21"}
TEST_BENIGN_DAYS = {"2019-09-22"}
FILE_PATTERN = re.compile(r"ecar-(?P<day>\d{4}-\d{2}-\d{2})-(?P<host>sysclient\d+)", re.I)
SPLITS = ("train", "val", "test")


def _classify_split(day: str, host: str, is_malicious: bool) -> str:
    if not is_malicious:
        return "train" if day in TRAIN_BENIGN_DAYS else "val" if day in VAL_BENIGN_DAYS else "test" if day in TEST_BENIGN_DAYS else "skip"
    match = re.fullmatch(r"sysclient(\d+)", host)
    if not match or int(match[1]) < 1:
        raise ValueError(f"invalid host: {host}")
    num = int(match[1])
    return "train" if num <= 400 else "val" if num <= 450 else "test"


def _parse_file_meta(path: Path) -> tuple[str, str]:
    match = FILE_PATTERN.search(path.name)
    if not match:
        raise ValueError(f"cannot identify host/day: {path}")
    return match["day"], match["host"].casefold()


def _identity(path: Path) -> dict:
    stat = path.stat()
    return {"path": str(path.resolve()), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def _digest(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _file_hash(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    path = validate_output_path(path)
    temporary = validate_output_path(path.with_name(f".{path.name}.{os.getpid()}.tmp"))
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _iter_rows(path: Path, vocab: dict[str, int], is_malicious: bool,
               line_limit: int, stats: Counter):
    day, host = _parse_file_meta(path)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        number = 0
        while not line_limit or number < line_limit:
            line = handle.readline()
            if not line:
                stats["eof_observed"] += 1
                break
            number += 1
            stats["lines_read"] += 1
            if not line.strip():
                stats["blank_lines"] += 1
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{number}: expected an event object")
            actual_host = record.get("hostname")
            if actual_host is not None and (not isinstance(actual_host, str) or actual_host.split('.')[0].casefold() != host):
                raise ValueError(f"{path}:{number}: hostname disagrees with filename")
            label = record.get("label")
            if label is None and not is_malicious:
                label = 0
            if type(label) is not int or label not in (0, 1) or (not is_malicious and label != 0):
                raise ValueError(f"{path}:{number}: explicit 0/1 label required on attack-day input; benign must be 0")
            stats["records_read"] += 1
            grouped, audit = tokenize_record(record)
            if not audit["eligible"]:
                stats[f"excluded_{audit['excluded_reason']}"] += 1
                continue
            counts = Counter()
            for token in flatten_tokens(grouped):
                for layer in token_layers(token):
                    stats[f"tokens_{layer}"] += 1
                    if token not in vocab:
                        stats[f"oov_{layer}"] += 1
                if token in vocab:
                    counts[vocab[token]] += 1
            if not counts:
                stats["no_vocab_hits"] += 1
            stats["eligible_records"] += 1
            stats[f"label_{label}"] += 1
            props = record.get("properties")
            props = props if isinstance(props, dict) else {}
            sidecar = {key: record.get(key) for key in ("actorID", "objectID", "hostname", "timestamp", "object", "action")}
            sidecar.update(event_id=record.get("id"), pid=props.get("pid", record.get("pid")),
                           label=label, source="malicious" if is_malicious else "benign", day=day, host=host,
                           source_file=str(path), source_line=number)
            yield label, counts, sidecar


def _write_chunk(directory: Path, index: int, rows: list, width: int) -> dict:
    stem = f"chunk_{index:06d}"
    for suffix in (".npz", ".npy", ".jsonl"):
        validate_output_path(directory / (stem + suffix))
    data, indices, indptr = [], [], [0]
    for _, counts, _ in rows:
        for column, count in sorted(counts.items()):
            indices.append(column)
            data.append(count)
        indptr.append(len(data))
    matrix = sparse.csr_matrix((np.asarray(data, dtype=np.float32), np.asarray(indices, dtype=np.int64),
                                np.asarray(indptr, dtype=np.int64)), shape=(len(rows), width))
    sparse.save_npz(directory / f"{stem}.npz", matrix)
    np.save(directory / f"{stem}.npy", np.asarray([row[0] for row in rows], dtype=np.int8))
    with (directory / f"{stem}.jsonl").open("w", encoding="utf-8") as handle:
        for _, _, value in rows:
            handle.write(json.dumps(value) + "\n")
    hashes = {}
    for suffix in (".npz", ".npy", ".jsonl"):
        path = directory / (stem + suffix)
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
        hashes[path.name] = _file_hash(path)
    return {"stem": stem, "rows": matrix.shape[0], "nnz": matrix.nnz, "sha256": hashes}


def _valid_manifest(manifest: dict, identity: dict, split: str, directory: Path) -> bool:
    if manifest['identity'] != identity or manifest['split'] != split:
        return False
    chunks = manifest['chunks']
    if not isinstance(chunks, list) or sum(part['rows'] for part in chunks) != manifest['stats'].get('eligible_records', 0):
        return False
    for index, part in enumerate(chunks):
        stem = f"chunk_{index:06d}"
        if (part['stem'] != stem or type(part['rows']) is not int or part['rows'] <= 0
                or type(part['nnz']) is not int or part['nnz'] < 0
                or set(part['sha256']) != {stem + ext for ext in ('.npz', '.npy', '.jsonl')}):
            return False
        if any(_file_hash(directory / name) != digest for name, digest in part['sha256'].items()):
            return False
    return True


def _process_file(path: Path, vocab: dict, malicious: bool, line_limit: int,
                  chunk_rows: int, checkpoint_root: Path, resume: bool) -> dict:
    identity = _identity(path)
    key = _digest({**identity, "malicious": malicious})
    directory = validate_output_path(checkpoint_root / key)
    manifest_path = directory / "manifest.json"
    day, host = _parse_file_meta(path)
    split = _classify_split(day, host, malicious)
    if resume and manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            if _valid_manifest(manifest, identity, split, directory):
                return {**manifest, "directory": str(directory), "resumed": True}
        except (OSError, ValueError, KeyError, TypeError):
            pass
    directory.mkdir(parents=True, exist_ok=True)
    stats = Counter()
    chunks, rows = [], []
    if split != "skip":
        for row in _iter_rows(path, vocab, malicious, line_limit, stats):
            rows.append(row)
            if len(rows) >= chunk_rows:
                chunks.append(_write_chunk(directory, len(chunks), rows, len(vocab)))
                rows = []
        if rows:
            chunks.append(_write_chunk(directory, len(chunks), rows, len(vocab)))
    if identity != _identity(path):
        raise ValueError(f"source changed while reading: {path}")
    manifest = {"identity": identity, "split": split, "chunks": chunks, "stats": dict(stats)}
    _atomic_json(manifest_path, manifest)
    return {**manifest, "directory": str(directory), "resumed": False}


def _assemble(stage: Path, split: str, manifests: list[dict], width: int, representation: str) -> dict | None:
    parts = [(Path(m["directory"]), chunk) for m in manifests if m["split"] == split for chunk in m["chunks"]]
    n_rows = sum(chunk["rows"] for _, chunk in parts)
    if not n_rows:
        return None
    nnz = sum(chunk["nnz"] for _, chunk in parts)
    arrays = stage / f".{split}_arrays"
    arrays.mkdir()
    def allocate(name, dtype, size):
        return np.lib.format.open_memmap(arrays / f"{name}.npy", mode="w+", dtype=dtype, shape=(size,))
    data = allocate("data", np.float32, nnz)
    indices = allocate("indices", np.int64, nnz)
    indptr = allocate("indptr", np.int64, n_rows + 1)
    labels = allocate("labels", np.int8, n_rows)
    row_offset = nz_offset = positives = 0
    indptr[0] = 0
    with (stage / f"row_sidecar_{split}.jsonl").open("w", encoding="utf-8") as sidecar:
        for directory, part in parts:
            chunk = sparse.load_npz(directory / (part["stem"] + ".npz"))
            y = np.load(directory / (part["stem"] + ".npy"))
            if chunk.shape != (part['rows'], width) or chunk.nnz != part['nnz'] or y.shape != (part['rows'],):
                raise ValueError("checkpoint chunk dimensions disagree with manifest")
            end_row, end_nz = row_offset + chunk.shape[0], nz_offset + chunk.nnz
            data[nz_offset:end_nz], indices[nz_offset:end_nz] = chunk.data, chunk.indices
            indptr[row_offset + 1:end_row + 1] = chunk.indptr[1:] + nz_offset
            labels[row_offset:end_row] = y
            positives += int(y.sum())
            with (directory / (part["stem"] + ".jsonl")).open() as handle:
                for local_row, line in enumerate(handle):
                    value = json.loads(line)
                    value["row_id"] = row_offset + local_row
                    sidecar.write(json.dumps(value) + "\n")
            row_offset, nz_offset = end_row, end_nz
    labels.flush()
    np.save(stage / f"y_{split}.npy", labels)
    matrix = sparse.csr_matrix((data, indices, indptr), shape=(n_rows, width), copy=False)
    if representation in {"count", "both"}:
        sparse.save_npz(stage / f"X_{split}_count.npz", matrix)
    matrix.data[:] = 1
    sparse.save_npz(stage / f"X_{split}.npz", matrix)
    del matrix, data, indices, indptr, labels
    shutil.rmtree(arrays)
    return {"rows": n_rows, "label_0": n_rows - positives, "label_1": positives, "nnz": nnz,
            "pos_rate": positives / n_rows, "avg_nnz_per_row": nnz / n_rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', type=Path, help='shared manifest from build_split.py; overrides the legacy date/host split')
    parser.add_argument("--benign-root", type=Path, default=PROJECT_ROOT / "host-begnin")
    parser.add_argument("--malicious-root", type=Path, default=PROJECT_ROOT / "host-malicious")
    parser.add_argument("--vocab", type=Path, default=PROJECT_ROOT / "code/output/vocab.json")
    parser.add_argument("--vocab-metadata", type=Path)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "code/output/matrix")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--lines-per-file", type=int, default=0)
    parser.add_argument("--max-files-per-group", type=int, default=0)
    parser.add_argument("--chunk-rows", type=int, default=50000)
    parser.add_argument("--representation", choices=("binary", "count", "both"), default="binary")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args(argv)
    if args.split is not None:
        if args.lines_per_file or args.max_files_per_group or args.no_resume:
            raise ValueError('--split requires all assigned rows and automatic checkpoints; scan limits are incompatible')
        from ML.code.preprocess.stratified_pipeline import matrix_main
        return matrix_main(args)
    roots = [args.benign_root, args.malicious_root]
    output = validate_output_path(args.output_dir, roots)
    if output.exists():
        raise ValueError("output directory already exists; choose an unused output directory")
    if args.workers < 1 or args.chunk_rows < 1 or min(args.lines_per_file, args.max_files_per_group) < 0:
        raise ValueError("workers/chunk-rows must be positive; scan limits must be nonnegative")
    metadata_path = args.vocab_metadata or args.vocab.with_name("vocab_metadata.json")
    vocab, vocab_meta = load_vocabulary(args.vocab, metadata_path, training_days=TRAIN_BENIGN_DAYS)
    if vocab_meta.get('fit_purpose') == 'supervised_training':
        raise ValueError('shared-split vocabulary requires --split; legacy date/host assignment is incompatible')
    sources = []
    for root, malicious in zip(roots, (False, True)):
        if not root.is_dir():
            raise ValueError(f"missing input root: {root}")
        paths = sorted(set(p.resolve() for p in root.rglob("*.json.gz")))
        if args.max_files_per_group:
            paths = paths[:args.max_files_per_group]
        sources.extend((p, malicious) for p in paths)
    if not sources:
        raise ValueError("no eCAR files found")
    if len({p for p, _ in sources}) != len(sources):
        raise ValueError("benign and malicious roots overlap")
    config = {"source_sha256": code_hashes(("build_matrix.py", "ecar_tokenizer.py", "command_syntax.py", "pipeline_contract.py")),
              "vocabulary_sha256": vocab_meta["vocabulary_sha256"], "chunk_rows": args.chunk_rows,
              "lines_per_file": args.lines_per_file, "python": list(sys.version_info[:3])}
    checkpoint = validate_output_path(output.parent / f".{output.name}.checkpoints" / _digest(config), roots)
    checkpoint.mkdir(parents=True, exist_ok=True)
    manifests = []
    if args.workers == 1:
        for path, malicious in sources:
            manifests.append(_process_file(path, vocab, malicious, args.lines_per_file, args.chunk_rows, checkpoint, not args.no_resume))
    else:
        with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(_process_file, path, vocab, malicious, args.lines_per_file, args.chunk_rows, checkpoint, not args.no_resume)
                       for path, malicious in sources]
            for future in futures:
                manifests.append(future.result())
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    try:
        splits = {}
        for split in SPLITS:
            info = _assemble(stage, split, manifests, len(vocab), args.representation)
            if info is not None:
                splits[split] = info
        aggregate = Counter()
        for manifest in manifests:
            aggregate.update(manifest["stats"])
        metadata = {"created_utc": datetime.now(timezone.utc).isoformat(), **config,
                    "vocab_file": str(args.vocab.resolve()), "vocab_size": len(vocab), "representation": args.representation,
                    "split_policy": {"benign_train_days": sorted(TRAIN_BENIGN_DAYS), "benign_val_days": sorted(VAL_BENIGN_DAYS),
                                     "benign_test_days": sorted(TEST_BENIGN_DAYS), "malicious_hosts": "1–400 train; 401–450 val; >450 test",
                                     "note": "Prototype temporal benign / host-range attack-day split; campaign isolation is not established."},
                    "label_policy": "explicit integer 0/1 on attack-day records; missing benign label accepted as 0",
                    "split_readiness": "both classes required in each split before supervised evaluation",
                    "scan": {"roots": [str(p.resolve()) for p in roots], "max_files_per_group": args.max_files_per_group,
                             "read_to_eof": args.lines_per_file == 0, "sources": [m['identity'] for m in manifests]},
                    "checkpoint": {"resumed_files": sum(m["resumed"] for m in manifests), "files": len(manifests),
                                   "validation": "configuration/code/vocab identity, source path/size/mtime, chunk SHA256"},
                    "splits": splits, "aggregate_stats": dict(aggregate)}
        metadata["artifact_sha256"] = {p.name: _file_hash(p) for p in sorted(stage.iterdir()) if p.is_file()}
        for path in stage.iterdir():
            if path.is_file():
                with path.open('rb') as handle:
                    os.fsync(handle.fileno())
        _atomic_json(stage / "split_metadata.json", metadata)
        if output.exists():
            raise ValueError("output was created concurrently; preserving it")
        os.rename(stage, output)
        sync_directory(output.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    shutil.rmtree(checkpoint)
    print(json.dumps({"output": str(output), "splits": splits, "resumed_files": metadata["checkpoint"]["resumed_files"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
