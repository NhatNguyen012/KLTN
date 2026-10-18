"""Shared read-only boundaries, code identity and vocabulary fit validation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = next((p for p in Path(__file__).resolve().parents if (p / "AGENTS.md").is_file()),
                    Path(__file__).resolve().parent.parent)
DATA_ROOT_NAMES = ("host-begnin", "host-malicious", "ecar-bro", "bro")
TRAIN_BENIGN_DAYS = frozenset(f"2019-09-{day:02d}" for day in range(16, 21))
TOKENIZER_FILES = ("ecar_tokenizer.py", "command_syntax.py")

# Reviewed feature-only migration: v4 -> v5 changes emitted features, never
# object eligibility, labels, source-line enumeration or split assignments.
# Pin BOTH implementations: future edits do not inherit this exception.
V4_SPLIT_TOKENIZER = {
    "ecar_tokenizer.py": "47642f9a95cf330f123e0c77b2f10a080d3df7326b3070c15d2ce72897118d6f",
    "command_syntax.py": "e625846e083df1ee1e7d908de60c3a997c51c67ff9b09cfda9d522ebb5661e89",
}
V5_SPLIT_TOKENIZER = {
    "ecar_tokenizer.py": "4d41f40c165853939b3cb9b441adccabcb4c7184fe3f613f36092654d0944fd0",
    "command_syntax.py": V4_SPLIT_TOKENIZER["command_syntax.py"],
}


def split_tokenizer_compatibility(recorded: dict) -> str:
    """Validate split eligibility compatibility, never frozen feature compatibility."""
    current = code_hashes()
    if recorded == current:
        return "exact_tokenizer"
    if recorded == V4_SPLIT_TOKENIZER and current == V5_SPLIT_TOKENIZER:
        return "reviewed_v4_to_v5_feature_only; unchanged eligibility and labels"
    raise ValueError("manifest tokenizer mismatch; no reviewed eligibility-compatible migration")


def validate_fit_input_path(path: Path) -> Path:
    """Guard the historical benign-only scan, including misleading symlinks.

    Custom external directories remain usable for isolated synthetic test fixtures.
    The supervised --split pipeline instead validates both roots and persisted
    TRAIN assignments through stratified_pipeline.py.
    """
    resolved = path.resolve()
    for name in DATA_ROOT_NAMES[1:]:
        if resolved.is_relative_to((PROJECT_ROOT / name).resolve()):
            raise ValueError(f"vocabulary fit cannot include {name}: {resolved}")
    return resolved


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_output_path(path: Path, input_roots: Iterable[Path] = ()) -> Path:
    """Reject all protected roots (also through symlinks) before any write."""
    resolved = path.resolve()
    roots = [PROJECT_ROOT / name for name in DATA_ROOT_NAMES] + list(input_roots)
    for root in roots:
        if resolved.is_relative_to(root.resolve()):
            raise ValueError(f"outputs must be outside source dataset roots: {resolved} is under {root.resolve()}")
    return resolved


def code_hashes(names: Iterable[str] = TOKENIZER_FILES) -> dict[str, str]:
    return {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in names}


def load_vocabulary(vocab_path: Path, metadata_path: Path,
                    *, training_days: Iterable[str] | None = None,
                    split_sha256: str | None = None) -> tuple[dict[str, int], dict]:
    """Require the exact tokenizer and intact vocabulary; optionally check fit days."""
    raw = vocab_path.read_bytes()
    vocabulary = json.loads(raw)
    meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (not isinstance(vocabulary, dict) or not vocabulary
            or any(not isinstance(t, str) or type(i) is not int for t, i in vocabulary.items())
            or sorted(vocabulary.values()) != list(range(len(vocabulary)))):
        raise ValueError("vocabulary must map strings to contiguous unique integer columns")
    if hashlib.sha256(raw).hexdigest() != meta.get("vocabulary_sha256"):
        raise ValueError("vocabulary checksum does not match metadata; use a complete publication")
    recorded = meta.get("source_sha256", {})
    if any(recorded.get(name) != digest for name, digest in code_hashes().items()):
        raise ValueError("vocabulary tokenizer is incompatible; rebuild vocabulary with current code")
    if split_sha256 is not None:
        if (meta.get('split_sha256') != split_sha256 or meta.get('fit_classes') != [0, 1]
                or meta.get('fit_purpose') != 'supervised_training'):
            raise ValueError('vocabulary must be fitted on both TRAIN classes of this exact shared split')
    if training_days is not None and meta.get('fit_purpose') == 'supervised_training':
        if not meta.get('split_sha256') or meta.get('fit_classes') != [0, 1]:
            raise ValueError('supervised vocabulary lacks split identity or both fit classes')
    elif training_days is not None:
        days = set(meta.get("scan", {}).get("days", {}))
        if not days or not days <= set(training_days):
            raise ValueError("vocabulary includes held-out or unknown fit days; fit benign training partitions only")
    return vocabulary, meta


def load_training_bundle(input_dir: Path, splits=('train', 'val')) -> tuple[dict, dict]:
    """Validate the shared vocabulary/split and arrays before supervised training."""
    matrix_dir = input_dir / 'matrix'
    if not matrix_dir.is_dir():
        matrix_dir = input_dir
    metadata = json.loads((matrix_dir / 'split_metadata.json').read_text())
    split_sha = metadata.get('split_sha256')
    if not isinstance(split_sha, str) or len(split_sha) != 64:
        raise ValueError('training requires a persisted shared split; rebuild with --split')
    vocab, vocab_meta = load_vocabulary(input_dir / 'vocab.json', input_dir / 'vocab_metadata.json', split_sha256=split_sha)
    if metadata.get('vocabulary_sha256') != vocab_meta['vocabulary_sha256']:
        raise ValueError('matrix/vocabulary identity mismatch')
    for split in splits:
        counts = metadata.get('splits', {}).get(split, {})
        if min(counts.get('label_0', 0), counts.get('label_1', 0)) < 1:
            raise ValueError(f'{split} needs both classes')
        for name in (f'X_{split}.npz', f'y_{split}.npy'):
            with (matrix_dir / name).open('rb') as handle:
                if hashlib.file_digest(handle, 'sha256').hexdigest() != metadata.get('artifact_sha256', {}).get(name):
                    raise ValueError(f'training artifact checksum mismatch: {name}')
    return vocab, {'split_sha256': split_sha, 'split_seed': metadata['split_seed'],
                   'vocabulary_sha256': vocab_meta['vocabulary_sha256']}
