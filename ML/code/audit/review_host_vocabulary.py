#!/usr/bin/env python3
"""Audit frozen vocabulary aliases/coverage without editing feature indices.

The canonical projection is a review mapping, NOT a fitted replacement vocab.
New path/registry features require TRAIN-only retokenization and new shards.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'preprocess'))
from ecar_tokenizer import COMMAND_FAMILIES, SEARCH_PIPE_COUNTER_RE, HEX_ADDRESS_RE
from pipeline_contract import validate_output_path, load_vocabulary
from stratified_pipeline import atomic_json, file_hash, work_directory, publish_directory


def canonical_token(token):
    """Map only reviewed aliases/counters; retain unfamiliar lexical evidence."""
    replacements = (
        ('::structure::switch=', '::syntax::switch='),
        ('command_line::launcher=', 'command_line::anchor::launcher='),
        ('command_line::native::executable=', 'command_line::anchor::launcher='),
        ('command_line::rundll32::dll=', 'command_line::anchor::dll='),
        ('command_line::rundll32::entry=', 'command_line::anchor::entrypoint='),
    )
    for old, new in replacements:
        if old in token:
            return token.replace(old, new, 1), 'canonical_alias'
    parts = token.split('::')
    if len(parts) == 3 and parts[0] == 'command_line' and parts[1] in {*COMMAND_FAMILIES, 'powershell_decoded'} and '=' not in parts[2]:
        value = SEARCH_PIPE_COUNTER_RE.sub(r'\1_number_value', parts[2])
        value = HEX_ADDRESS_RE.sub('hex_value', value)
        if value != parts[2]:
            return '::'.join([*parts[:2], value]), 'dynamic_literal'
    return token, 'retain'


def load_frozen(vocab, metadata):
    values = json.loads(vocab.read_text())
    meta = json.loads(metadata.read_text())
    if meta['vocabulary_sha256'] != file_hash(vocab):
        raise ValueError('vocabulary checksum mismatch')
    if sorted(values.values()) != list(range(len(values))):
        raise ValueError('invalid feature indices')
    return values, meta


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vocab', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--new-vocab', type=Path)
    parser.add_argument('--new-metadata', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    if bool(args.new_vocab) != bool(args.new_metadata):
        raise ValueError('provide both new vocabulary and metadata')
    vocab, meta = load_frozen(args.vocab, args.metadata)
    config = dict(vocabulary_sha256=file_hash(args.vocab), metadata_sha256=file_hash(args.metadata),
                  implementation_sha256=file_hash(Path(__file__)))
    new = new_meta = None
    if args.new_vocab:
        new, new_meta = load_vocabulary(args.new_vocab, args.new_metadata, split_sha256=meta['split_sha256'])
        config.update(new_vocabulary_sha256=file_hash(args.new_vocab), new_metadata_sha256=file_hash(args.new_metadata))
    protected = [args.vocab.resolve(), args.metadata.resolve()]
    output = validate_output_path(args.output_dir, protected)
    output, work = work_directory(output, config)
    counts = Counter(); rows = []; projected = set()
    for token, index in sorted(vocab.items(), key=lambda item: item[1]):
        canonical, decision = canonical_token(token)
        frequency = meta['token_statistics'][token]
        df = frequency['document_frequency']
        # Low support is a review flag, never an automatic deletion rule.
        rare = bool(re.fullmatch(r'command_line::[^:]+::[^:=]+', token) and df <= 2)
        rows.append(dict(old_index=index, token=token, canonical_token=canonical, decision=decision,
                         train_tf=frequency['term_frequency'], train_df=df, review_rare_lexical=rare))
        projected.add(canonical); counts[decision] += 1; counts['rare_lexical_review'] += rare
    with validate_output_path(work / 'token_review.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    summary = dict(**config, original_columns=len(vocab), projected_canonical_columns=len(projected),
                   projected_column_reduction=len(vocab)-len(projected), decisions=dict(counts),
                   interpretation='Projection only; merged DF cannot be obtained by summing DF. No token is deleted solely for rarity. New semantic categories require refitting TRAIN.')
    if new is not None:
        summary.update(new_fitted_columns=len(new), removed_token_strings=len(set(vocab)-set(new)),
                       added_token_strings=len(set(new)-set(vocab)), fit_counts=new_meta['fit_counts'],
                       split_sha256=new_meta['split_sha256'])
        atomic_json(work / 'added_tokens.json', sorted(set(new)-set(vocab)))
        atomic_json(work / 'removed_tokens.json', sorted(set(vocab)-set(new)))
    atomic_json(work / 'summary.json', summary)
    publish_directory(work, output, dict(kind='host_vocabulary_review', complete=True, **config))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
