#!/usr/bin/env python3
"""Render a Vietnamese walkthrough from the production tokenizer, without fitting.

By default no vocabulary is loaded. --vocab requires compatible metadata so
token columns are used only with the matching tokenizer and vocabulary.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ecar_tokenizer import TOKENIZER_POLICY, flatten_tokens, token_layers, tokenize_record
from pipeline_contract import PROJECT_ROOT, load_vocabulary, validate_output_path


def render(sample_path: Path, vocab_path: Path | None = None,
           metadata_path: Path | None = None) -> str:
    records = json.loads(sample_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("sample must contain a JSON list of eCAR records")
    vocab = None
    if vocab_path is not None:
        vocab, _ = load_vocabulary(vocab_path, metadata_path or vocab_path.with_name("vocab_metadata.json"))
    lines = ["# Walkthrough: eCAR → Structure / Anchor / Syntax → sparse feature", "",
             f"Policy: `{TOKENIZER_POLICY['name']}`. Sinh từ production tokenizer; không fit sample, không execute telemetry.", "",
             "Anchor là tên ổn định trong vai trò grammar. Structure giữ quan hệ có hướng; syntax giữ switch/operator/quote/AST. "
             "Semantic role và lexical fallback bổ sung. Tag layer có thể chồng lấp, không tạo cột riêng.", "",
             (f"Vocabulary tương thích: {len(vocab):,} cột. Token OOV không tự tạo cột." if vocab is not None else
              "Chưa nạp vocabulary: dưới đây là candidate token, chưa phải cột đã được giữ qua ngưỡng TF. "
              "Dùng --vocab với vocabulary tương thích để xem column ID."), "",
             "| Record | Family | Candidate duy nhất | Anchor | Syntax | Structure |",
             "|---:|---|---:|---:|---:|---:|"]
    results = []
    for index, record in enumerate(records, 1):
        grouped, audit = tokenize_record(record)
        tokens = sorted(set(flatten_tokens(grouped)))
        results.append((tokens, audit))
        counts = {layer: sum(layer in token_layers(token) for token in tokens) for layer in ('anchor', 'syntax', 'structure')}
        lines.append(f"| {index} | {audit['command_family']} | {len(tokens)} | {counts['anchor']} | {counts['syntax']} | {counts['structure']} |")
    for index, (tokens, audit) in enumerate(results, 1):
        lines.extend(["", f"## Record {index}: {audit['command_family']}", "",
                      f"Decode audit: `{json.dumps(audit['decode_status'], sort_keys=True)}`.", ""])
        for layer in ('anchor', 'syntax', 'structure', 'semantic', 'lexical', 'context'):
            selected = [token for token in tokens if layer in token_layers(token)]
            if not selected:
                continue
            lines.extend([f"**{layer}** ({len(selected)} candidate; hiển thị tối đa 25)", "", "```text"])
            for token in selected[:25]:
                column = f" → {vocab.get(token, 'OOV')}" if vocab is not None else ""
                lines.append(token + column)
            lines.extend(["```", ""])
    lines.extend(["## Giới hạn và tái tạo", "",
                  "Parser bounded, không execution-equivalent. Group PowerShell có thể opaque; AST Python chỉ parse source inline. "
                  "Mẫu không chứng minh coverage hoặc hiệu quả APT toàn corpus. Fit vocabulary trên cả benign và malicious thuộc TRAIN của split chung trước khi transform validation/test.", "",
                  "```bash",
                  "python3 code/audit/explain_sample_tokenization.py --output code/output/sample_tokenization.md",
                  "python3 code/preprocess/build_vocab.py --split code/output/host_ml_seed02/split/manifest.json --workers 4 \\",
                  "  --output code/output/host_ml_seed02/vocab.json --metadata-output code/output/host_ml_seed02/vocab_metadata.json",
                  "```", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, default=PROJECT_ROOT / "analyst/sample/command_line_sample.json")
    parser.add_argument("--vocab", type=Path)
    parser.add_argument("--vocab-metadata", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.output is not None:
        args.output = validate_output_path(args.output)
        inputs = {p.resolve() for p in (args.sample, args.vocab, args.vocab_metadata) if p is not None}
        if args.output in inputs:
            raise ValueError("walkthrough output must not overwrite an input")
    text = render(args.sample, args.vocab, args.vocab_metadata)
    if args.output is None:
        print(text, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
