#!/usr/bin/env python3
"""Build the Deep Learning Vocabulary (dl_vocab.json) uniting Host and Network Telemetry.

This builder produces the unified vocabulary for Deep Learning models (BiLSTM,
MixHead Self-Attention). It incorporates:
1. All Host ML tokens (Process, File, Registry, Module, Command-Line AST, Causal Context)
   from the approved baseline vocabulary (ML/code/output/host_ml_parent_incoming_seed02/vocab.json).
2. Deterministic bounded Network tokens for OpTC FLOW events:
   - Traffic direction (inbound, outbound)
   - L4 protocols (tcp, udp, icmp, other)
   - Semantic enterprise & RFC IP scopes (internal_to_internal, internal_to_external, etc.)
   - MITRE service port roles (http, https, dns, smb, rpc, rdp, winrm, kerberos, ldap, etc.)
   - Quantized payload sizes (zero, tiny_beacon, small_payload, medium_transfer, bulk_exfil)
   - Flow interaction patterns (e.g., tcp:https_web:outbound, udp:dns:outbound)
   - Normalized socket process binaries and directory classes

Outputs:
  dl_vocab.json: Mapping of token string -> integer token ID
  dl_vocab_metadata.json: Audit trail, token counts, SHA256 hashes, and category breakdowns
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = next((p for p in CURRENT_DIR.parents if (p / "AGENTS.md").is_file()), CURRENT_DIR)
for p in (CURRENT_DIR, CURRENT_DIR.parent, PROJECT_ROOT, PROJECT_ROOT / "DL/code/preprocess"):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from dl_ecar_tokenizer import (
        get_all_bounded_network_tokens,
        tokenize_dl_record,
    )
except ImportError:
    from DL.code.preprocess.dl_ecar_tokenizer import (
        get_all_bounded_network_tokens,
        tokenize_dl_record,
    )


def compute_sha256(path: Path) -> str:
    """Compute sha256 checksum of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_dl_vocabulary(
    base_vocab_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    metadata_path: Optional[Path] = None,
    force_scan_dir: Optional[Path] = None,
) -> Dict[str, int]:
    """Constructs and persists the DL vocabulary.

    By default, bootstraps from the approved Host ML vocabulary (preserving 0..N-1 indices)
    and appends bounded network tokens, providing immediate full coverage and zero degradation.
    """
    default_base = PROJECT_ROOT / "ML/code/output/host_ml_parent_incoming_seed02/vocab.json"
    base_vocab_path = Path(base_vocab_path) if base_vocab_path else default_base
    output_path = Path(output_path) if output_path else PROJECT_ROOT / "DL/code/output/dl_vocab.json"
    metadata_path = Path(metadata_path) if metadata_path else PROJECT_ROOT / "DL/code/output/dl_vocab_metadata.json"

    print(f"[build_dl_vocab] Loading base Host ML vocabulary from {base_vocab_path}...")
    if not base_vocab_path.is_file():
        raise FileNotFoundError(f"Base vocabulary not found at {base_vocab_path}")

    base_sha256 = compute_sha256(base_vocab_path)
    with base_vocab_path.open("r", encoding="utf-8") as f:
        base_vocab: Dict[str, int] = json.load(f)

    base_count = len(base_vocab)
    print(f"[build_dl_vocab] Loaded {base_count:,} base tokens.")

    # Initialize new DL vocab with base tokens
    dl_vocab: Dict[str, int] = dict(base_vocab)
    next_id = max(dl_vocab.values()) + 1 if dl_vocab else 0

    # Obtain bounded network tokens
    bounded_net_tokens = get_all_bounded_network_tokens()
    added_net_tokens: List[str] = []

    for tok in bounded_net_tokens:
        if tok not in dl_vocab:
            dl_vocab[tok] = next_id
            added_net_tokens.append(tok)
            next_id += 1

    total_count = len(dl_vocab)
    print(f"[build_dl_vocab] Appended {len(added_net_tokens):,} network tokens.")
    print(f"[build_dl_vocab] Unified DL Vocabulary Size: {total_count:,} tokens.")

    # Categorize tokens for metadata audit
    category_counts: Dict[str, int] = {
        "ctx_causal_context": 0,
        "shell_ast_switches": 0,
        "image_and_path": 0,
        "registry": 0,
        "actions_and_objects": 0,
        "principal": 0,
        "network_bounded": 0,
        "other": 0,
    }

    for tok in dl_vocab:
        if tok.startswith("net::") or tok == "object::flow" or "->flow" in tok:
            category_counts["network_bounded"] += 1
        elif tok.startswith("ctx::"):
            category_counts["ctx_causal_context"] += 1
        elif tok.startswith("shell::") or "cmd" in tok or "switch" in tok:
            category_counts["shell_ast_switches"] += 1
        elif "path" in tok or "dir" in tok or "exe" in tok:
            category_counts["image_and_path"] += 1
        elif "reg" in tok or "key" in tok:
            category_counts["registry"] += 1
        elif tok.startswith("action::") or tok.startswith("object::") or tok.startswith("structure::"):
            category_counts["actions_and_objects"] += 1
        elif tok.startswith("principal::"):
            category_counts["principal"] += 1
        else:
            category_counts["other"] += 1

    # Ensure parent output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    # Write dl_vocab.json
    temp_vocab = output_path.with_suffix(".tmp")
    with temp_vocab.open("w", encoding="utf-8") as f:
        json.dump(dl_vocab, f, indent=2, ensure_ascii=False)
    temp_vocab.replace(output_path)
    vocab_sha256 = compute_sha256(output_path)

    # Write metadata
    metadata = {
        "format": "dl_host_and_network_vocabulary",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "total_tokens": total_count,
        "base_vocabulary": {
            "path": str(base_vocab_path),
            "sha256": base_sha256,
            "token_count": base_count,
        },
        "network_extension": {
            "new_network_tokens_count": len(added_net_tokens),
            "total_network_category_tokens": category_counts["network_bounded"],
            "added_tokens_sample": added_net_tokens[:20],
            "ip_policy": "enterprise_rfc_bounded_scopes_no_raw_ips",
            "port_policy": "mitre_roles_and_registered_ephemeral_ranges",
            "size_policy": "quantized_payload_buckets",
        },
        "token_category_breakdown": category_counts,
        "vocabulary_file": {
            "path": str(output_path),
            "sha256": vocab_sha256,
        },
    }

    temp_meta = metadata_path.with_suffix(".tmp")
    with temp_meta.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    temp_meta.replace(metadata_path)

    print(f"[build_dl_vocab] Successfully published dl_vocab.json -> {output_path}")
    print(f"[build_dl_vocab] Successfully published dl_vocab_metadata.json -> {metadata_path}")
    return dl_vocab


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-vocab", type=Path, help="Base Host ML vocab.json path")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "DL/code/output/dl_vocab.json")
    parser.add_argument("--metadata-output", type=Path, default=PROJECT_ROOT / "DL/code/output/dl_vocab_metadata.json")
    args = parser.parse_args()

    build_dl_vocabulary(
        base_vocab_path=args.base_vocab,
        output_path=args.output,
        metadata_path=args.metadata_output,
    )


if __name__ == "__main__":
    main()
