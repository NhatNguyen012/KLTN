#!/usr/bin/env python3
"""Vendor the training-time preprocessing code into serving/kltn_features/_vendor (reproducible, no edits by hand).

Serving must tokenize exactly like training. Instead of re-implementing the IL preprocessing, the research modules
are copied byte-for-byte; only import lines are rewritten (package-relative), and from modules with heavy training
dependencies just the needed top-level definitions are extracted with `ast`. PROVENANCE.json records the source path,
source sha256 and vendored sha256 of every file; tests/test_feature_parity.py re-checks behaviour against the
original modules on real data.

Usage: vendor_features.py [--workspace /mnt/SSD_Data/optc] [--check]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "serving/kltn_features/_vendor"

# (vendored name, source path relative to the workspace, import rewrites, definitions to extract or None = whole file)
SOURCES = [
    ("command_syntax.py", "ML/code/preprocess/command_syntax.py", [], None),
    ("ecar_tokenizer.py", "ML/code/preprocess/ecar_tokenizer.py",
     [("from ML.code.preprocess.command_syntax import", "from .command_syntax import")], None),
    ("linux_ctx.py", "IL/dataset_2-AInception/code/rootcause/linux_ctx.py", [], None),
    ("ainception_adapters.py", "IL/dataset_2-AInception/code/adapters.py", [], None),
    ("sl700_ecar.py", "IL/dataset_2-AInception/code/ML/sl700_ecar.py",
     [('sys.path.insert(0, "/mnt/SSD_Data/optc")\n', ""),
      ('sys.path.insert(0, "/mnt/SSD_Data/optc/IL/dataset_2-AInception/code/rootcause")\n', ""),
      ("from ML.code.preprocess.ecar_tokenizer import", "from .ecar_tokenizer import"),
      ("from linux_ctx import", "from .linux_ctx import")], None),
    ("common_schema.py", "IL/dataset_1-ATLASv2/code/preprocess/common_schema.py", [], None),
    ("atlas_host_ctx.py", "IL/dataset_1-ATLASv2/code/ML/preprocess/build_host_shards.py", [],
     ["DIR_CATEGORIES", "get_command_family", "dir_to_role", "PREDEFINED_DOMAIN_TOKENS", "FileSessionIndex",
      "extract_domain_shift_tokens", "canonical_ecar_record"]),
    ("dl_contract.py", "IL/dataset_1-ATLASv2/code/DL/optc_il/contract.py", [], None),
    ("dl_atlas_events.py", "IL/dataset_1-ATLASv2/code/DL/bilstm_v9/build_dataset.py", [],
     ["LABEL_KINDS", "WINDOW", "STRIDE", "MAX_LEN", "CAT_FIELDS", "CMD_FLAGS", "cmd_flags", "ip_scope",
      "file_ext_class", "event_tokens"]),
    ("dl_port_class.py", "IL/dataset_1-ATLASv2/code/DL/preprocess/build_network_shards.py", [],
     ["map_resp_port_class"]),
    ("dl_sl700_events.py", "IL/dataset_2-AInception/code/DL/build_sl700_windows.py", [],
     ["LABEL_KINDS", "EXTRA_KINDS", "WINDOW", "STRIDE", "MAX_LEN", "DELETE_SC", "base", "user_class", "event_record",
      "pidx_ppid", "encode"]),
    ("dl_bag_groups.py", "IL/dataset_2-AInception/code/rootcause/build_sl700_events_v2.py", [],
     ["SEP", "GROUPS", "group_of"]),
    ("dl_cbc_parse.py", "IL/dataset_1-ATLASv2/code/DL/bilstm_v9/parse_events.py", [],
     ["KEEP_TYPES", "FILEMOD_EXT", "_pub_state"]),
    ("dl_base_model.py", "IL/dataset_1-ATLASv2/code/DL/optc_il/vendor/05b_train_bilstm.py", [],
     ["embedding_dim", "BiLSTMBaseline"]),
    ("dl_il_model.py", "IL/dataset_1-ATLASv2/code/DL/optc_il/il_model.py", [],
     ["emb_dim", "ExtEmbedding", "ILBiLSTM"]),
    ("dl_il_bag_model.py", "IL/dataset_2-AInception/code/DL/train_il_step3_v2.py", [],
     ["ILBiLSTMBag"]),
]

# extracted modules need these headers (only names the extracted definitions use)
HEADERS = {
    "atlas_host_ctx.py": ("from __future__ import annotations\n\nfrom bisect import bisect_left, bisect_right\n"
                          "from collections import defaultdict\nfrom typing import Any\n\n"
                          "from .common_schema import CanonicalEvent, classify_image_dir, extract_basename\n"),
    "dl_atlas_events.py": ("from __future__ import annotations\n\nimport re\n\n"
                           "from .common_schema import classify_image_dir, classify_principal, extract_basename\n"
                           "from .dl_port_class import map_resp_port_class\n"),
    "dl_port_class.py": "from __future__ import annotations\n",
    "dl_sl700_events.py": ("from __future__ import annotations\n\nimport math\n\nimport numpy as np\n\n"
                           "from .dl_atlas_events import CAT_FIELDS, CMD_FLAGS, cmd_flags, ip_scope\n"
                           "from .dl_contract import image_dir_class, optc_tokens\n"
                           "from .dl_port_class import map_resp_port_class\n\n\n"
                           "def _isna(v):\n    return v is None or (isinstance(v, float) and v != v)\n\n\n"
                           "class _PdShim:\n    \"\"\"pd.isna for the vendored event_record (no pandas at serving time).\"\"\"\n"
                           "    isna = staticmethod(_isna)\n\n\npd = _PdShim()\n"),
    "dl_bag_groups.py": "from __future__ import annotations\n",
    "dl_cbc_parse.py": "from __future__ import annotations\n",
    "dl_base_model.py": ("from __future__ import annotations\n\nimport math\n\nimport torch\nimport torch.nn as nn\n"
                         "from torch.nn.utils.rnn import pack_padded_sequence\n"),
    "dl_il_model.py": ("from __future__ import annotations\n\nimport math\n\nimport torch\nimport torch.nn as nn\n"
                       "from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence\n"),
    "dl_il_bag_model.py": ("from __future__ import annotations\n\nimport torch\n"
                           "from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence\n\n"
                           "from .dl_il_model import ILBiLSTM\n"),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract(src: str, names: list[str]) -> str:
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    got = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            found = [node.name]
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            found = [node.targets[0].id]
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Tuple)
              and all(isinstance(e, ast.Name) for e in node.targets[0].elts)):
            found = [e.id for e in node.targets[0].elts]          # WINDOW, STRIDE, MAX_LEN = ...
        else:
            continue
        for name in found:
            if name in names:
                start = (node.decorator_list[0].lineno if getattr(node, "decorator_list", None) else node.lineno) - 1
                got[name] = "".join(lines[start:node.end_lineno])
    missing = [n for n in names if n not in got]
    if missing:
        raise SystemExit(f"definitions not found: {missing}")
    segments = list(dict.fromkeys(got[n] for n in names))     # a tuple assignment is emitted once
    return "\n\n".join(s.rstrip() + "\n" for s in segments)


def build(workspace: Path) -> dict:
    files, prov = {}, {}
    for name, rel, rewrites, defs in SOURCES:
        path = workspace / rel
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        for old, new in rewrites:
            if old not in text:
                raise SystemExit(f"{rel}: rewrite target not found: {old!r}")
            text = text.replace(old, new)
        if defs is not None:
            text = HEADERS[name] + "\n\n" + extract(text, defs)
        header = (f"# Vendored by Openstack/KLTN/scripts/vendor_features.py from {rel}\n"
                  f"# source sha256 {sha(raw)}; do not edit (re-run the vendoring script instead).\n")
        body = header + text
        files[name] = body
        prov[name] = {"source": rel, "source_sha256": sha(raw), "extracted": defs, "rewrites": len(rewrites),
                      "vendored_sha256": sha(body.encode())}
    files["__init__.py"] = "# Vendored training-time preprocessing (see PROVENANCE.json).\n"
    return files, prov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", default="/mnt/SSD_Data/optc")
    ap.add_argument("--check", action="store_true", help="only verify that the vendored files match the sources")
    a = ap.parse_args()
    files, prov = build(Path(a.workspace))
    if a.check:
        bad = [n for n, body in files.items() if not (OUT / n).is_file() or (OUT / n).read_text() != body]
        print(json.dumps({"vendored_up_to_date": not bad, "stale": bad}))
        sys.exit(1 if bad else 0)
    OUT.mkdir(parents=True, exist_ok=True)
    for n, body in files.items():
        (OUT / n).write_text(body)
    (OUT / "PROVENANCE.json").write_text(json.dumps(prov, indent=1) + "\n")
    print(json.dumps({n: p["source"] for n, p in prov.items()}, indent=1))


if __name__ == "__main__":
    main()
