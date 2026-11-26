#!/usr/bin/env python3
"""Generator for self-contained Kaggle Dual-GPU Continual Learning notebook `THEIA-MixHead-IL.ipynb`.

Exact architecture parity with OpTC base model (`MixHeadSelfAttentionCausalHost` in
`DL/code/preprocess/model_mixhead_attention.py`), enabling direct transfer of OpTC weights
from `mixhead_attention_t4x2_full.pt`, exact frozen preservation of OpTC base embeddings `[0:10499]`,
trainable adaptation on new THEIA Linux tokens `[10499:]` + IL Adapter + 3-Head classifiers,
validation-only threshold selection, forensic error traceback, and automatic ZIP export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

IL_ROOT = Path(__file__).resolve().parents[2]
NOTEBOOK_OUT = IL_ROOT / "code/kaggle/THEIA-MixHead-IL.ipynb"


def md_cell(source: str) -> Dict[str, Any]:
    lines = [ln + "\n" for ln in source.splitlines()]
    if lines:
        lines[-1] = lines[-1].rstrip("\n")
    return {"cell_type": "markdown", "metadata": {}, "source": lines}


def code_cell(source: str) -> Dict[str, Any]:
    lines = [ln + "\n" for ln in source.splitlines()]
    if lines:
        lines[-1] = lines[-1].rstrip("\n")
    return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": lines}


CELL_1_MD = """# DARPA TC E3 THEIA: Mix-Head Self-Attention Continual Learning ($L=3$ Causal Triplets)

Self-contained Domain-Incremental Learning pipeline transferring from **DARPA OpTC (Domain 0)** $\\rightarrow$ **DARPA TC E3 THEIA (Domain 2, Linux)** using the exact `MixHeadSelfAttentionCausalHost` architecture.

### Verified Dataset & Ground-Truth Guarantees
- **Clean T3 Regime**: `Parquet/event_table.parquet` filtered strictly to post-reboot T3 (`>= 2018-04-10 16:44:33 UTC`), chronologically sorted by `(timestamp_rec, event_uuid)` with direction-aware `EDGE_REVERSED_OPS` and full `EVENT_CLONE`/`EVENT_UNLINK` lineage preserved.
- **REAPr Hygiene**: Excludes all failed attack chains (`theia_3.3_fail_*`, `theia_3.11_fail`, `theia_4.8_fail`), `contaminated` nodes/edges, Section 4.6 phishing traffic (`208.75.117.*`), and standard OS `.so`/`ld.so.cache` linker noise while retaining `/tmp/memtrace.so`.
- **Leakage-Free Splits & Vocab**: Stratified over disjoint 5s attack / 60s benign wall-clock windows; shared OpTC tokens map directly to `[3..10498]`, while new THEIA tokens (`[10499:]`) are fitted strictly on `train`.
- **Continual Learning Protection**: Base Transformer blocks, `line_embedding`, `token_norm`, and OpTC base embedding rows `[0:10499]` remain bitwise frozen; only new THEIA embedding rows `[10499:]`, the 32-dim IL Adapter, pooling, and 3-Head classifiers adapt.
- **Forensic Export**: Packages `theia_mixhead_il_best.pt`, metrics, confusion matrices, and decoded FP/FN/Stage error traceback into `/kaggle/working/theia_traceback_results.zip`."""

CELL_2_ENV = """import json
import math
import os
import random
import shutil
import time
import zipfile
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from torch.utils.data import DataLoader, Dataset

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
n_gpus = torch.cuda.device_count()
print(f"Device: {device} | GPUs available: {n_gpus}")
for i in range(n_gpus):
    print(f"  GPU {i}: {torch.cuda.get_device_name(i)}")

WORK_DIR = Path("/kaggle/working") if Path("/kaggle/working").exists() else Path("./output_theia_il")
WORK_DIR.mkdir(parents=True, exist_ok=True)


def locate_inputs():
    search_roots = [
        Path("/kaggle/input"),
        Path("/mnt/SSD_Data/optc/IL/dataset_4-THEIA/output"),
        Path("/mnt/SSD_Data/optc/DL/code/output/results"),
        Path("."),
    ]
    shards_dir = None
    ckpt_path = None
    for root in search_roots:
        if not root.exists():
            continue
        for cand in [root / "theia_dl_shards", root / "dl_shards", root]:
            if (cand / "split_manifest.json").is_file() and (cand / "train").is_dir():
                shards_dir = cand
                break
        if shards_dir is None:
            for mf in root.rglob("split_manifest.json"):
                if (mf.parent / "train").is_dir():
                    shards_dir = mf.parent
                    break
        for c_cand in [root / "mixhead_attention_t4x2_full.pt"]:
            if c_cand.is_file():
                ckpt_path = c_cand
        if ckpt_path is None:
            for cf in root.rglob("mixhead_attention_t4x2_full.pt"):
                ckpt_path = cf
                break
        if shards_dir is not None and ckpt_path is not None:
            break

    # Extract standalone zip if uploaded as zip inside /kaggle/input
    if shards_dir is None and Path("/kaggle/input").exists():
        for zf in Path("/kaggle/input").rglob("*.zip"):
            extract_dir = WORK_DIR / "_extracted_inputs"
            with zipfile.ZipFile(zf, "r") as z:
                z.extractall(extract_dir)
            for mf in extract_dir.rglob("split_manifest.json"):
                if (mf.parent / "train").is_dir():
                    shards_dir = mf.parent
            for cf in extract_dir.rglob("mixhead_attention_t4x2_full.pt"):
                ckpt_path = cf

    assert shards_dir is not None, "Could not locate THEIA shards directory containing split_manifest.json"
    return shards_dir, ckpt_path


SHARDS_DIR, OPTC_CKPT_PATH = locate_inputs()
print(f"Resolved SHARDS_DIR    : {SHARDS_DIR}")
print(f"Resolved OPTC_CKPT_PATH: {OPTC_CKPT_PATH}")

with open(SHARDS_DIR / "split_manifest.json", "r", encoding="utf-8") as f:
    MANIFEST = json.load(f)
with open(SHARDS_DIR / "extended_dl_vocab.json", "r", encoding="utf-8") as f:
    VOCAB = json.load(f)
ID2TOK = {int(v): k for k, v in VOCAB.items()}

BASE_VOCAB_SIZE = int(MANIFEST.get("base_vocab_size", 10499))
TOTAL_VOCAB_SIZE = len(VOCAB)
SCENARIO_NAMES = {0: "Benign", 1: "NationState_Firefox_Drakon", 2: "BrowserExtension_MicroAPT"}
STAGE_NAMES = {
    0: "Benign",
    1: "Initial_Compromise",
    2: "Execution_PrivilegeEscalation",
    3: "Discovery_Reconnaissance",
    4: "C2_Exfiltration",
}
print(f"Manifest summary: splits={MANIFEST['splits']}, base_vocab={BASE_VOCAB_SIZE}, total_vocab={TOTAL_VOCAB_SIZE}")
print(f"Scenarios: {MANIFEST['scenarios']}")
print(f"Stages   : {MANIFEST['stages']}")"""

CELL_3_DATA = """class TheiaShardDataset(Dataset):
    \"\"\"Loads pre-built PyTorch L=3 causal triplet shards for a split.\"\"\"

    def __init__(self, split_dir: Path):
        self.samples = []
        shard_files = sorted(split_dir.glob("shard_*.pt"))
        if not shard_files:
            raise FileNotFoundError(f"No shard_*.pt files found under {split_dir}")
        for sf in shard_files:
            data = torch.load(sf, map_location="cpu", weights_only=False)
            self.samples.extend(data)
        print(f"Loaded {split_dir.name}: {len(self.samples):,} samples from {len(shard_files)} shards")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]


def collate_causal_batch(batch):
    \"\"\"Collates L=3 causal triplets into 3D padded `(batch_size, 3, max_len)` tensors for single/multi-GPU DataParallel.\"\"\"
    b = len(batch)
    max_len = 1
    labels_bin, labels_sc, labels_st = [], [], []
    triplets = []

    for sample in batch:
        labels_bin.append(float(sample["is_malicious"]))
        labels_sc.append(int(sample["scenario_id"]))
        labels_st.append(int(sample["stage_id"]))
        row = []
        for step_key in ("incoming_ids", "parent_ids", "current_ids"):
            ids = sample.get(step_key) or [2]
            if not ids:
                ids = [2]
            if len(ids) > max_len:
                max_len = len(ids)
            row.append(ids)
        triplets.append(row)

    token_ids = torch.zeros((b, 3, max_len), dtype=torch.long)
    for i, row in enumerate(triplets):
        for line_idx, ids in enumerate(row):
            token_ids[i, line_idx, :len(ids)] = torch.tensor(ids, dtype=torch.long)

    return {
        "token_ids": token_ids,
        "target_binary": torch.tensor(labels_bin, dtype=torch.float32),
        "target_scenario": torch.tensor(labels_sc, dtype=torch.long),
        "target_stage": torch.tensor(labels_st, dtype=torch.long),
    }


train_ds = TheiaShardDataset(SHARDS_DIR / "train")
val_ds = TheiaShardDataset(SHARDS_DIR / "val")
test_ds = TheiaShardDataset(SHARDS_DIR / "test")

BATCH_SIZE = 512 if torch.cuda.is_available() else 256
# Ensure every DataParallel GPU receives >= 1 sample on final batch
drop_last_tr = (n_gpus > 1 and (len(train_ds) % BATCH_SIZE) in range(1, n_gpus))
train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, drop_last=drop_last_tr, collate_fn=collate_causal_batch, num_workers=2, pin_memory=True)
val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_causal_batch, num_workers=2, pin_memory=True)
test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate_causal_batch, num_workers=2, pin_memory=True)

# Compute training-only class statistics for calibrated imbalance handling (zero val/test leakage)
train_bin_cnt = Counter(int(s["is_malicious"]) for s in train_ds.samples)
train_sc_cnt = Counter(int(s["scenario_id"]) for s in train_ds.samples)
train_st_cnt = Counter(int(s["stage_id"]) for s in train_ds.samples)
print("Train binary counts  :", dict(train_bin_cnt))
print("Train scenario counts:", dict(train_sc_cnt))
print("Train stage counts   :", dict(train_st_cnt))"""

CELL_4_MODEL = """class PeterBloemMultiHeadSelfAttention(nn.Module):
    def __init__(self, embed_dim: int = 128, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        assert embed_dim % num_heads == 0
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads
        self.to_keys = nn.Linear(embed_dim, embed_dim, bias=False)
        self.to_queries = nn.Linear(embed_dim, embed_dim, bias=False)
        self.to_values = nn.Linear(embed_dim, embed_dim, bias=False)
        self.unify_heads = nn.Linear(embed_dim, embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor):
        b, t, d = x.size()
        h, s = self.num_heads, self.head_dim
        queries = self.to_queries(x).view(b, t, h, s).transpose(1, 2)
        keys = self.to_keys(x).view(b, t, h, s).transpose(1, 2)
        values = self.to_values(x).view(b, t, h, s).transpose(1, 2)
        scores = torch.matmul(queries, keys.transpose(-2, -1)) / math.sqrt(s)
        attn_weights = F.softmax(scores, dim=-1)
        out = torch.matmul(self.dropout(attn_weights), values)
        out = out.transpose(1, 2).contiguous().view(b, t, d)
        return self.unify_heads(out), attn_weights


class TransformerCausalBlock(nn.Module):
    def __init__(self, embed_dim: int = 128, num_heads: int = 4, ff_dim: int = 256, dropout: float = 0.1):
        super().__init__()
        self.attention = PeterBloemMultiHeadSelfAttention(embed_dim, num_heads=num_heads, dropout=dropout)
        self.norm1 = nn.LayerNorm(embed_dim)
        self.norm2 = nn.LayerNorm(embed_dim)
        self.ffn = nn.Sequential(
            nn.Linear(embed_dim, ff_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ff_dim, embed_dim),
            nn.Dropout(dropout),
        )

    def forward(self, x: torch.Tensor):
        attn_out, weights = self.attention(x)
        x = self.norm1(x + attn_out)
        x = self.norm2(x + self.ffn(x))
        return x, weights


class IncrementalLearningAdapter(nn.Module):
    def __init__(self, embed_dim: int = 128, bottleneck_dim: int = 32, dropout: float = 0.1):
        super().__init__()
        self.down_proj = nn.Linear(embed_dim, bottleneck_dim)
        self.act = nn.GELU()
        self.up_proj = nn.Linear(bottleneck_dim, embed_dim)
        self.norm = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor):
        residual = x
        out = self.up_proj(self.dropout(self.act(self.down_proj(x))))
        return self.norm(residual + out)


class MixHeadSelfAttentionCausalHost(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 128,
        num_heads: int = 4,
        ff_dim: int = 256,
        num_transformer_blocks: int = 2,
        num_scenarios: int = 3,
        num_stages: int = 5,
        dropout: float = 0.1,
        enable_il_adapter: bool = True,
    ):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.token_embedding = nn.EmbeddingBag(vocab_size, embed_dim, mode="mean", padding_idx=0)
        self.token_norm = nn.LayerNorm(embed_dim)
        self.line_embedding = nn.Embedding(3, embed_dim)
        self.blocks = nn.ModuleList([
            TransformerCausalBlock(embed_dim, num_heads, ff_dim, dropout)
            for _ in range(num_transformer_blocks)
        ])
        self.il_adapter = IncrementalLearningAdapter(embed_dim, 32, dropout) if enable_il_adapter else None
        self.line_pooling_attn = nn.Linear(embed_dim, 1)
        pooled_dim = embed_dim * 2
        self.binary_head = nn.Sequential(nn.Linear(pooled_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, 1))
        self.scenario_head = nn.Sequential(nn.Linear(pooled_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, num_scenarios))
        self.stage_head = nn.Sequential(nn.Linear(pooled_dim, 64), nn.GELU(), nn.Dropout(dropout), nn.Linear(64, num_stages))

    def forward(self, token_ids: torch.Tensor, offsets: torch.Tensor = None, batch_size=None):
        if token_ids.dim() == 3:
            b, n_lines, l_max = token_ids.shape
            emb = self.token_embedding(token_ids.reshape(b * n_lines, l_max))
            x = self.token_norm(emb).view(b, n_lines, self.embed_dim)
        else:
            if isinstance(batch_size, torch.Tensor):
                b = int(batch_size.item())
            elif batch_size is not None:
                b = int(batch_size)
            else:
                b = offsets.numel() // 3
            x = self.token_norm(self.token_embedding(token_ids, offsets)).view(b, 3, self.embed_dim)
        line_ids = torch.tensor([0, 1, 2], device=x.device).unsqueeze(0).expand(b, -1)
        x = x + self.line_embedding(line_ids)
        attn_maps = []
        for block in self.blocks:
            x, w = block(x)
            attn_maps.append(w)
        if self.il_adapter is not None:
            x = self.il_adapter(x)
        current_line_repr = x[:, 2, :]
        line_weights = F.softmax(self.line_pooling_attn(x), dim=1)
        pooled_causal = (x * line_weights).sum(dim=1)
        combined = torch.cat([pooled_causal, current_line_repr], dim=-1)
        return {
            "binary_logits": self.binary_head(combined).squeeze(-1),
            "scenario_logits": self.scenario_head(combined),
            "stage_logits": self.stage_head(combined),
            "attention_maps": attn_maps,
            "line_weights": line_weights.squeeze(-1),
        }


def build_and_load_il_model():
    ckpt = torch.load(OPTC_CKPT_PATH, map_location="cpu", weights_only=False) if OPTC_CKPT_PATH else None
    arch = ckpt.get("arch", {}) if ckpt else {}
    ckpt_vocab = int(ckpt.get("vocab_size", BASE_VOCAB_SIZE)) if ckpt else BASE_VOCAB_SIZE
    model_vocab = max(TOTAL_VOCAB_SIZE + 32, int(ckpt.get("model_vocab_size", TOTAL_VOCAB_SIZE)) if ckpt else TOTAL_VOCAB_SIZE)

    base = MixHeadSelfAttentionCausalHost(
        vocab_size=model_vocab,
        embed_dim=int(arch.get("embed_dim", 128)),
        num_heads=int(arch.get("num_heads", 4)),
        ff_dim=int(arch.get("ff_dim", 256)),
        num_transformer_blocks=int(arch.get("num_transformer_blocks", 2)),
        num_scenarios=len(SCENARIO_NAMES),
        num_stages=len(STAGE_NAMES),
        dropout=0.1,
        enable_il_adapter=True,
    )

    with torch.no_grad():
        nn.init.normal_(base.token_embedding.weight, mean=0.0, std=0.02)
        base.token_embedding.weight[0].zero_()

    transferred, skipped = [], []
    if ckpt is not None:
        sd = ckpt["model_state_dict"]
        own_sd = base.state_dict()
        for k, v in sd.items():
            if k == "token_embedding.weight":
                copy_rows = min(v.shape[0], own_sd[k].shape[0])
                with torch.no_grad():
                    own_sd[k][:copy_rows].copy_(v[:copy_rows])
                transferred.append(f"{k}[:{copy_rows}]")
            elif k in own_sd and own_sd[k].shape == v.shape:
                with torch.no_grad():
                    own_sd[k].copy_(v)
                transferred.append(k)
            else:
                skipped.append(f"{k} ({tuple(v.shape)} vs {tuple(own_sd[k].shape) if k in own_sd else 'missing'})")
        print(f"Transferred {len(transferred)} tensors from OpTC checkpoint (epoch={ckpt.get('epoch')}).")
        print(f"Re-initialized target-specific output heads: {skipped}")

    # Domain-IL Freezing: Freeze Transformer blocks, token_norm, line_embedding + OpTC base embedding rows
    for p in base.token_norm.parameters():
        p.requires_grad = False
    for p in base.line_embedding.parameters():
        p.requires_grad = False
    for p in base.blocks.parameters():
        p.requires_grad = False

    # Keep snapshot of frozen OpTC embeddings [0:ckpt_vocab] to guarantee bitwise preservation under AdamW
    frozen_base_emb = base.token_embedding.weight[:ckpt_vocab].detach().clone().to(device)
    trainable = sum(p.numel() for p in base.parameters() if p.requires_grad)
    total = sum(p.numel() for p in base.parameters())
    print(f"Model params: total={total:,}, requires_grad={trainable:,} (base blocks/norm/OpTC rows [0:{ckpt_vocab}] frozen)")
    return base, frozen_base_emb, ckpt_vocab


base_model, FROZEN_BASE_EMB, FROZEN_VOCAB_ROWS = build_and_load_il_model()
base_model = base_model.to(device)
model = nn.DataParallel(base_model) if n_gpus > 1 else base_model
raw_model = model.module if isinstance(model, nn.DataParallel) else model"""

CELL_5_TRAIN = """def make_bounded_class_weights(counts: Counter, num_classes: int, min_w: float = 0.25, max_w: float = 12.0) -> torch.Tensor:
    non_zero = [counts.get(c, 0) for c in range(num_classes) if counts.get(c, 0) > 0]
    med = float(np.median(non_zero)) if non_zero else 1.0
    weights = []
    for c in range(num_classes):
        cnt = counts.get(c, 0)
        if cnt <= 0:
            weights.append(1.0)
        else:
            w = math.sqrt(med / float(cnt))
            weights.append(float(np.clip(w, min_w, max_w)))
    return torch.tensor(weights, dtype=torch.float32, device=device)


pos_weight_val = min(8.0, math.sqrt(max(1.0, train_bin_cnt.get(0, 1)) / max(1.0, train_bin_cnt.get(1, 1))))
criterion_bin = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([pos_weight_val], dtype=torch.float32, device=device))
sc_weights = make_bounded_class_weights(train_sc_cnt, len(SCENARIO_NAMES), min_w=0.2, max_w=8.0)
st_weights = make_bounded_class_weights(train_st_cnt, len(STAGE_NAMES), min_w=0.2, max_w=12.0)
criterion_sc = nn.CrossEntropyLoss(weight=sc_weights)
criterion_st = nn.CrossEntropyLoss(weight=st_weights)
print(f"Loss weights -> binary pos_weight={pos_weight_val:.2f}, scenario={sc_weights.tolist()}, stage={[round(x,2) for x in st_weights.tolist()]}")

# Separate AdamW param groups: zero weight_decay on token_embedding (and exact restore on base rows)
emb_params = [raw_model.token_embedding.weight]
other_params = [p for n, p in raw_model.named_parameters() if p.requires_grad and n != "token_embedding.weight"]
optimizer = torch.optim.AdamW([
    {"params": emb_params, "lr": 2e-3, "weight_decay": 0.0},
    {"params": other_params, "lr": 1e-3, "weight_decay": 1e-4},
])
EPOCHS = 12
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS, eta_min=1e-5)


def evaluate_loader(loader):
    model.eval()
    total_loss = 0.0
    all_bin_prob, all_bin_tgt = [], []
    all_sc_pred, all_sc_tgt = [], []
    all_st_pred, all_st_tgt = [], []
    with torch.no_grad():
        for batch in loader:
            tids = batch["token_ids"].to(device, non_blocking=True)
            yb = batch["target_binary"].to(device, non_blocking=True)
            ysc = batch["target_scenario"].to(device, non_blocking=True)
            yst = batch["target_stage"].to(device, non_blocking=True)
            out = model(tids)
            loss = criterion_bin(out["binary_logits"], yb) + criterion_sc(out["scenario_logits"], ysc) + criterion_st(out["stage_logits"], yst)
            total_loss += float(loss.item()) * len(yb)
            all_bin_prob.append(torch.sigmoid(out["binary_logits"]).cpu().numpy())
            all_bin_tgt.append(yb.cpu().numpy())
            all_sc_pred.append(out["scenario_logits"].argmax(dim=-1).cpu().numpy())
            all_sc_tgt.append(ysc.cpu().numpy())
            all_st_pred.append(out["stage_logits"].argmax(dim=-1).cpu().numpy())
            all_st_tgt.append(yst.cpu().numpy())
    bp = np.concatenate(all_bin_prob)
    bt = np.concatenate(all_bin_tgt).astype(int)
    scp = np.concatenate(all_sc_pred)
    sct = np.concatenate(all_sc_tgt)
    stp = np.concatenate(all_st_pred)
    stt = np.concatenate(all_st_tgt)
    return {
        "loss": total_loss / max(1, len(bt)),
        "bin_probs": bp,
        "bin_targets": bt,
        "sc_preds": scp,
        "sc_targets": sct,
        "st_preds": stp,
        "st_targets": stt,
        "pr_auc": float(average_precision_score(bt, bp)) if len(np.unique(bt)) > 1 else 0.0,
        "roc_auc": float(roc_auc_score(bt, bp)) if len(np.unique(bt)) > 1 else 0.0,
        "st_macro_f1": float(f1_score(stt, stp, average="macro", zero_division=0)),
        "sc_macro_f1": float(f1_score(sct, scp, average="macro", zero_division=0)),
    }


history = []
best_score = -1.0
best_ckpt_path = WORK_DIR / "theia_mixhead_il_best.pt"

for epoch in range(1, EPOCHS + 1):
    t0 = time.time()
    model.train()
    tr_loss = 0.0
    n_tr = 0
    for batch in train_loader:
        optimizer.zero_grad(set_to_none=True)
        tids = batch["token_ids"].to(device, non_blocking=True)
        yb = batch["target_binary"].to(device, non_blocking=True)
        ysc = batch["target_scenario"].to(device, non_blocking=True)
        yst = batch["target_stage"].to(device, non_blocking=True)

        out = model(tids)
        loss = criterion_bin(out["binary_logits"], yb) + criterion_sc(out["scenario_logits"], ysc) + criterion_st(out["stage_logits"], yst)
        loss.backward()
        if raw_model.token_embedding.weight.grad is not None:
            raw_model.token_embedding.weight.grad[:FROZEN_VOCAB_ROWS].zero_()
        torch.nn.utils.clip_grad_norm_(other_params, max_norm=2.0)
        optimizer.step()
        with torch.no_grad():
            raw_model.token_embedding.weight[:FROZEN_VOCAB_ROWS].copy_(FROZEN_BASE_EMB)
        tr_loss += float(loss.item()) * len(yb)
        n_tr += len(yb)

    scheduler.step()
    val_res = evaluate_loader(val_loader)
    sel_score = 0.5 * val_res["pr_auc"] + 0.5 * val_res["st_macro_f1"]
    row = {
        "epoch": epoch,
        "train_loss": tr_loss / max(1, n_tr),
        "val_loss": val_res["loss"],
        "val_pr_auc": val_res["pr_auc"],
        "val_roc_auc": val_res["roc_auc"],
        "val_sc_macro_f1": val_res["sc_macro_f1"],
        "val_st_macro_f1": val_res["st_macro_f1"],
        "elapsed_s": round(time.time() - t0, 1),
    }
    history.append(row)
    print(
        f"Epoch {epoch:02d}/{EPOCHS} | train_loss={row['train_loss']:.4f} | val_loss={row['val_loss']:.4f} | "
        f"val_PR-AUC={row['val_pr_auc']:.4f} | val_SC_F1={row['val_sc_macro_f1']:.4f} | "
        f"val_ST_F1={row['val_st_macro_f1']:.4f} ({row['elapsed_s']}s)"
    )
    if sel_score > best_score:
        best_score = sel_score
        torch.save({
            "epoch": epoch,
            "model_state_dict": raw_model.state_dict(),
            "val_metrics": {k: v for k, v in row.items()},
            "vocab_size": raw_model.token_embedding.num_embeddings,
            "base_vocab_size": FROZEN_VOCAB_ROWS,
            "scenario_names": SCENARIO_NAMES,
            "stage_names": STAGE_NAMES,
        }, best_ckpt_path)
        print(f"  --> Saved best IL checkpoint (score={sel_score:.4f})")"""

CELL_6_EVAL_TRACE = """# Load best checkpoint and calibrate threshold strictly on VAL split (FPR <= 1% or max F1)
best_ckpt = torch.load(best_ckpt_path, map_location=device, weights_only=False)
raw_model.load_state_dict(best_ckpt["model_state_dict"])

val_res = evaluate_loader(val_loader)
best_thr = 0.5
best_val_f1 = -1.0
for thr in np.linspace(0.05, 0.95, 91):
    preds = (val_res["bin_probs"] >= thr).astype(int)
    f1 = f1_score(val_res["bin_targets"], preds, zero_division=0)
    fp = int(((preds == 1) & (val_res["bin_targets"] == 0)).sum())
    tn = int(((preds == 0) & (val_res["bin_targets"] == 0)).sum())
    fpr = fp / max(1, fp + tn)
    if fpr <= 0.01 and f1 > best_val_f1:
        best_val_f1 = f1
        best_thr = float(thr)

if best_val_f1 < 0:
    best_thr = 0.5
print(f"Calibrated Binary Threshold on VAL: {best_thr:.3f} (val F1={best_val_f1:.4f})")

# Evaluate once on TEST split
test_res = evaluate_loader(test_loader)
bt = test_res["bin_targets"]
bp = test_res["bin_probs"]
bpred = (bp >= best_thr).astype(int)

tn = int(((bpred == 0) & (bt == 0)).sum())
fp = int(((bpred == 1) & (bt == 0)).sum())
fn = int(((bpred == 0) & (bt == 1)).sum())
tp = int(((bpred == 1) & (bt == 1)).sum())
fpr = fp / max(1, fp + tn)
prec, rec, f1_bin, _ = precision_recall_fscore_support(bt, bpred, average="binary", zero_division=0)

print("\\n=== THEIA TEST BINARY METRICS ===")
print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn} | Precision={prec:.4f} Recall={rec:.4f} F1={f1_bin:.4f} FPR={fpr*100:.4f}% PR-AUC={test_res['pr_auc']:.4f} ROC-AUC={test_res['roc_auc']:.4f}")

sc_labels_present = sorted(SCENARIO_NAMES.keys())
st_labels_present = sorted(STAGE_NAMES.keys())
print("\\n=== HEAD 2: SCENARIO REPORT ===")
sc_report = classification_report(
    test_res["sc_targets"], test_res["sc_preds"],
    labels=sc_labels_present, target_names=[SCENARIO_NAMES[i] for i in sc_labels_present],
    output_dict=True, zero_division=0,
)
print(classification_report(
    test_res["sc_targets"], test_res["sc_preds"],
    labels=sc_labels_present, target_names=[SCENARIO_NAMES[i] for i in sc_labels_present],
    digits=4, zero_division=0,
))

print("\\n=== HEAD 3: STAGE REPORT ===")
st_report = classification_report(
    test_res["st_targets"], test_res["st_preds"],
    labels=st_labels_present, target_names=[STAGE_NAMES[i] for i in st_labels_present],
    output_dict=True, zero_division=0,
)
print(classification_report(
    test_res["st_targets"], test_res["st_preds"],
    labels=st_labels_present, target_names=[STAGE_NAMES[i] for i in st_labels_present],
    digits=4, zero_division=0,
))

# Plot Stage & Scenario confusion matrices
cm_sc = confusion_matrix(test_res["sc_targets"], test_res["sc_preds"], labels=sc_labels_present)
cm_st = confusion_matrix(test_res["st_targets"], test_res["st_preds"], labels=st_labels_present)
fig, axes = plt.subplots(1, 2, figsize=(16, 6))
for ax, cm, names, title in [
    (axes[0], cm_sc, [SCENARIO_NAMES[i] for i in sc_labels_present], "Head 2: Scenario Attribution"),
    (axes[1], cm_st, [STAGE_NAMES[i] for i in st_labels_present], "Head 3: Kill-Chain Stage"),
]:
    im = ax.imshow(np.log1p(cm), cmap="Blues")
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=30, ha="right")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names)
    ax.set_title(title)
    for r in range(cm.shape[0]):
        for c in range(cm.shape[1]):
            ax.text(c, r, f"{cm[r, c]}", ha="center", va="center", color="black", fontsize=9)
plt.tight_layout()
plt.savefig(WORK_DIR / "theia_confusion_matrices.png", dpi=150)
plt.show()

# Forensic Error Traceback (decoded tokens + timestamps + probabilities)
def decode_ids(id_list):
    return [ID2TOK.get(int(i), f"<id:{i}>") for i in (id_list or [])]


def build_trace_entry(idx, err_kind):
    s = test_ds.samples[idx]
    return {
        "test_index": int(idx),
        "error_type": err_kind,
        "event_uuid": s.get("event_uuid", ""),
        "timestamp_rec": int(s.get("timestamp_rec", 0)),
        "true_binary": int(bt[idx]),
        "pred_binary": int(bpred[idx]),
        "pred_prob": round(float(bp[idx]), 5),
        "true_scenario": SCENARIO_NAMES.get(int(test_res["sc_targets"][idx]), str(test_res["sc_targets"][idx])),
        "pred_scenario": SCENARIO_NAMES.get(int(test_res["sc_preds"][idx]), str(test_res["sc_preds"][idx])),
        "true_stage": STAGE_NAMES.get(int(test_res["st_targets"][idx]), str(test_res["st_targets"][idx])),
        "pred_stage": STAGE_NAMES.get(int(test_res["st_preds"][idx]), str(test_res["st_preds"][idx])),
        "E_incoming": decode_ids(s.get("incoming_ids")),
        "E_parent": decode_ids(s.get("parent_ids")),
        "E_current": decode_ids(s.get("current_ids")),
    }


fp_indices = [i for i in range(len(bt)) if bpred[i] == 1 and bt[i] == 0]
fn_indices = [i for i in range(len(bt)) if bpred[i] == 0 and bt[i] == 1]
st_err_indices = [i for i in range(len(bt)) if bt[i] == 1 and test_res["st_preds"][i] != test_res["st_targets"][i]]

traceback_payload = {
    "threshold_val_calibrated": best_thr,
    "counts": {"fp": len(fp_indices), "fn": len(fn_indices), "stage_mismatch_on_attack": len(st_err_indices)},
    "false_positives_sample": [build_trace_entry(i, "FP") for i in fp_indices[:250]],
    "false_negatives_sample": [build_trace_entry(i, "FN") for i in fn_indices[:250]],
    "stage_errors_sample": [build_trace_entry(i, "STAGE_ERR") for i in st_err_indices[:250]],
}
with open(WORK_DIR / "theia_error_traceback.json", "w", encoding="utf-8") as f:
    json.dump(traceback_payload, f, indent=2)

metrics_payload = {
    "best_epoch": int(best_ckpt["epoch"]),
    "threshold_val_calibrated": best_thr,
    "binary": {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": prec, "recall": rec, "f1": f1_bin, "fpr": fpr, "pr_auc": test_res["pr_auc"], "roc_auc": test_res["roc_auc"]},
    "scenario_report": sc_report,
    "stage_report": st_report,
    "confusion_matrix_scenario": cm_sc.tolist(),
    "confusion_matrix_stage": cm_st.tolist(),
    "history": history,
    "manifest": MANIFEST,
}
with open(WORK_DIR / "theia_test_metrics.json", "w", encoding="utf-8") as f:
    json.dump(metrics_payload, f, indent=2)

# Package ZIP bundle automatically into `/kaggle/working/theia_traceback_results.zip`
zip_out = WORK_DIR / "theia_traceback_results.zip"
bundle_files = [
    WORK_DIR / "theia_mixhead_il_best.pt",
    WORK_DIR / "theia_test_metrics.json",
    WORK_DIR / "theia_error_traceback.json",
    WORK_DIR / "theia_confusion_matrices.png",
]
with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
    for bf in bundle_files:
        if bf.is_file():
            zf.write(bf, arcname=bf.name)
assert zip_out.is_file() and zip_out.stat().st_size > 0
print(f"\\nSUCCESS: Created {zip_out} ({zip_out.stat().st_size / (1024*1024):.2f} MB) containing {len(zipfile.ZipFile(zip_out).namelist())} files.")"""


def main() -> None:
    nb = {
        "cells": [
            md_cell(CELL_1_MD),
            code_cell(CELL_2_ENV),
            code_cell(CELL_3_DATA),
            code_cell(CELL_4_MODEL),
            code_cell(CELL_5_TRAIN),
            code_cell(CELL_6_EVAL_TRACE),
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.10"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK_OUT.parent.mkdir(parents=True, exist_ok=True)
    with NOTEBOOK_OUT.open("w", encoding="utf-8") as f:
        json.dump(nb, f, indent=2)
    print(f"Generated Kaggle notebook -> {NOTEBOOK_OUT} ({len(nb['cells'])} cells)")


if __name__ == "__main__":
    main()
