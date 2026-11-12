"""OpTC -> ATLASv2 incremental BiLSTM: the OpTC base model plus new parts.

Old (from the OpTC subsetB checkpoint, forward unchanged):
    embeddings[4] -> event_encoder -> BiLSTM -> [h_fwd, h_bwd] -> classifier  => z_old
New (ATLASv2):
    * embedding rows for tokens the OpTC vocabulary does not have (vocab
      extension; OpTC ids keep their rows and meaning; new rows start as a copy
      of <UNK>, so an unseen token behaves exactly as it did in the base model);
    * a host-context branch (process kind, parent, target, command-line flags,
      ... from the ATLASv2 EDR) added to the event encoding through a
      zero-initialised projection and gated by `has_ctx` (0 for OpTC flows,
      whose telemetry has no such fields);
    * a second BiLSTM layer over the old per-event states, with a per-event
      attack head (multiple-instance max) and a per-event attack-stage head;
    * window score z = z_old + gate * max_t(event_logit), gate initialised to 0.
At initialisation z == z_old for every input, i.e. the extended model is the
base model; this is asserted numerically before training.
"""
from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

VENDOR = Path(__file__).resolve().parent / "vendor"
BASE_DIR = Path(__file__).resolve().parents[1] / "pretrained_optc_model"


def load_base_module():
    sys.path.insert(0, str(VENDOR))
    spec = importlib.util.spec_from_file_location("optc_05b_train_bilstm", VENDOR / "05b_train_bilstm.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_base(device="cpu"):
    """Original OpTC BiLSTM (05_models/v2_subsetB/bilstm, md5-identical copy)."""
    import json
    mod = load_base_module()
    cfg = json.loads((BASE_DIR / "config.json").read_text())
    thr = json.loads((BASE_DIR / "threshold.json").read_text())["threshold"]
    m = mod.BiLSTMBaseline(categorical_cardinalities=cfg["categorical_cardinalities"], numerical_dim=0,
                           event_dim=cfg["event_dim"], hidden_dim=cfg["hidden_dim"],
                           lstm_layers=cfg["lstm_layers"], dropout=cfg["dropout"])
    ck = torch.load(BASE_DIR / "best_model.pt", map_location="cpu", weights_only=False)
    sd = ck["model_state_dict"] if isinstance(ck, dict) and "model_state_dict" in ck else ck
    m.load_state_dict(sd)
    return m.to(device).eval(), cfg, float(thr)


def emb_dim(card: int) -> int:
    return int(min(24, max(4, round(2 * math.sqrt(card)))))


class ExtEmbedding(nn.Module):
    """Old rows (frozen-able) + appended rows for new token ids."""

    def __init__(self, old: nn.Embedding, n_new: int):
        super().__init__()
        self.n_old = old.num_embeddings
        self.old = nn.Embedding.from_pretrained(old.weight.detach().clone(), freeze=False)
        self.new = nn.Embedding(max(1, n_new), old.embedding_dim)
        with torch.no_grad():
            self.new.weight.copy_(old.weight[0:1].expand_as(self.new.weight))  # copy of <UNK>

    def forward(self, ids):
        is_new = ids >= self.n_old
        e_old = self.old(ids.clamp(max=self.n_old - 1))
        e_new = self.new((ids - self.n_old).clamp(min=0))
        return torch.where(is_new.unsqueeze(-1), e_new, e_old)


class ILBiLSTM(nn.Module):
    def __init__(self, base: nn.Module, n_new: list[int], ctx_cards: list[int], ctx_num_dim: int,
                 hidden2: int = 64, dropout: float = 0.25):
        super().__init__()
        self.embeddings = nn.ModuleList(ExtEmbedding(e, k) for e, k in zip(base.embeddings, n_new))
        self.event_encoder = base.event_encoder
        self.lstm = base.lstm
        self.classifier = base.classifier
        d_event = base.event_encoder[0].out_features
        H = 2 * base.lstm.hidden_size
        # new: host-context branch (zero output at init)
        self.ctx_embs = nn.ModuleList(nn.Embedding(c, emb_dim(c), padding_idx=0) for c in ctx_cards)
        cin = sum(e.embedding_dim for e in self.ctx_embs) + ctx_num_dim
        self.ctx_proj = nn.Sequential(nn.Linear(cin, d_event), nn.LayerNorm(d_event), nn.GELU(),
                                      nn.Dropout(dropout), nn.Linear(d_event, d_event))
        nn.init.zeros_(self.ctx_proj[-1].weight)
        nn.init.zeros_(self.ctx_proj[-1].bias)
        # new layers and heads
        self.lstm2 = nn.LSTM(H, hidden2, batch_first=True, bidirectional=True)
        H2 = 2 * hidden2
        self.event_head = nn.Sequential(nn.Linear(H2, hidden2), nn.GELU(), nn.Linear(hidden2, 1))
        self.stage_head = nn.Sequential(nn.Linear(H2, hidden2), nn.GELU(), nn.Linear(hidden2, 4))
        self.gate = nn.Parameter(torch.zeros(()))

    # parameter groups used by the freezing schedule
    def groups(self):
        g = {"old_emb": [], "old_body": [], "new": []}
        for n, p in self.named_parameters():
            if n.startswith("embeddings.") and ".old." in n:
                g["old_emb"].append(p)
            elif n.startswith(("event_encoder.", "lstm.", "classifier.")):
                g["old_body"].append(p)
            else:
                g["new"].append(p)
        return g

    def forward(self, x_cat, delta, ctx_cat, ctx_num, has_ctx, lengths):
        B, T, _ = x_cat.shape
        parts = [emb(x_cat[..., i]) for i, emb in enumerate(self.embeddings)]
        x_bin = torch.zeros(B, T, 1, device=x_cat.device)
        event = self.event_encoder(torch.cat(parts + [x_bin, delta], -1))
        if ctx_cat is not None:
            c = torch.cat([e(ctx_cat[..., i]) for i, e in enumerate(self.ctx_embs)] + [ctx_num], -1)
            event = event + self.ctx_proj(c) * has_ctx[:, None, None]
        packed = pack_padded_sequence(event, lengths.cpu(), batch_first=True, enforce_sorted=False)
        out, (h_n, _) = self.lstm(packed)
        z_old = self.classifier(torch.cat([h_n[-2], h_n[-1]], -1)).squeeze(-1)
        h2, _ = self.lstm2(out)
        h2, _ = pad_packed_sequence(h2, batch_first=True, total_length=T)
        mask = torch.arange(T, device=x_cat.device)[None] < lengths[:, None]
        ev = self.event_head(h2).squeeze(-1).masked_fill(~mask, -1e4)
        z = z_old + self.gate * ev.max(1).values
        return z, z_old, ev, self.stage_head(h2), mask
