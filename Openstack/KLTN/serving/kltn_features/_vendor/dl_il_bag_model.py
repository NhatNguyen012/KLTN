# Vendored by Openstack/KLTN/scripts/vendor_features.py from IL/dataset_2-AInception/code/DL/train_il_step3_v2.py
# source sha256 8c623a487bddb990b88a4cee4a3d7936df93db98bcc10b2560c9219c5692e242; do not edit (re-run the vendoring script instead).
from __future__ import annotations

import torch
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

from .dl_il_model import ILBiLSTM


class ILBiLSTMBag(ILBiLSTM):
    def forward(self, x_cat, delta, ctx_cat, ctx_num, has_ctx, lengths, bag=None):
        B, T_, _ = x_cat.shape
        parts = [emb(x_cat[..., i]) for i, emb in enumerate(self.embeddings)]
        x_bin = torch.zeros(B, T_, 1, device=x_cat.device)
        event = self.event_encoder(torch.cat(parts + [x_bin, delta], -1))
        c = [e(ctx_cat[..., i]) for i, e in enumerate(self.ctx_embs)] + [ctx_num]
        bv = self.bag_emb(bag.reshape(B * T_, -1)).reshape(B, T_, -1)
        event = event + self.ctx_proj(torch.cat(c + [bv], -1)) * has_ctx[:, None, None]
        packed = pack_padded_sequence(event, lengths.cpu(), batch_first=True, enforce_sorted=False)
        out, (h_n, _) = self.lstm(packed)
        z_old = self.classifier(torch.cat([h_n[-2], h_n[-1]], -1)).squeeze(-1)
        h2, _ = self.lstm2(out)
        h2, _ = pad_packed_sequence(h2, batch_first=True, total_length=T_)
        mask = torch.arange(T_, device=x_cat.device)[None] < lengths[:, None]
        ev = self.event_head(h2).squeeze(-1).masked_fill(~mask, -1e4)
        z = z_old + self.gate * ev.max(1).values
        return z, z_old, ev, self.stage_head(h2), mask
