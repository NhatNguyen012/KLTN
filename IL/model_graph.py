#!/usr/bin/env python3
"""Write the computation graph of the final DL model for TensorBoard (SummaryWriter.add_graph).

Usage: python3 model_graph.py <step3 run dir> <out logdir> [--pkg <dir with tensorboard>]
View:  tensorboard --logdir <out logdir>   -> tab GRAPHS (double-click a block to expand it)
"""
import argparse, sys, warnings
from pathlib import Path
import torch

ap = argparse.ArgumentParser(); ap.add_argument("run"); ap.add_argument("out"); ap.add_argument("--pkg", default="/tmp/viz_pkg")
ap.add_argument("--events", type=int, default=512); ap.add_argument("--bag-k", type=int, default=64)
a = ap.parse_args()
sys.path.append(a.pkg)                                           # after the system packages
sys.path.insert(0, str(Path(__file__).resolve().parent))
from model_summary import build_from_checkpoint                  # noqa: E402
from torch.utils.tensorboard import SummaryWriter                # noqa: E402

m, base, info = build_from_checkpoint(torch.load(Path(a.run) / "best.pt", map_location="cpu"))
B, T = 1, a.events
d_delta = m.event_encoder[0].in_features - sum(e.old.embedding_dim for e in m.embeddings) - 1
inp = [torch.ones(B, T, len(m.embeddings), dtype=torch.long), torch.zeros(B, T, d_delta),
       torch.ones(B, T, len(info["ctx"]), dtype=torch.long), torch.zeros(B, T, info["ctx_num"]),
       torch.ones(B), torch.full((B,), T, dtype=torch.long)]
if info["has_bag"]:
    inp.append(torch.ones(B, T, a.bag_k, dtype=torch.long))
warnings.filterwarnings("ignore")
w = SummaryWriter(a.out)
w.add_graph(m, tuple(inp))
w.close()
print("graph written to", a.out)
