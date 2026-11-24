#!/usr/bin/env python3
"""Static picture (PNG + PDF) of the final DL model with torchview (needs the system package graphviz).

Usage: python3 model_picture.py <step3 run dir> <out file prefix> [--depth 2] [--pkg <dir with torchview, graphviz>]
"""
import argparse, sys, warnings
from pathlib import Path
import torch

ap = argparse.ArgumentParser(); ap.add_argument("run"); ap.add_argument("out"); ap.add_argument("--pkg", default="/tmp/viz_pkg")
ap.add_argument("--depth", type=int, default=2); ap.add_argument("--events", type=int, default=512); ap.add_argument("--bag-k", type=int, default=64)
a = ap.parse_args()
sys.path.append(a.pkg)                                           # after the system packages
sys.path.insert(0, str(Path(__file__).resolve().parent))
from model_summary import build_from_checkpoint                  # noqa: E402
from torchview import draw_graph                                 # noqa: E402

warnings.filterwarnings("ignore")
m, base, info = build_from_checkpoint(torch.load(Path(a.run) / "best.pt", map_location="cpu"))
B, T = 1, a.events
d_delta = m.event_encoder[0].in_features - sum(e.old.embedding_dim for e in m.embeddings) - 1
inp = dict(x_cat=torch.ones(B, T, len(m.embeddings), dtype=torch.long), delta=torch.zeros(B, T, d_delta),
           ctx_cat=torch.ones(B, T, len(info["ctx"]), dtype=torch.long), ctx_num=torch.zeros(B, T, info["ctx_num"]),
           has_ctx=torch.ones(B), lengths=torch.full((B,), T, dtype=torch.long))
if info["has_bag"]:
    inp["bag"] = torch.ones(B, T, a.bag_k, dtype=torch.long)
g = draw_graph(m, input_data=inp, depth=a.depth, expand_nested=True, hide_inner_tensors=True, roll=False,
               graph_name=type(m).__name__, device="cpu")
g.visual_graph.attr(dpi="130")
for fmt in ("png", "pdf"):
    print(g.visual_graph.render(a.out, format=fmt, cleanup=True))
