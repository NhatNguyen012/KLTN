"""Fuse residual LightGBM boosters into one booster: z = sum_k w_k * z_k(x[:, :width_k]).

The IL chain trains residual boosters on prefix-compatible feature spaces (vocabulary extension appends columns, old
column ids never move), so a tree of an older booster reads the same column ids in the widest space. Scaling every
leaf value of booster k by w_k (its first tree carries its init score) and concatenating the trees gives one model
whose raw score equals the weighted sum, which the endpoint can run as a single LightGBM text model.
"""
from __future__ import annotations

import re


def _split(text: str):
    head, _, rest = text.partition("\nTree=")
    if not rest:
        raise ValueError("model has no trees")
    trees_part, _, _tail = ("Tree=" + rest).partition("end of trees")
    blocks = [b for b in re.split(r"(?m)^(?=Tree=\d+$)", trees_part) if b.strip()]
    header = {}
    order = []
    for line in head.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            header[k] = v
            order.append(k)
        elif line.strip():
            header[line.strip()] = None
            order.append(line.strip())
    return header, order, blocks


def _scale_block(block: str, w: float, new_index: int) -> str:
    out = []
    for line in block.splitlines():
        if line.startswith("Tree="):
            line = f"Tree={new_index}"
        elif line.startswith(("leaf_value=", "internal_value=")):
            k, v = line.split("=", 1)
            line = k + "=" + " ".join(repr(float(x) * w) for x in v.split())
        out.append(line)
    return "\n".join(out).rstrip("\n") + "\n\n"


def fuse(models: list[tuple[str, float]]) -> str:
    """models: [(model_text, weight), ...]; returns the fused model text (load with lgb.Booster(model_str=...))."""
    parsed = [(_split(t), w) for t, w in models]
    objectives = {h.get("objective") for (h, _, _), _ in parsed}
    if len(objectives) != 1:
        raise ValueError(f"objectives differ: {objectives}")
    for (h, _, _), _ in parsed:
        if h.get("num_class") != "1" or h.get("num_tree_per_iteration") != "1":
            raise ValueError("only single-output boosters can be fused")
    width = max(int(h["max_feature_idx"]) + 1 for (h, _, _), _ in parsed)
    infos = ["none"] * width
    for (h, _, _), _ in parsed:
        for i, v in enumerate(h.get("feature_infos", "").split()):
            if infos[i] == "none" and v != "none":
                infos[i] = v
    base_h, base_order, _ = parsed[-1][0]
    header = dict(base_h)
    header["max_feature_idx"] = str(width - 1)
    header["feature_names"] = " ".join(f"Column_{i}" for i in range(width))
    header["feature_infos"] = " ".join(infos)
    header.pop("tree_sizes", None)
    lines = []
    for k in base_order:
        if k == "tree_sizes":
            continue
        lines.append(k if header.get(k) is None else f"{k}={header[k]}")
    body, n = [], 0
    for (_, _, blocks), w in parsed:
        for b in blocks:
            body.append(_scale_block(b, w, n))
            n += 1
    return "\n".join(lines) + "\n\n" + "".join(body) + "end of trees\n\npandas_categorical:null\n"
