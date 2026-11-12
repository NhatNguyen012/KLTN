"""Reject outputs inside dataset inputs before creating any generated files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]


def validate_output_dir(path):
    out = Path(path).resolve()
    protected = [ROOT / "DATASET"] + [ROOT / n for n in
                 ("host-begnin", "host-malicious", "ecar-bro", "bro")]
    protected += list((ROOT / "DATASET").glob("*/host-begnin"))
    for base in protected:
        if out == base.resolve() or base.resolve() in out.parents:
            raise ValueError(f"Generated output must be outside dataset inputs: {out}")
    return out
