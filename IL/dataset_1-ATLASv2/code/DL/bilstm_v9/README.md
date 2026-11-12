# bilstm_v9 — single BiLSTM window detector for ATLASv2 CBC-EDR

1. `parse_events.py` — stream raw jsonl once (read-only) → `events/*.pkl`.
2. `build_dataset.py` — original 180 s/30 s windows, split and embargo; labels `legacy`, `v9`, `v9b`; TRAIN-only vocab.
3. `train.py` — BiLSTM (event head + window head); val-only selection of epoch/head/threshold; `--drop-fields`, `--drop-cmd` for ablations.
4. `summarize.py <dir>` — per-run and mean±std tables.
5. `reproduce.sh` — full pipeline + 5-seed final recipe.

Findings and all numbers: `../../../analyst/dl_bilstm_v9_20261112.md`.
Recommended model: `../output/bilstm_v9_20261112/final_model/` (v9b labels, `--drop-fields ip_scope`, lr 5e-4, 20 epochs).
