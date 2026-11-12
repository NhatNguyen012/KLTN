# KLTN — PROJECT STATE / HANDOFF

## Thesis

**A multi-source context-aware framework for advanced persistent threat (APT) detection** on DARPA OpTC, with:

- lightweight Host ML Agent (XGBoost / LightGBM / Random Forest),
- Network DL Agent (GraphSAGE/GAT + BiLSTM/Mixed-Type Self-Attention),
- Context-aware Fusion (gating/cross-attention + source mask/reliability),
- evaluation against host-only, network-only, simple fusion and missing-data robustness,
- later continual learning and OpenStack prototype.

## Supervisor feedback incorporated

- Many raw host fields are unstable/non-semantic; do not feed them blindly.
- `command_line` and `action` are high-value host signals.
- Host should become a normalized/tokenized language rather than a host provenance graph.
- Network should model interactions/flows and connect application activity to external communications.
- Focus on application/process behavior, not host identity.

## Non-negotiable data handling

- Raw dataset remains compressed on external disk (~1 TB ZIP archives).
- Read ZIP members directly; no bulk extraction.
- Derived outputs live in `D:\UIT\KLTN`.
- Every completed step ends with a detailed Markdown handoff/run report.

## Current completed work

- STEP 00 scaffold: project conventions, archive inventory script, path policy.
- STEP 01 scaffold: finite semantic host tokenizer + vocabulary builder; safe PowerShell encoded-command text decoding; raw unstable identities excluded from tokens.
- A provisional run on the provided `sample_ecar` is included under `artifacts/step01_sample` only as a parser/tokenizer check; it is **not** the final model vocab.

## Next exact actions

1. Copy this scaffold into `D:\UIT\KLTN`.
2. Run `00_inventory_archives.py` against the real external-drive root.
3. Review `archive_inventory.csv` and its generated `STEP_00_INVENTORY_RUN.md`.
4. Decide/obtain ground-truth labels and correction policy; build split manifest before freezing any data-derived vocab.
5. Re-run `01_build_host_vocab.py` on the training split only and freeze the final host vocab.

## Handoff protocol for future chats/agents

Read in this order:

1. `PROJECT_STATE.md`
2. newest generated `artifacts/**/STEP_*_RUN.md`
3. corresponding design note in `docs/steps/`
4. code/config referenced by that step report

Never infer completed work that is not recorded in a step report.
