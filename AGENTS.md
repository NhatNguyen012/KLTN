# OpTC Research Workspace Instructions

## Active approved run (user update 2026-09-26)

The main run is now `ML/code/output/host_ml_seed02/` (formerly `code/output/host_ml_seed02/`).
Its inherited index and frozen contextual split are consolidated as `index/`
and `split/`; its 358 shards are under `model_input/volumes/ssd/`.
Older output namespaces have been removed. Use `ML/code/README.md` and
`ML/code/kaggle/docs/KAGGLE_RUNBOOK.md` for current paths and the approved experiment.
The frozen split seed is 02; notebook sampling seed is separately 1. Do not
rebuild or replace the approved artifacts using the general seed-01/full-corpus
instructions below. Historical metadata paths/hashes are provenance, not current
output destinations. Preserve them; only active location metadata was relocated.

## Separate provenance experiment (user update 2026-09-26)

The user authorizes `ML/code/provenace_graph/` (spelling intentional) as a separate
workspace with its own preprocess/test/notebook/docs subfolders. Generated artifacts
belong in `ML/code/output/provenace_graph/`. Its purpose is a lightweight two-hop
Host/Process graph supporting the LightGBM cascade; it is not the Network DL branch.
Reuse the frozen seed02 split for the first comparison, keep baseline artifacts
unchanged, and never use true ancestor labels or future evidence as features.
The user clarified that this must be a learned provenance graph model, not another
RF/XGB/LGBM pipeline or only engineered ancestry columns. The active implementation
is in `ML/code/provenace_graph/model/`; preserve the raw-index checkpoint and consult
its README before restarting the scanner.

## Project scope (user update 2026-10-20)

This workspace develops an APT-detection architecture from the corrected DARPA
OpTC dataset. The architecture source of truth is
`analyst/image/general_model_architect.png`.

The implemented system has two model branches:

**Host ML branch** (`ML/` directory, Nguyen Nhat Nguyen):
- **LightGBM** — primary tree model, fully trained, baseline F1 ~0.985 on OpTC.
  This is the ONLY tree model receiving new code and Incremental Learning work.
  RF and XGBoost checkpoints exist from earlier experiments but are NOT targets
  for new code development. Do not write new training, fine-tuning, or
  preprocessing code targeting RF or XGBoost.
- **2-hop GraphSAGE** — learned relational graph model providing provenance
  context to LightGBM via a cascade. Architecture: two relational mean-message
  layers (32→16), Process+Host nodes, four relations (creates, communicates,
  communicates_reverse, hosts), 40 node attributes, 9,041 trainable parameters.
  Code: `ML/code/provenace_graph/`. Cascade notebook:
  `ML/code/kaggle/notebooks/lgbm_conditional_collision_cascade.ipynb`.
  Sample TEST standalone F1: 0.937 (2,000-row sample; not representative of full set).

**Network DL branch** (`DL/` directory, Vo Ngoc Hoang Lam):
- **BiLSTM** — primary sequence model on 15-minute flow windows. Pipeline v2,
  fully trained on OpTC, TEST F1: 0.988. This is the ONLY DL model receiving
  new code and Incremental Learning work. Mixed-Type Self-Attention exists in
  the same pipeline but is NOT a target for new code development. Do not write
  new training or fine-tuning code targeting Mixed-Type Self-Attention.
- Current input features from eCAR-Bro (host context): `app_family`,
  `image_dir_class`, `principal_class`. From Bro conn (network L3/L4):
  `proto`, `service`, `conn_state`, `resp_port_class`, `duration`, `orig_bytes`,
  `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`,
  `has_missed_bytes`, `delta_t_log1p`.
- Pipeline v2 code: `DL/01_code/pipeline_v2/`. Training on Kaggle via notebooks
  `DL/04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb`. Results and artifacts:
  `DL/02_artifacts/22_v2_pipeline/`. State document: `DL/CLAUDE.md`.
- Known limitation: high F1 (0.988) is primarily due to `powershell.exe`
  shortcut signal and beacon C2 pattern — not true generalization. Documented
  in `DL/CLAUDE.md`. Metric improvements via Host-Based network fields (OS-native
  FLOW events) are planned for Incremental Learning tasks.

Their outputs are intended to be combined by context-aware fusion using gating
and source masks. The fusion branch is not yet implemented.

## Incremental Learning roadmap (user update 2026-10-20)

The next milestone extends both branches to new datasets via Incremental Learning
(Fine-tune + Replay Buffer). This is a research extension, not a rebuild of the
existing baseline.

**Approved additional datasets:**
- **`DATASET/skrghosh/`** (Windows 10, MITRE Caldera — Task 2): Applicable to
  LightGBM, GraphSAGE, and BiLSTM. Contains Sysmon FLOW events (START/FLOW,
  MESSAGE/FLOW) with native OS network fields: `dest_ip`, `dest_port`, `src_ip`,
  `src_port`, `l4_protocol`, `image_path`, `size`. Labels 100% complete in
  `DATASET/skrghosh/labeled/`. Campaigns: APT29, FIN6, Oilrig, MenuPass,
  Wizard Spider.
- **`DATASET/AIT_Log_V2.1/`** (Linux Debian/Kali — Task 3): Applicable to
  LightGBM and BiLSTM. Contains Linux auditd host events and Suricata IDS
  network events (flow, alert, dns, tls, http in eve.json). Labels 100%
  complete in `DATASET/AIT_Log_V2.1/labeled/`.

**Incremental Learning rules:**
- LightGBM: use `init_model` to append new trees; existing weights frozen.
  Replay Buffer = 10–20% random sample from previous TRAIN shards mixed into
  each new training batch.
- BiLSTM: gradient fine-tuning with LR ≤ 1e-5; Replay Buffer = 20–30% replay
  windows from previous TRAIN shards. Do not change model architecture.
- GraphSAGE: full fine-tune (all 9,041 params, LR = 1e-5), 30% replay ego
  graphs from OpTC TRAIN. Requires new `build_ait_graph.py` (Linux auditd
  adapter, not yet written) for Task 3.
- `vocab.json` expansion: append-only. Existing indices 0→N are frozen.
  New task tokens appended from N+1. Fit only from the new task TRAIN partition.
  Apply canonical semantic mapping before tokenization:
  PROCESS_CREATE / execve / fork → PROC_SPAWN;
  FILE_WRITE / write / sys_write → FILE_WRITE;
  NETWORK_CONNECT / connect / bind → NET_CONNECT; etc.
- Replay Buffer does not require re-tokenizing old shards through the new vocab
  because existing token indices are unchanged. Simply sample existing shards.

## Data sources and references

The corrected OpTC dataset lives under `DATASET/DARPA-OPTC/`. Its sub-directories
and their interpretation are documented in
`DATASET/DARPA-OPTC/a_new_hope_for_darpa_optc/A New Hope for DARPA OpTC.pdf`:

- `DATASET/DARPA-OPTC/host-begnin/` — eCAR host/provenance telemetry, benign
  periods 16–22/09. The directory name `host-begnin` is intentionally misspelled
  in the workspace; always use that exact path.
- `DATASET/DARPA-OPTC/host-malicious/` — eCAR host telemetry, attack periods
  23–25/09 (Scenario 1, 2, 3). SC3 has only 2 hosts and very few events.
- `DATASET/DARPA-OPTC/bro/` — Bro/Zeek network telemetry.
- `DATASET/DARPA-OPTC/ecar-bro/` — linkage/normalization data between eCAR and
  Bro. Used by the DL branch (inner join on bro_uid=uid) to enrich flows with
  host context.

Additional datasets evaluated and labeled (see `DATASET/NewDataset.md`):
- `DATASET/skrghosh/` — Windows 10 Caldera APT, Sysmon events, labeled 100%.
- `DATASET/AIT_Log_V2.1/` — Linux multi-modal (auditd + Suricata), labeled 100%.
- `DATASET/DARPA-TC-E3-THEIA/` — Linux Ubuntu provenance graph (Parquet/CSV);
  has `netflow_node_table` with src_addr, src_port, dst_addr, dst_port.
- `DATASET/DARPA-TC-E3-CADETS/` — FreeBSD provenance graph, similar to THEIA.

Research papers: `DATASET/research/papers/`. Code references: `DATASET/research/
code_references/`. Existing analyses: `analyst/`. Do not treat small samples as
proof of full-corpus distributions.

## Hard read-only boundary

The following dataset directories are read-only inputs. These paths are correct
and current as of 2026-10-20:

- `DATASET/DARPA-OPTC/host-begnin/`
- `DATASET/DARPA-OPTC/host-malicious/`
- `DATASET/DARPA-OPTC/ecar-bro/`
- `DATASET/DARPA-OPTC/bro/`
- `DATASET/skrghosh/` (all JSON source files; `labeled/` is also read-only input)
- `DATASET/AIT_Log_V2.1/fox_dataset/` and `DATASET/AIT_Log_V2.1/harrison_dataset/`
  (raw logs; `labeled/` was generated by the labeling script and is now a
  read-only input)
- `DATASET/DARPA-TC-E3-THEIA/`
- `DATASET/DARPA-TC-E3-CADETS/`
- `DATASET/research/` (papers and code references — never edit)

Never create, edit, rename, move, delete, decompress in place, or write caches,
indexes, checkpoints, logs, temporary files, or generated artifacts anywhere
inside these directories. Reading and streaming their existing files is
allowed. Put every derived artifact under `ML/code/output/` or `DL/` artifact
directories or another explicitly approved writable directory outside dataset roots.

Before running code that writes files, resolve and verify its output paths. A
script must reject any output or checkpoint path nested under a read-only data
root. Preserve source filenames, contents, permissions, and timestamps whenever
possible.

## Current vocabulary objective

The approved frozen vocabulary and split (seed 02) are already built under
`ML/code/output/host_ml_seed02/`. Do not rebuild unless explicitly instructed.

For Incremental Learning tasks only:
- Fit new tokens exclusively from the new task TRAIN partition.
- Never modify existing token indices (0 → N-1 from OpTC are frozen).
- Record expansion provenance in `vocab_metadata.json`.
- The default first representation is binary sparse presence; counts and TF-IDF
  are ablations.

Avoid evaluation leakage: fit vocabulary and any feature transforms on the
training partition only.

## Code and artifact layout

**ML branch** (`ML/` at workspace root):
- `ML/code/preprocess/` — Host ML preprocessing pipeline
- `ML/code/kaggle/` — Kaggle training notebooks and packaging
- `ML/code/provenace_graph/` — 2-hop GraphSAGE implementation and cascade
- `ML/code/output/host_ml_seed02/` — approved artifacts (358 shards, split, vocab)
- `ML/code/output/provenace_graph/` — GraphSAGE graph index and ego cache
- `ML/MENU.md` — file-role map; read before inspecting any ML code

**DL branch** (`DL/` at workspace root):
- `DL/01_code/pipeline_v2/` — BiLSTM pipeline v2 (active; scripts s1–s7)
- `DL/02_artifacts/22_v2_pipeline/` — build artifacts per step (S1–S7)
- `DL/04_notebooks/` — Kaggle training notebooks (06d BiLSTM, 07d Mixed-Type)
- `DL/05_models/v2_final/` — trained model checkpoints
- `DL/00_docs/ai_agent/HANDOFF_V2_PIPELINE.md` — current state document
- `DL/CLAUDE.md` — read before inspecting any DL code
- Pipeline v1 (`DL/01_code/pipeline/`, steps 00→21) is historical; do not use
  to generate new artifacts.

**General rules:**
- Update `ML/MENU.md` whenever a source file's role, location, or generated
  artifacts change materially.
- Put generated vocabularies, metadata, matrices, logs, and resumable state in
  `ML/code/output/`, never in a dataset or paper directory.
- Treat papers and reference implementations as evidence; do not edit them.

The active preprocessing order for Host ML (already complete for OpTC baseline):
`ML/code/preprocess/build_host_index.py` → `build_split.py` →
`build_vocab.py --split` → `build_model_input.py`.
Run only for new Incremental Learning tasks with new datasets.

Additional preprocessing storage authorized: up to 100 GB under
`/home/nguyen/optc_model_input`, spare capacity under
`/mnt/HDD_Data/optc_model_input` and `ML/code/output/host_ml/model_input/volumes/ssd`.
Use quotas in `ML/code/others/model_input_volumes.json`. Training on Kaggle only.

## Engineering expectations

- Inspect existing implementations and analyses before changing behavior.
- Keep tokenization deterministic, bounded, non-executing, and auditable.
- Never execute command lines or decoded payloads found in telemetry.
- Use atomic publication for final artifacts and durable checkpoints for long
  scans. Do not replace a valid prior artifact with a partial or failed result.
- Preserve unrelated user changes and avoid destructive commands.
- Add or update focused regression tests for behavior changes. Run the relevant
  local tests before reporting completion.
- Record corpus scope, source hashes, tokenizer policy, frequency thresholds,
  split assumptions, and checkpoint/resume details in generated metadata.
- Clearly distinguish measured results from architectural plans and research
  hypotheses.
- **ML tree models:** new code targets LightGBM only. Do NOT write new training,
  fine-tuning, or preprocessing code for RF or XGBoost.
- **DL models:** new code targets BiLSTM only. Do NOT write new training or
  fine-tuning code for Mixed-Type Self-Attention.

Useful local checks include:

```bash
python3 ML/code/test/test_build_vocab.py
python3 ML/code/test/test_ecar_tokenizer.py
python3 ML/code/preprocess/build_host_index.py --dry-run
```
