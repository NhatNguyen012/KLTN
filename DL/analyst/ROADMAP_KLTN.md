# KLTN execution roadmap — compressed OpTC → Kaggle training → fusion

This roadmap is ordered to minimize data leakage, unnecessary I/O and rework.

## Phase A — Data contract and reproducibility

### STEP 00 — Archive inventory
Read ZIP central directories only. Produce archive/member manifest, size totals, inferred source (`ecar`, `ecar-bro`, `bro`), bad-archive list and a Markdown run report.

### STEP 01 — Host token language / vocab implementation
Implement normalization rules first. Raw IDs/PIDs/hostnames never become model tokens. Parse `command_line` as inert text; normalize paths, UUIDs, SIDs, IPs and high-entropy values. Decode PowerShell `-enc` only as text and tokenize the decoded text. Produce a provisional semantic vocab for validation.

### STEP 02 — Ground truth + correction + split manifest
Use Red Team ground truth and reproducible host/network labeling policy. Decide whether to use original or corrected eCAR; if corrected labels are used, record exact version/source. Build a single immutable manifest assigning records/windows/scenarios to train/val/test. No vocabulary or scaler may be fitted using val/test.

Recommended experiment protocols:
- P0: time-aware supervised split for baseline development.
- P1: leave-one-scenario-out to measure generalization to an unseen APT scenario.
- P2: host-disjoint check where possible to measure memorization of endpoint identity.

## Phase B — Host branch

### STEP 03 — Freeze final host vocab on train only
Stream only training eCAR archives/records. Freeze `vocab_host_final.json` with hash/version. Unknown val/test tokens map to `<UNK>` or stable semantic buckets.

### STEP 04 — Host feature shards
Convert each host event to sparse multi-hot/count features plus non-token stable numeric buckets. Write compact Parquet/NPZ shards to `D:\UIT\KLTN`, partitioned by date/scenario/host. Keep join keys in metadata columns, not predictive matrix.

### STEP 05 — Host baselines
Train XGBoost, LightGBM and Random Forest. Handle imbalance using class weights / scale_pos_weight first; avoid naive random oversampling across temporal windows. Evaluate Precision, Recall, F1, PR-AUC, ROC-AUC, FPR and per-scenario metrics. Save model, config, vocab hash, split hash and Markdown report.

## Phase C — Network branch

### STEP 06 — Bro/Zeek normalization
Stream Bro CSV/log members. Keep `uid` for joining only. Engineer protocol/service/state, port class, duration/bytes/packets/log buckets, direction and history features. Treat raw IP identity carefully: topology node identity may be used in graphs, but raw IP must not become a shortcut tabular label feature.

### STEP 07 — eCAR-Bro correlation / application-centric ontology
Join `bro.uid` ↔ eCAR-Bro `properties.bro_uid`; map flow to process/application using actorID/image_path and host/IP/time. Build ontology edges such as `APPLICATION -> CONNECTS_TO -> ENDPOINT`, `APPLICATION -> USES -> PORT/SERVICE`, and temporal windows. This implements the supervisor's application-centric requirement.

### STEP 08 — Network graph/sequence datasets
Build windows (start with 5/15 min variants) and produce graph tensors + ordered flow sequences. Store PyTorch/PyG-ready shards on D drive. Record node/edge definitions and all normalization statistics fitted on train only.

### STEP 09 — Network models on Kaggle
Prepare compact derived datasets instead of uploading the 1 TB raw corpus. Train/evaluate GraphSAGE vs GAT and BiLSTM vs Mixed-Type Self-Attention. Save checkpoints and metrics back to the project structure.

## Phase D — Multi-source fusion

### STEP 10 — Alignment unit
Choose common prediction unit (recommended: application/process-centric time window). Aggregate Host ML score/embedding and Network DL score/embedding into aligned samples. Add source masks for missing host/network data.

### STEP 11 — Fusion baselines
Evaluate host-only, network-only and simple concatenation fusion first.

### STEP 12 — Context-aware fusion
Implement gating and then cross-attention if gating baseline is stable. Inputs include host representation, network representation, availability/source mask and reliability/context signals. Output APT probability + confidence.

### STEP 13 — Robustness / ablation
Drop/corrupt 10%, 20%, 30% of each source in controlled experiments. Report degradation, false-positive behavior and calibration. Ablate command-line tokens, graph component, temporal component, source mask and reliability signals.

## Phase E — continual learning + system prototype

### STEP 14 — Continual learning
Replay-buffer + periodic/incremental fine-tuning by time/scenario. Compare against full retraining in performance, forgetting and compute cost.

### STEP 15 — OpenStack prototype / dashboard flow
Implement the architecture from the proposal: endpoint log agent, tap/network collection, correlation/feature builder, central inference, dashboard/SOC verification, validated-data storage and retraining loop.

## Kaggle packaging principle

Do **not** upload or extract the full raw 1 TB OpTC dataset to Kaggle. Preprocess locally by streaming ZIPs and upload only immutable derived shards needed for a model experiment, plus vocab/split/config manifests. This makes experiments reproducible and keeps Kaggle I/O manageable.
