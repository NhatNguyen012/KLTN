# OpTC Research Workspace Instructions

## Project scope

This workspace develops an APT-detection architecture from the corrected DARPA
OpTC dataset. The architecture source of truth is
`analyst/image/general_model_architect.png`.

The intended system has two model branches:

- Host ML Agent: XGBoost, LightGBM, and Random Forest over eCAR host telemetry.
- Network DL Agent: GraphSAGE, GAT, BiLSTM, and Mixed-Type Self-Attention over
  network telemetry.

Their outputs are intended to be combined by context-aware fusion using gating,
cross-attention, and source masks, followed by APT detection, confidence
estimation, evaluation, and incremental retraining.

The current milestone is the local Host ML supervised preprocessing pipeline.
Build deterministic, interpretable structure-aware semantic features for RF,
XGBoost and LightGBM. The Network DL and fusion branches are future
work unless the user explicitly changes the scope.

## Data sources and references

The corrected dataset and its interpretation are documented in
`a_new_hope_for_darpa_optc/A New Hope for DARPA OpTC.pdf`. The three related
data views are:

- `host-begnin/` and `host-malicious/`: eCAR host/provenance telemetry. The
  directory name `host-begnin` is intentionally misspelled in the workspace;
  always use that exact path.
- `bro/`: Bro/Zeek network telemetry.
- `ecar-bro/`: linkage/normalization data between eCAR and Bro.

Research papers that may inform the design are stored in `paper-token/` and
`paper-general/`. Existing analyses are in `analyst/`, and small inspection or
test fixtures are in `analyst/sample/`. Do not treat a small sample as proof of
full-corpus distributions.

## Hard read-only boundary

The following dataset directories are read-only inputs:

- `host-begnin/`
- `host-malicious/`
- `ecar-bro/`
- `bro/`

Never create, edit, rename, move, delete, decompress in place, or write caches,
indexes, checkpoints, logs, temporary files, or generated artifacts anywhere
inside these directories. Reading and streaming their existing files is
allowed. Put every derived artifact under `code/output/` or another explicitly
approved writable directory outside the dataset roots.

Before running code that writes files, resolve and verify its output paths. A
script must reject any output or checkpoint path nested under a read-only data
root. Preserve source filenames, contents, permissions, and timestamps whenever
possible.

## Current vocabulary objective

Use corrected Host events from `host-begnin/` and `host-malicious/` (16–25/09).
Create one persisted stratified random event split: 75% TRAIN, 10% validation,
15% test, seed 1 (displayed as 01). RF/XGBoost/LightGBM must reuse this same
split. Fit vocabulary from BOTH benign and malicious events assigned to TRAIN;
validation/test only transform. Never fit from Bro or eCAR-Bro data.

Use the design and evidence in
`analyst/host_ml_tokenization_research.md`. In this project,
"structure-aware semantic tokenization" is a deterministic engineering
adaptation for sparse tree-model features. It is inspired by Toolscaler's
shared-code principle but is not an implementation of Toolscaler's learned
neural codebooks.

Tokens should preserve, where applicable:

- field-scoped lexical evidence;
- launcher, switch, operand, operator, and command-family structure;
- semantic types of dynamic values rather than unique raw identifiers;
- explicit principal-action-object, switch-value, process-lineage, path, and
  endpoint relationships;
- safe AST node and edge types when parsing embedded code without executing it.

Keep high-cardinality execution identifiers available only in untouched source
records for future graph joins; do not turn arbitrary IDs, UUIDs, PIDs, memory
addresses, or user-specific values into vocabulary features.

`vocab.json` maps token strings to sparse feature-column indices. Those integers
are not ordinal token values. The default first representation for the Host ML
models is binary sparse presence; counts and TF-IDF are ablations.

Avoid evaluation leakage: fit the vocabulary and any feature transforms on the
training partition only. Record split identity in vocabulary and matrix metadata.
This random-event baseline does not establish temporal, process or campaign
generalization. Report precision-recall behavior and false-positive rates.

## Code and artifact layout

- Put local preprocessing, tokenization, indexing, matrix-building, testing,
  and orchestration code in `code/`.
- Complete and validate the local pipeline before adapting it for Kaggle.
- Put Kaggle-specific training or packaging code in `code/kaggle/`; do not make
  Kaggle copies the primary implementation while local work is incomplete.
- Put generated vocabularies, metadata, matrices, logs, and resumable state in
  `code/output/`, never in a dataset or paper directory.
- Treat papers and supplied reference implementations as evidence. Do not edit
  them unless the user explicitly asks for such a change.

The active order is `build_host_index.py`, `build_split.py`, `build_vocab.py --split`,
then `build_model_input.py` (compressed binary shards, no global CSR merge).
Keep already-built index/split/vocabulary unchanged when updating downstream
packaging. Re-running compatible commands resumes
automatically. Checkpoints must be written outside all dataset roots and must be
validated against the scan configuration, source-file identity, and tokenizer
code before reuse.

Example vocabulary fit after publishing the shared split:

```bash
nohup python3 /mnt/SSD_Data/optc/code/build_vocab.py \
  --split /mnt/SSD_Data/optc/code/output/host_ml/split/manifest.json \
  --output /mnt/SSD_Data/optc/code/output/host_ml/vocab.json \
  --metadata-output /mnt/SSD_Data/optc/code/output/host_ml/vocab_metadata.json \
  --workers 4 \
  > /mnt/SSD_Data/optc/code/output/build_vocab.log 2>&1 &
```

Additional preprocessing storage authorized by the user: up to 100 GB of output
under `/home/nguyen/optc_model_input`, and spare capacity under
`/mnt/HDD_Data/optc_model_input` and `code/output/host_ml/model_input/volumes/ssd`.
Use the quotas/free-space reserves in `code/model_input_volumes.json`. These are
output directories, not dataset roots. Training remains on Kaggle; do not launch
full local training as part of preprocessing.

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

Useful local checks include:

```bash
python3 code/test_build_vocab.py
python3 code/test_ecar_tokenizer.py
python3 code/build_host_index.py --dry-run
```
