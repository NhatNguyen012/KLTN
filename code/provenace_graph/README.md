# Lightweight learned provenance graph

## Generated artifact retention

The 2026-10-17 cleanup retained `kaggle_output/`,
`conditional_collision_v4_results/`, and `evidence_veto_v4_results/`. The new
exact-time GraphSAGE experiment adds its own `exact_time_graph/`,
`exact_time_ego_cache/`, and `kaggle_upload_exact_time_graphsage/` outputs.
Unrelated old indexes, caches, bundles, temporary runs, and v5a artifacts remain
removed. Existing conditional-v4 results and baseline outputs are untouched.

## Exact-time GraphSAGE retraining

The v4 inference graph used exact microsecond cutoffs, but its GraphSAGE
checkpoint had been trained on ego graphs floored to one-second boundaries. This
separate run keeps the Process/Host nodes, four relations, 40 attributes, two
GraphSAGE layers and readout unchanged. It rebuilds label-blind graph context
from the same frozen seed02 sources, then materializes TRAIN/validation/TEST ego
graphs with `quantum_us=1`. Each cached cutoff is checked against its target
event's original timestamp; every indexed evidence timestamp must be strictly
less than that cutoff. The GPU trainer and package builder reject any other
time policy, and the runtime ego-graph encoder now rejects any request to round
timestamps (`quantum_us` other than 1).

Build the full graph index, exact-time sampled cache, and upload archive from the
repository root:

```bash
python3 code/provenace_graph/preprocess/build_graph.py \
  --baseline code/output/host_ml_seed02/model_input/manifest.json \
  --split code/output/host_ml_seed02/split/manifest.json \
  --output code/output/provenace_graph/exact_time_graph

python3 code/provenace_graph/preprocess/build_ego_cache.py \
  --baseline code/output/host_ml_seed02/model_input/manifest.json \
  --graph code/output/provenace_graph/exact_time_graph \
  --output code/output/provenace_graph/exact_time_ego_cache \
  --quantum-us 1 --train-limit 4000 --val-limit 2000 --test-limit 2000

python3 code/provenace_graph/preprocess/package_ego_cache.py \
  --cache code/output/provenace_graph/exact_time_ego_cache \
  --output-dir code/output/provenace_graph/kaggle_upload_exact_time_graphsage
```

Attach the prepared dataset in Kaggle so its extracted files are mounted at
`/kaggle/input/datasets/ngkimngn/provenance-exact-time-graphsage`, then import
`notebook/provenance_graph_exact_time_gpu.ipynb` from this workspace and enable
a Kaggle GPU. The notebook reads the mounted manifest and shards directly; it
does not search for or extract the TAR again. It trains a new checkpoint,
selects the threshold on validation, reports cached sample TEST metrics, and
exports `exact_time_graphsage_results.zip`. This is a
GraphSAGE-only sampled evaluation; a full LightGBM cascade run needs the new
checkpoint integrated into a separately versioned inference bundle.

## Full cascade with the exact-time checkpoint

The sampled checkpoint passed export compatibility: loading its NumPy weights
in `RelationalSAGE` reproduced the validation and sample-TEST confusion counts.
The separate full input is packaged at
`code/output/provenace_graph/kaggle_upload_cascade_exact_time_graphsage/` as
`provenance-cascade-exact-time-graphsage.tar.gz`. It contains the complete
1.81-GB graph SQLite index, the new checkpoint, its training/cache audit, and
the unchanged seed02 LightGBM checkpoint. Attach it at
`/kaggle/input/datasets/ngkimngn/optc-cascade-exact-time-graphsage` together
with the existing `optc-host-ml-full-input`, then run
`code/kaggle/notebooks/lgbm_conditional_collision_cascade.ipynb`.

That notebook no longer accepts the old v4 graph-score cache. It calculates
scores with the new checkpoint, builds ego graphs with bounded CPU worker processes, each using its own read-only
SQLite connection, then batches float64 inference across all visible CUDA GPUs
with `DataParallel` (verified against the NumPy scorer). SQLite target lookups
and Host shard decoding also use CPU. The worker queue is bounded to control RAM. The TRAIN collision registry is reused
when its frozen Host manifest/schema match, and validation plus TEST checkpoints
are saved after each shard with model/data hashes; they can resume across CPU/GPU
configurations, including a timeout before validation policy freeze. TPU is not used
by this irregular graph workload. Enable all available Kaggle GPUs to use the
multi-GPU scorer.
For a fresh Kaggle session, attach the prior notebook output and set `RESUME_FROM`
in the setup cell to the mounted output folder; in the same working session,
rerunning uses the existing checkpoint directory automatically.
The 2,000-row sample TEST result is a readiness check, not a replacement for the
full held-out evaluation. At the validation-selected standalone threshold
`0.9001769`, the sample TEST GraphSAGE F1 is `0.93694`; at the cascade's fixed
middle-band threshold `0.95`, graph-only sample F1 is `0.86538` (45 TP, 3 FP,
11 FN, 1,941 TN). These all-event sample metrics do not predict performance on
the ML-routed middle-band cohort, so the full validation-selected cascade run
must decide whether the new checkpoint is useful.

## Event-only v5a experiment

The isolated v5a variant adds **one target Event node per ego graph** to the
existing Process/Host graph. It has a `node=event` bit and one action and one
object-type bit obtained from the frozen Host binary feature columns. For
example, a PROCESS/CREATE target has `event::action::create` and
`event::object::process`. The only new relations are actor Process → Event
(`performs`) and Event → actor Process (`performs_reverse`); the reverse edge
lets the two-layer GraphSAGE readout receive Event information. An object-type
bit does **not** create a File or Module node. No label, source identity, raw
command, or future event is used as an Event feature.

The cache builder joins target action/object columns to the **same 8,000
seed02 events** in the frozen baseline graph cache using `(source_id,
source_line)`, checking split and label identity. It copies every pre-existing
node, edge, root, cutoff and label unchanged. The sample is 4,000 balanced
TRAIN, 2,000 validation and 2,000 TEST graphs. The frozen baseline cache uses
a one-second cutoff (`quantum_us=1000000`); v5a retains that time policy to
isolate the Event-node change. This is distinct from the later v4 exact-time
full-cascade inference. The v4 checkpoint cannot score the new 71-attribute,
six-relation schema, so v5a trains a **separate** GraphSAGE checkpoint on Kaggle
GPU. LightGBM and all existing v4 artifacts remain unchanged.

The former local cache and upload archive were removed during the output cleanup.
The Event-only v5a implementation and build commands remain documented, but its
generated cache/package are no longer retained:

```text
code/output/provenace_graph/seed02_event_v5a_cache/
code/output/provenace_graph/kaggle_upload_event_v5a/provenance-event-v5a-cache.tar
```

Upload **only** the tar file as a Kaggle Dataset and run
`code/provenace_graph/notebook/provenance_event_v5a_gpu.ipynb` with GPU enabled.
The notebook accepts the uploaded tar or its extracted files, verifies the
cache, trains for 30 epochs, selects the decision threshold from validation,
then evaluates the sampled TEST and writes
`/kaggle/working/provenance_event_v5a_results.zip`. The ZIP contains metrics,
new checkpoint, NumPy weights and the cache manifest. No Host input archive,
v4 cascade bundle, raw logs or SQLite database is required for this sampled
training run. A full TEST LightGBM cascade comparison is **not** implied by
the 2,000-graph GraphSAGE sample; that requires separately scoring the full
manifest with the new checkpoint.

The Event attributes are deliberately narrow: action and object **type** only.
They do not encode file/module identity, path, command content or raw endpoint.
If a future target contains an action/object category outside this frozen
schema, inference raises an explicit error instead of silently inventing an
embedding. The builder verifies that all 8,000 selected events have exactly
one action and one object type. Rebuild commands, if the frozen inputs are
replaced with an independently approved version, are:

```bash
python3 code/provenace_graph/preprocess/build_event_ego_cache.py
python3 code/provenace_graph/preprocess/package_event_ego_cache.py
python3 code/provenace_graph/test/test_event_v5a.py
```

Both builders refuse to overwrite their existing outputs.

The corrected implementation is a **two-layer relational mean GraphSAGE model**.
It learns embeddings by passing messages along explicit Process→Process and
Host→Host edges. It is not RF, XGBoost, LightGBM, or a manually aggregated graph
feature vector. The optional risk head is a small neural linear layer.

The initial fixed-feature/tree adapter was retired: `augment_shards.py` and the
three tree-training notebooks were removed. The approved `host_ml_seed02` baseline
is unchanged. The raw SQLite graph index remains useful and is preserved.

## Model

- Nodes: Process `(event hostname, UUID)` and Host `(event hostname)`.
- Evidence: PROCESS/CREATE parent→child, observed eCAR FLOW host communication,
  and host ownership. No ancestry inferred from PROCESS/OPEN or PID reuse.
- Input: 40 finite node attributes (types, semantic roles, local observed behavior,
  and missing/ambiguous states). UUIDs, hostnames and IPs are lookup keys only.
- Encoder: two learned relational mean-message layers, widths **32 → 16**.
- Readout: actor embedding (16) + local-host embedding (16); optional sigmoid head.
- Size: **9,041 trainable parameters**; approximately 71 KiB of float64 weights,
  excluding optimizer state, sampled graph arrays and the disk index.
- Limits: 64 nodes per ego graph, eight host peers per direction per hop, strictly
  past exact-microsecond snapshots in the retraining experiment. Process ancestry
  and host neighborhoods extend two hops.
- Runtime: NumPy only for neural operations; no PyTorch/PyG installation required.

[Design, research evidence and limitations](docs/DESIGN.md).

## Current index status

The former graph index and its pilot artifacts were removed during cleanup. A
fresh exact-time index has now been built from all **106 frozen seed02 sources**
at `code/output/provenace_graph/exact_time_graph/` (8,331,257 target events).
Its 8,000-graph sampled cache and Kaggle archive are published under
`exact_time_ego_cache/` and `kaggle_upload_exact_time_graphsage/`. The cache
audit confirms all 8,000 cutoffs equal the target timestamps and all 13,576
explicit evidence timestamps are strictly earlier.

Historical scanner-resume instructions below apply only to the deleted earlier
graph build. This experiment uses a fresh output directory and does not reuse or
overwrite the old graph checkpoint:

```bash
# From the repository root; first check without starting a scan:
python3 code/provenace_graph/model/resume_index.py --dry-run

# Historical resume command; use only with the verified original source snapshot:
nohup python3 code/provenace_graph/model/resume_index.py \
  > code/output/build_graph_prov.log 2>&1 &
tail -f code/output/build_graph_prov.log
```

Use `Ctrl+C` to leave `tail` without stopping the background job. If `tail` is
already suspended in your shell, `fg` resumes that viewer, then `Ctrl+C` exits it.
For a completely new index/output, `preprocess/build_graph.py` remains the entry
point. Do not edit scanner sources during a long resumable build.

## Files

| Path | Role |
| --- | --- |
| `preprocess/build_graph.py` | Raw Host scan and durable SQLite index; preserves seed02 masks |
| `preprocess/graph.py`, `common.py` | Frozen index schema, causal lookups, safety and fingerprint support |
| `model/ego.py` | Actual typed node/edge ego-graph extraction with bounded causal neighborhoods |
| `model/relational_sage.py` | Learned graph layers, explicit backpropagation, Adam and model checkpoints |
| `model/train.py` | Standalone graph training/evaluation on frozen split labels; no tree features |
| `model/score_event.py` | Graph risk, embeddings, edge evidence and ancestor-edge ablation explanation |
| `model/resume_index.py` | Hash-checked continuation of the existing scanner checkpoint |
| `notebook/provenance_graph.ipynb` | Graph-only Kaggle workflow; no RF/XGB/LGBM training |
| `test/test_graph.py` | Index, causality, ontology, boundary and scan-resume tests |
| `test/test_learned_graph.py` | Real message passing, gradients, learning, permutation and model-resume tests |

`preprocess/graph.py` still contains the old aggregate diagnostic encoder because
its byte identity is bound to the unfinished scan. The learned model uses its raw
facts and ancestry lookup, not its 134-column tree-feature output. Old pilot reports
under `code/output/provenace_graph/` describe that earlier indexing/diagnostic test,
not a trained learned-graph result.

## Training and scoring

Training stays on Kaggle. Upload `code/output/provenace_graph/learned_graph_code.zip`
as a Kaggle dataset and attach it with the complete graph index and baseline input
package (used only for immutable labels, source-line identity, and split membership).
Keep the baseline manifest and its `assets/` directory together. The archive includes
the scanner-fingerprint files `preprocess/graph.py`, `preprocess/build_graph.py`, and
`preprocess/common.py`; a manually assembled source-tree dataset must include all
three. The notebook extracts the archive automatically and remaps shard volumes from
manifest-relative paths beneath the Kaggle input mounts. The trainer refuses
prefix-limited graphs.
Its default CPU budget is 4,000 balanced TRAIN rows and 2,000 uniform rows for
each validation/test sample. The sampler reads every shard's compact label array to
obtain a reproducible global reservoir, but performs SQLite graph lookup only for
selected rows. Each two-hop graph is materialized once and reused across epochs.
These are smoke/initial-experiment budgets, not the full baseline sample. Set
`--val-limit 0 --test-limit 0` only for a separately budgeted full-partition
evaluation. The saved metrics explicitly distinguish sampled from full scope.

```bash
python3 code/provenace_graph/model/train.py \
  --graph code/output/provenace_graph/graph \
  --baseline code/output/host_ml_seed02/model_input/manifest.json \
  --output code/output/provenace_graph/learned_model \
  --epochs 5 --train-limit 4000 --val-limit 2000 --test-limit 2000 --evaluate-test
```

Use matching arguments plus `--resume` to continue from the last complete epoch.
Alternating model slots preserve Adam state, shuffle RNG state and checkpoint
identity. New code/configuration requires a new output. Validation chooses the
threshold; no test labels enter fitting or selection. Balanced-training scores
are risk scores, not calibrated real-world probabilities. The random event split
can share processes across partitions and is not an unseen-process evaluation.

```bash
python3 code/provenace_graph/model/score_event.py \
  --graph code/output/provenace_graph/graph \
  --model-dir code/output/provenace_graph/learned_model \
  --source-id SOURCE_ID --source-line RAW_LINE_NUMBER
```

Scoring returns learned process/host embeddings and graph-edge evidence. Removing
an ancestor edge measures model sensitivity, not a proven malicious root cause.
Embeddings may later support the existing Host ML ensemble; that integration is
not implemented here. No true parent/grandparent labels are model inputs.

## Validation status

Only synthetic neural training and the earlier bounded 20,000-line raw-data index
pilot have run locally. The neural tests demonstrate two-hop influence, loss
reduction, analytic-gradient agreement, permutation equivariance, and exact optimizer
resume. The tiny end-to-end training/resume test uses synthetic rows only. Full
OpTC accuracy, FP/FN improvement, and production throughput remain unmeasured.
Reports: `code/output/provenace_graph/learned_graph_tests.log`, `index_tests.log`,
and `learned_smoke_test.json`.


## Cached GPU workflow

The direct SQLite lookup notebook is retained as a small debugging path only. It
is not suitable for Kaggle-scale graph extraction: the GPU model is fast, while
random SQLite reads and per-event causal graph construction are slow. The
recommended experiment has two stages:

```text
complete label-blind graph.sqlite + frozen seed02 masks
  -> local CPU and SSD: static strict-past ego-graph cache (one time, resumable)
  -> Kaggle GPU: sequential cache reads + batched relational GraphSAGE
```

`preprocess/build_ego_cache.py` preserves the current graph semantics: a
maximum-two-hop CREATE ancestry, observed Host communication, 40 finite node
attributes, no raw telemetry/node IDs as features, no ancestor labels, and only
evidence strictly before the target timestamp. It first selects the same global
seeded samples from the frozen seed02 shard labels, then persists only source
line provenance and graph tensors. The default cache contains 4,000 balanced
TRAIN graphs plus 2,000 uniform validation and 2,000 uniform test graphs.

The static tensor format is compressed NPZ rather than a Torch pickle so a
CPU-only local workstation can build and verify it. `model/train_gpu.py` turns
those arrays into CUDA tensors and performs relation-specific mean GraphSAGE
batching with PyTorch; PyTorch Geometric is not required.

Build locally from the repository root. The command can be interrupted and
restarted with identical arguments; completed parts are checksum-validated and
resumed.

```bash
nohup python3 code/provenace_graph/preprocess/build_ego_cache.py \
  --graph code/output/provenace_graph/graph \
  --baseline code/output/host_ml_seed02/model_input/manifest.json \
  --output code/output/provenace_graph/seed02_ego_cache \
  --train-limit 4000 --val-limit 2000 --test-limit 2000 \
  --graphs-per-shard 250 --sqlite-cache-mib 256 \
  > code/output/provenace_graph/build_ego_cache.log 2>&1 &

tail -f code/output/provenace_graph/build_ego_cache.log
```

After the final manifest is published, package it without rebuilding. The
historical package path below is not currently retained:

```bash
python3 code/provenace_graph/preprocess/package_ego_cache.py \
  --cache code/output/provenace_graph/seed02_ego_cache
```

Historically this published
`code/output/provenace_graph/kaggle_upload_seed02_ego_cache/provenance-ego-cache.tar`.
That generated archive was removed in the 2026-10-17 cleanup. After rebuilding,
upload the TAR as a Kaggle Dataset. Attach it and import
`notebook/provenance_graph_gpu.ipynb`; enable a GPU accelerator. The GPU notebook
extracts the archive safely and needs neither the 1.8 GiB SQLite graph nor the
Host ML shard package.

## Frozen RF/XGBoost/LightGBM cascades (v3)

The former Kaggle cascade bundle was
`code/output/provenace_graph/kaggle_upload_cascade_v3/provenance-cascade-bundle-v3.tar.gz`.
It contained the approved seed02 checkpoints and metrics for all three Host models,
plus the frozen learned GraphSAGE weights, graph index, and shared runtime. The
generated bundle was removed in the 2026-10-17 cleanup; rebuild it before upload.
Attach the existing `optc-host-ml-full-input` dataset and the new v3 bundle. Import
one of `notebook/host_two_stage_cascade.ipynb` (LightGBM),
`notebook/host_rf_two_stage_cascade.ipynb`, or
`notebook/host_xgb_two_stage_cascade.ipynb`. The notebook discovers Kaggle's
already-extracted dataset directories at the configured user paths, or extracts a
single attached archive. RF requires the saved scikit-learn 1.6.1 environment.

Each notebook uses its own approved Host model and threshold, selects a cascade
policy using measured full validation F1, then verifies the frozen model's full
validation and test confusion before publishing the full-test cascade result.
The result ZIP includes exact `test_errors.jsonl` source-line IDs and ML/graph
scores for future raw telemetry analysis, plus the notebook's confusion and
metric/routing plots. The v3 measured LightGBM F1 is 98.48%; XGB's measured F1
is 98.03%. These results use the one-second causal snapshot, not the v4 input.

## Exact-time LightGBM cascade input (v4)

`preprocess/package_cascade_v4.py` publishes
`code/output/provenace_graph/kaggle_upload_cascade_v4/provenance-cascade-bundle-v4.tar.gz`.
This generated bundle was removed in the 2026-10-17 cleanup; the retained v4
experiment outputs are results only.
The graph database and frozen model checkpoints are unchanged from v3; the bundled
ego-graph code uses the event's full microsecond timestamp and admits only evidence
strictly earlier than that event. This restores earlier CREATE events inside the
same second. The existing GraphSAGE checkpoint was trained with the old one-second
snapshot, so v4 changes its inference input distribution without retraining. Its
F1 is unknown until validation/test evaluation is run.

Upload v4 as the `optc-cascade-bundle` Kaggle dataset (or attach an extracted v4
bundle), keep `optc-host-ml-full-input` unchanged, and run
`code/kaggle/notebooks/lgbm_two_stage_cascade.ipynb`. This notebook uses the
previous LightGBM cascade policy search, not the later joint-decision experiment.
It selects thresholds on validation only, evaluates all test events, and verifies
that the downloadable ZIP includes every final FP/FN with scores, route and raw
source-line mapping. `test_errors_full_scores.jsonl` also supplies a diagnostic
GraphSAGE score for direct-route errors; those scores are computed after the
decision and do not change predictions.

The matched raw-event analysis of the existing LightGBM cascade is in
`analyst/cascade_fn_fp_raw_comparisons.md`.
