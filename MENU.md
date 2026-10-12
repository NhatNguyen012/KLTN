
# OpTC workspace map

This file maps the maintained source in this workspace. The current milestone is the **Host ML preprocessing pipeline**: corrected Host telemetry is indexed, split once (75/10/15, seed `02`, frozen contextual cohort), tokenized, and written as lossless sparse shards for RF, XGBoost, and LightGBM. The `bro/` and `ecar-bro/` inputs are not part of this pipeline.

## Main run: host_ml_seed02

The teacher-approved run (formerly v4) is consolidated under
`code/output/host_ml_seed02/`. See `code/README.md` for identities and commands.
The run contains `index/`, frozen `split/`, vocabulary, `model_input/volumes/ssd/`,
the Kaggle archive, and approved training results. Older output namespaces have
been removed. Historical paths in immutable provenance describe the original run.

Only active path defaults and local notebook discovery paths changed during the
rename. Tokenizer, training runtime, split assignments, vocabulary columns, and
shard bytes remain unchanged. `maintenance/` contains restoration and relocation
records. Do not regenerate or overwrite the approved artifacts.

## Workspace roots

| Path | Role |
| --- | --- |
| `AGENTS.md` | Project rules, data boundaries, and the authoritative current pipeline order. Read this first. |
| `analyst/` | Analyst notes, sample fixtures, and architecture material; not runtime code. |
| `a_new_hope_for_darpa_optc/` | Corrected-dataset documentation. |
| `host-begnin/`, `host-malicious/` | Read-only corrected Host/eCAR telemetry inputs. `host-begnin` is intentionally misspelled. |
| `bro/`, `ecar-bro/` | Read-only network telemetry and linkage data, reserved for later Network DL/fusion work. |
| `code/` | Source code, tests, Kaggle/EC2 delivery material, and generated output. |
| `code/output/` | Generated indexes, splits, vocabulary, shards, packages, logs, reviews, and audits. It is deliberately excluded from the source-file inventory below. |
| `paper-general/`, `paper-token/` | Research references; do not edit as part of pipeline work. |
| `Temp/` | Temporary workspace material, not a pipeline input or publication location. |
| `analyst/cascade_fn_fp_raw_comparisons.md` | Matched raw-event FP/FN analysis for the measured LightGBM cascade, including exact-vector opposite-label TRAIN controls, route/score evidence and limits of the aggregate result export. |
| `analyst/cascade_v3_joint_vs_v4_exact_error_analysis.md` | Event-keyed comparison of the downloaded v3 joint-policy and v4 exact-time LightGBM results, including a same-policy time-fix comparison, raw-log CREATE/event tracebacks, and residual FP/FN causes. |
| `analyst/lgbm_v4_root_cause_sc_analysis.md` | V4-only LightGBM + GraphSAGE error traceback: full FP/FN exact-vector TRAIN controls, representative raw events, graph limitations, and SC host-cohort rates. The reproducible census and per-error control index are under `code/output/provenace_graph/audit_v4_root_causes/`. |
| `analyst/lgbm_v4_conditional_collision_kaggle_analysis.md` | Completed Kaggle conditional-collision result audit: baseline/hash reconciliation, validation-frozen thresholds, TEST FP/FN transitions, per-vector representation limits, raw examples of rescued and newly missed events, workload cost, and residual error breakdown. |

## Historical pipeline entry points

```text
read-only Host JSON/JSON.GZ
  → preprocess/build_host_index.py
  → preprocess/build_split.py     (one persisted 75/10/15 split, seed 01)
  → preprocess/build_vocab.py     (TRAIN only; benign + malicious)
  → preprocess/build_model_input.py
  → compressed, lossless binary sparse shards + manifest
  → Kaggle/EC2 notebooks using host_training_runtime.py
  → model metrics, diagnostics, and optional audit scripts
```

`build_matrix.py` is a compatible, older global-CSR route. It is useful for tests and small experiments, but it is **not** the full-corpus default: the shard route avoids a global CSR merge. All writers must keep artifacts outside the four read-only dataset roots.

## `code/preprocess/` — production preprocessing

| File | Effect / responsibility |
| --- | --- |
| `build_host_index.py` | Thin CLI entry point for `stratified_pipeline.index_main`. Streams both Host roots, records every source-line label as a compact index, fingerprints source files, and supports per-file resume. Produces the immutable input to splitting. |
| `build_split.py` | Thin CLI entry point for `stratified_pipeline.split_main`. Creates and publishes the shared stratified random event assignment: 75% TRAIN, 10% validation, 15% test, seed `01`. Every downstream supervised model must reuse it. |
| `build_split_contextual.py` | Option B contextual cohort → standard `host_random_split` masks in `host_ml_seed02/split/`. Uses available attacked-file-host baseline windows on Sep 21–22, retains all eligible positives and benign events in the 42 inclusive attack windows, records missing benign files, validates old index labels against current eligibility, checkpoints per source, and atomically publishes. Dry-run checks coverage without scanning raw events; current index has 32/34 baseline hosts, 106 files and 268,734 eligible positives; selected totals require a real run. |
| `stratified_pipeline.py` | Implements the indexed/split workflow and shared helpers: source identity and hashes, atomic publication, compact gzip label/split streams, deterministic assignment, TRAIN-only two-class vocabulary fitting, and the compatible matrix-building path. It enforces that excluded rows stay excluded and that all stages bind to the same artifacts. |
| `build_vocab.py` | Approved vocabulary builder; supply the approved split explicitly. Reads the persisted split, scans only rows assigned to TRAIN from **both** labels, tokenizes them, counts TF/DF, applies frequency/layer/cap rules, and atomically writes `vocab.json` plus provenance-rich metadata. Supports bounded, resumable scanning; its explicit `--roots` mode is retained only for historical benign-only experiments/tests. |
| `ecar_tokenizer.py` | Pure, non-executing structure-aware Host-event tokenizer. Policy v5 canonicalizes duplicate switch/launcher/DLL features and dynamic pipe/hex literals; retains XSL/Office extensions, finite Office path roles alongside location, and richer registry categories. Converts eligible eCAR records into deterministic field, command, relationship, semantic-value, and safe embedded-code tokens; excludes `FLOW`. Feature changes require a newly fitted vocabulary and rebuilt shards. |
| `command_syntax.py` | Bounded lexer used by the tokenizer for Windows argv, CMD clauses, and PowerShell text. Identifies safe spans/operators without executing or decoding telemetry payloads; unsupported syntax is kept opaque and audited. |
| `pipeline_contract.py` | Shared safety and compatibility contract. Rejects output paths under data roots (including through symlinks), synchronizes directories, hashes implementation files, and validates a frozen vocabulary/metadata pair against the expected TRAIN split. Allows one hash-pinned, reviewed v4→v5 feature-only migration to reuse immutable split assignments; frozen vocabulary compatibility remains exact. |
| `build_model_input.py` | Approved shard builder; supply the approved split/vocabulary/output paths explicitly. Validates the published split/vocabulary pair, tokenizes every eligible event once, and writes lossless binary sparse NPZ shards across approved volumes. It resumes from durable receipts, copies the reader, vocabulary and split-manifest assets, and notebooks beside the manifest, and never assembles a global CSR matrix. Accepts the approved `host_random_split` manifest. |

| `host_shards.py` | Defines the portable shard format and readers/writers. Stores row nonzero counts, delta-encoded feature columns, labels, and source-line deltas in compressed NPZ; validates hashes and reconstructs one shard at a time into CSR when a consumer needs it. |
| `shard_storage.py` | Volume-management layer for shard construction. Loads the approved volume quota configuration, locks the build, selects an output volume with reserve space, places files atomically, and preserves resumable completed shards when capacity is exhausted. |
| `shard_metrics.py` | Bounded-memory streamed validation/test evaluator for shard consumers. Chooses a threshold from validation only and reports binned ranking/threshold metrics without materializing an entire split. |
| `verify_model_input.py` | Read-only verifier for a completed shard manifest. Checks manifest/assets/shard integrity and, with `--decode`, reconstructs and validates each shard separately; supports relocated volume paths. |
| `build_matrix.py` | Alternative bounded/chunked CSR builder. Reuses a frozen split and vocabulary to publish binary and/or count matrices with sidecars and checkpoints. Intended for smaller/legacy matrix consumers, not the primary full-data shard route. |
| `build_host_pilot.py` | Builds a deterministic corrected train/test pilot from malicious telemetry plus ground truth and sampled benign rows. It uses a frozen vocabulary, has no validation partition, and is for pilot/regression work rather than the shared 75/10/15 corpus run. |
| `build_malicious_index.py` | Quick structured inventory of `host-malicious/`, optionally sampling header lines for label counts. It is diagnostic only and cannot replace the two-root full label index used by `build_host_index.py`. |
| `package_kaggle_input.py` | Legacy matrix-input packager. Safely copies matrices, vocabulary, tokenizer/reference code from `preprocess/` and `others/`, training scripts from `kaggle/scripts/`, and a Kaggle README into a newly published upload directory. It does not modify telemetry. |

## `code/kaggle/` — training delivery and runtime

| File | Effect / responsibility |
| --- | --- |
| `host_training_runtime.py` | Shared standalone runtime embedded in the shard notebooks. Opens and verifies manifests, samples TRAIN deterministically/resumably, decodes shard batches, trains RF/XGB/LGBM with alternating durable model slots, evaluates full validation/test sets, selects the validation-only threshold, deduplicates identical prediction rows, and publishes diagnostics/checkpoints safely. |
| `scripts/refresh_host_notebooks.py` | Generates/replaces the reviewed RF/XGB/LGBM notebooks with an embedded copy of `host_training_runtime.py`. Supports a Kaggle sampled profile and an EC2 100-million-row shared-sample profile; it rebuilds notebooks only, never dataset artifacts. Owns the shared atomic result-zip cell with source-ID/raw-line provenance for all three models. |
| `notebooks/host_rf_shards.ipynb` | Runnable RF notebook using the persisted shard manifest, a shared TRAIN sample, full validation/test, checkpoints, and diagnostics. |
| `notebooks/host_xgb_shards.ipynb` | Runnable XGBoost equivalent, including CPU/CUDA selection and the same split/sample/evaluation contract. Last cell packages results as a zip that includes bounded `val_errors.json`/`test_errors.json` examples under results, vocab, split manifest, and a `shard_source_index.json` mapping volume/shard→source gz paths for offline lookup by source ID and 1-based raw line; the Mission 4 audit helper is not a generic zip reader. |
| `notebooks/host_lgbm_shards.ipynb` | Runnable LightGBM equivalent with the same sampling, full evaluation, checkpoints, and diagnostics. |
| `notebooks/host_isoforest_shards.ipynb` | Exploratory Isolation Forest notebook on the shared shards; not one of the supervised RF/XGB/LGBM baseline models. |
| `notebooks/host_river_stream_shards.ipynb` | Exploratory incremental River tree-model notebook that streams the shared shards; outside the primary baseline trio. |
| `scripts/prepare_train_sample.py` | Small CLI wrapper that makes/resumes the common deterministic TRAIN sample via the shared runtime before fitting any model, so models can use exactly the same sampled rows. |
| `scripts/package_host_shards.py` | Packages an already-built shard manifest, assets, readers, and shards as an integrity-checked USTAR archive for upload. It refuses existing targets, validates paths/space, and writes a package report; it neither refits nor uploads. Includes `assets/split_manifest.json` when recorded by the builder; requires the frozen reader copies beside the manifest and preserves existing upload directories. |
| `scripts/train_rf.py` | Older matrix-based Random Forest trainer. Loads a prebuilt matrix bundle, fits/evaluates RF, chooses an F1 threshold from validation, and writes a pickle model, feature importances, probabilities, and training log. |
| `scripts/train_xgb.py` | Older matrix-based XGBoost trainer. Detects GPU availability, trains from a prebuilt matrix bundle, selects a validation F1 threshold, and writes a UBJ model, importances, probabilities, and log. |
| `scripts/train_lgbm.py` | Older matrix-based LightGBM trainer. Detects GPU availability, trains from a prebuilt matrix bundle, selects a validation F1 threshold, and writes a text model, importances, probabilities, and log. |
| `scripts/evaluate_models.py` | Matrix-era unified evaluator for RF/XGB/LGBM outputs. Produces val/test metrics, PR/ROC and confusion-matrix graphics, optional SHAP results, and a feature-importance comparison. |
| `requirements-cpu.txt` | Pinned CPU environment for reproducible EC2/Kaggle-compatible matrix/runtime experiments. |
| `requirements-gpu.txt` | Pinned GPU environment; uses GPU XGBoost instead of the CPU package. |
| `docs/KAGGLE_RUNBOOK.md` | Current seed02 Kaggle workflow, frozen cohort counts, notebook settings, checkpoint handling, and input/results locations; replaces the obsolete full-corpus EC2 plan. |
| `docs/XGB_DIAGNOSTICS.md` | Vietnamese guide to diagnostic artifacts, environment repair, reading F1/threshold results, and regenerating diagnostics for XGB/RF/LGBM. |

## `code/others/` — shared support/configuration

| File | Effect / responsibility |
| --- | --- |
| `evaluation_metrics.py` | Small shared metric functions. Validates binary labels, selects a threshold strictly from validation probabilities, and computes fixed-threshold binary metrics (including false-positive behavior). |
| `model_input_volumes.json` | Approved multi-volume quota and free-space-reserve plan for the main `host_ml_seed02` shard output. Pass this configuration to the shard builder when appropriate. |

## `code/audit/` — post-run investigation tools

These scripts inspect already-created model diagnostics, vocabularies, manifests, and raw telemetry. Reusable audits and approved-run inspection helpers remain; fixed-path helpers for deleted experiments were removed.

| File | Effect / responsibility |
| --- | --- |
| `audit_xgb_run.py` | Re-scores a frozen XGBoost result against matching local shards without training. Checks reproduced validation/test confusion counts, exports every FP/FN with exact source-line provenance, counts full-TRAIN/test feature-vector label collisions, and optionally traces representative raw events. Publishes to a new output directory. |
| `extract_error_rows.py` | Converts complete error JSONL exports into raw-event JSONL using manifest source IDs and 1-based lines. Validates source identities/labels, checkpoints source reads outside data roots, and atomically publishes all traces. |
| `review_host_vocabulary.py` | Reviews a frozen vocabulary/metadata pair without editing columns. Publishes `token_review.csv`, canonical-alias/dynamic-literal counts and rare-lexical review flags; optionally compares a newly fitted vocabulary on the same split and exports added/removed token strings. The canonical projection is not a replacement fitted vocabulary. |
| `extract_failed_events.py` | CLI utility that retrieves raw Host JSON for diagnostics’ failed events and writes an audit JSON plus human-readable Markdown report. |
| `explain_sample_tokenization.py` | Renders a Vietnamese Markdown walkthrough of tokenizer output for a sample record, optionally checking the matching frozen vocabulary; it does not fit a vocabulary. |
| `graph_vs_ml_complementarity.py` | Post-run complementarity audit between the learned GraphSAGE ego-graph model and all three Host ML models (RF/XGB/LGBM). Joins the 2,000-event graph test sample with ML `test_errors.json` via `(source_id, source_line)`, classifies joint outcomes (graph corrects FP/FN, graph breaks TN/TP, both wrong, both correct), annotates casebook case patterns (vector_collision / generalization / near_threshold / context_loss), reports cross-model events where all three ML models are wrong but graph is right, and writes JSON + Markdown reports. Metadata-only mode if no model weights; supply `--model-weights` for NumPy inference. Output: `code/output/provenace_graph/graph_vs_ml_complementarity.{json,md}`. |
| `gating_fusion_evaluation.py` | Two-stage context-aware gating fusion audit: Tree ML (fast linear triage filter) + Relational GraphSAGE (two-hop causal arbiter). Evaluates Gating Policies (FP Veto, FN Boost, Dual Gating, Soft Blend) on the 2,000-event uniform sample, queries and scores ALL 7,390 unique ML errors across the entire 1,249,689-event test set directly from `graph.sqlite` target table, and projects full-corpus F1, Precision, and Recall improvements. Output: `code/output/provenace_graph/gating_fusion_report.{json,md}`. |
| `tune_gating_cascade.py` | Historical projection using assumed graph false-positive/true-positive rates; its 98.49% test F1 is **not a measured full-test result**. Do not use for model selection or claims. |

## `code/test/` — regression and reproducibility checks

| File | What it protects |
| --- | --- |
| `test_stratified_pipeline.py` | Synthetic end-to-end index → split → two-class TRAIN vocabulary → matrix/package flow, including deterministic shared assignments and leakage prevention. |
| `test_build_vocab.py` | Vocabulary sampling, filtering, deterministic parallel output, checkpoints/resume, atomic publication, output-boundary checks, and TRAIN-only fitting. |
| `test_build_split_contextual.py` | Synthetic contextual windows, exact class quotas, deterministic masks, interruption/resume, old-index revalidation, and downstream TRAIN vocab → lossless shards. |
| `test_audit_xgb_run.py` | Frozen-threshold error semantics, collision bounds and exhaustive F1-oracle check, source-line extraction, resume, and output/source-identity guards. |
| `test_notebook_exports.py` | Shared generator/notebook export consistency, valid Python cells, unique manifest names, source-ID/volume provenance and raw-line interpretation in generated result zips. |
| `test_ecar_tokenizer.py` | Tokenizer behavior: command syntax, semantic typing, relationship tokens, embedded-code handling, bounds, determinism, and non-mutation/non-execution guarantees. |
| `test_pipeline_contract.py` | Read-only-root/symlink output protections and frozen vocabulary/split/checksum compatibility checks. |
| `test_review_host_vocabulary.py` | Protects canonical vocabulary mappings, dynamic-counter normalization, and retention of distinct field/command roles and unfamiliar anchors. |
| `test_host_shards.py` | Shard encoding/decoding round trips, quota spillover, resume behavior, and full lossless shard-pipeline validation. |
| `test_host_training_runtime.py` | Shared runtime sampling plans, safe output paths, CPU prediction, checkpoints, resume behavior, and error handling. |
| `test_xgb_diagnostics.py` | Runtime diagnostic state, version/preflight safeguards, resume identity, error provenance, and post-hoc learning-curve behavior. |
| `test_package_host_shards.py` | Archive contents, hashes, safety/space guards, and all-row preservation for host-shard packaging. |
| `test_build_matrix.py` | Legacy/compatible chunked matrix output, binary/count representation, safe publication, checkpoints, and matrix-input packaging. |
| `test_build_host_pilot.py` | Corrected pilot selection, label reconciliation, deterministic sampling, and checkpoint regression coverage. |
| `test_evaluation_metrics.py` | Validation-only threshold selection, false-positive budgeting, and binary-target validation. |
| `test_rng.py` | Tiny ad hoc NumPy RNG-state/digest probe for reproducibility investigations; not a `unittest` suite. |

| `lsass_tokens.py` | Small read-only helper inspecting LSASS false positives in the approved seed02 XGBoost diagnostics. |
| `provenance_tracer.py` | Exploratory raw-log PID trace helper; not used for approved features or training. |

## Practical commands

Run tests from the repository root. For tests that import shared modules, set `PYTHONPATH=code/preprocess:code/others:code/kaggle:code/kaggle/scripts:code/test`. The focused suite below does not touch source telemetry:

```bash
python3 code/test/test_stratified_pipeline.py
python3 code/test/test_build_vocab.py
python3 code/test/test_ecar_tokenizer.py
python3 code/test/test_host_shards.py
python3 code/test/test_host_training_runtime.py
```

For the production ordering and output locations, use the commands in `AGENTS.md`. In particular, preserve completed index/split/vocabulary artifacts when rebuilding downstream shards or packages.

## `code/provenace_graph/` — learned two-hop provenance graph

The corrected experiment is a learned relational mean GraphSAGE encoder with an
optional neural risk head, not another tree model. The approved Host ML baseline
is untouched. Read `code/provenace_graph/README.md` and `docs/DESIGN.md`.

| Path | Role |
| --- | --- |
| `preprocess/build_graph.py`, `graph.py`, `common.py` | Raw-index scanner, graph schema, causal lookup and safety helpers. The completed graph database remains frozen; `graph.py` now defaults new Encoder calls to exact-time inference, so do not resume an old scanner checkpoint with this changed source hash. |
| `preprocess/audit_graph.py`, `explain_event.py` | Earlier bounded index diagnostics; not a learned-model evaluator. |
| `model/ego.py` | Actual typed causal ego graphs, capped at 64 nodes and two hops; new exact-microsecond cutoff restores strictly earlier same-second CREATE edges. |
| `model/relational_sage.py` | Two learned message-passing layers, 16-dimensional embeddings and optional neural risk head; 9,041 parameters. |
| `model/train.py` | TRAIN-only graph-model fitting, validation threshold, explicit sampled/full evaluation and resumable epoch checkpoints. Its sampled mode selects globally from compact shard labels, looks up graph identities only for selected rows, and materializes each two-hop graph once; it resolves relocated baseline shard volumes from Kaggle mounts. |
| `model/score_event.py` | Learned risk, embeddings, source-line evidence and ancestry-edge ablations. |
| `model/ego_cache.py` | Portable no-pickle NPZ cache schema, integrity checks and graph-part reader; node identities/raw telemetry are excluded. |
| `model/train_gpu.py` | PyTorch CUDA two-layer relational mean GraphSAGE over precomputed cache shards; it never opens SQLite or raw telemetry. At the end of training, automatically calls `export_numpy_weights()` to write `model_numpy.npz` alongside `checkpoint.pt` — a relational_sage-compatible NumPy weight file for local inference without PyTorch. Also supports `--export-only` to convert an existing `checkpoint.pt` to `model_numpy.npz` without retraining. |
| `model/resume_index.py` | Verifies the existing 200,000-line checkpoint against active source and the archived retired-adapter fingerprint before resuming the unchanged scanner. |
| `preprocess/build_ego_cache.py` | Local SSD, label-blind, strict-past two-hop ego-graph cache builder with deterministic seed02 sample selection, part-level checksum resume and atomic publication. New builds default to exact-microsecond cutoffs; completed one-second caches remain unchanged. |
| `preprocess/package_ego_cache.py` | Packages a complete cache, GPU trainer and GPU notebook into a verified Kaggle USTAR archive without copying graph.sqlite or raw telemetry. |
| `preprocess/package_cascade_input.py` | Packages frozen approved LightGBM and GraphSAGE checkpoints, SQLite, baseline metrics and integrity-checked inference runtime as `kaggle_upload_cascade_v2/provenance-cascade-bundle-v2.tar.gz`; excludes obsolete projected thresholds and training cache. |
| `model/cascade_runtime.py` | Shared RF/XGB/LGBM frozen-model cascade inference. Verifies v3 bundle/model identity, selects a policy from full validation, checks each approved full-test baseline, reports branch confusion, saves per-shard scores and every final FP/FN with source-line IDs, and packages metrics/error rows. |
| `model/collision_aware_runtime.py` | LightGBM v4 controlled routing experiment. Builds exact full-TRAIN and fit-subset vector-label registries, overrides legacy gates only for conflicting vectors, verifies frozen bundle/manifest identities and baseline, and exports validation/TEST metrics plus all final errors and prediction transitions in a separate output directory. |
| `model/conditional_collision_runtime.py` | Separate LightGBM v4 conditional collision experiment. Selects low-band graph threshold under a 10-FP validation budget and high-band veto under a 10-FN validation budget, requires at least 0.0001 validation F1 gain, freezes policy before TEST, audits each TRAIN-conflicting vector and verified identical opposite-label graph encodings, and exports full TEST errors/transitions. |
| `audit/collision_validation_diagnostic.py` | Validation-only diagnostic of TRAIN-derived exact Host-vector collisions. Verifies frozen v4 validation shards and graph-score caches, measures GraphSAGE discrimination by LightGBM band and within opposite-label same-vector pairs, and records representative ego-graph contexts under the separate collision-aware results directory. |
| `test/test_cascade_runtime.py` | Protects validation policy choice, tie-to-baseline rule, missing graph fallback, and sparse RF/XGB checkpoint scoring. |
| `test/test_collision_aware_runtime.py` | Checks exact binary Host-vector equality, collision override in all LightGBM score bands, unchanged non-collision routing, and explicit failure on missing required graph scores. |
| `test/test_conditional_collision_runtime.py` | Protects conditional threshold budgets, unchanged middle/noncollision behavior, and missing-score failure. |
| `notebook/provenance_graph.ipynb` | Earlier SQLite-query Kaggle workflow for debugging only; not suitable for an experiment-sized cache. |
| `notebook/provenance_graph_gpu.ipynb` | Kaggle GPU workflow; securely extracts the static cache and trains the batched PyTorch relational GraphSAGE. |
| `notebook/host_two_stage_cascade.ipynb`, `code/kaggle/notebooks/host_two_stage_cascade.ipynb` | LightGBM + GraphSAGE notebooks. The Kaggle copy alone runs the joint-decision experiment: validation-selected low/middle/high graph thresholds, GraphSAGE scoring for ML ≥0.10 including high ML, old-vs-new full-test transition audit, all FP/FN export, and comparison plots. The provenance-graph copy retains the prior v3 cascade workflow. |
| `code/kaggle/notebooks/lgbm_two_stage_cascade.ipynb` | Self-contained LightGBM v4 exact-time collision-aware experiment. Keeps frozen checkpoints and thresholds, builds a full-TRAIN exact-vector registry, evaluates validation then TEST against the reproduced legacy policy, and ZIPs summary, metrics, final FP/FN and event transitions. The separate local measured experiment is in `code/output/provenace_graph/collision_aware_v4_results/` (TEST F1 0.979324); the original v4 baseline remains in `code/output/provenace_graph/kaggle_output/lgbm-two-stage-cascade-results/` (TEST F1 0.985026). |
| `code/kaggle/notebooks/lgbm_conditional_collision_cascade.ipynb` | Self-contained Kaggle implementation of validation-selected conditional collision routing using existing v4 Host and cascade inputs. Optionally reads a hash-verified third input, `kaggle_upload_conditional_cache/v4-graph-score-cache.tar.gz`, to reuse frozen per-shard GraphSAGE scores and avoid long SQLite inference. Builds the TRAIN registry, freezes a validation-approved low/high policy, scores full TEST once, exports per-vector audit, verified representation limitations, all TEST FP/FN and prediction changes, and packages a downloadable result ZIP. |
| `notebook/host_rf_two_stage_cascade.ipynb`, `code/kaggle/notebooks/host_rf_two_stage_cascade.ipynb` | RF equivalent using the approved frozen RF checkpoint and its own validation threshold; exports the same plots and source mapping. |
| `notebook/host_xgb_two_stage_cascade.ipynb`, `code/kaggle/notebooks/host_xgb_two_stage_cascade.ipynb` | XGBoost equivalent using the approved frozen XGB checkpoint and its own validation threshold; exports the same plots and source mapping. |
| `preprocess/package_cascade_trio.py` | Publishes the integrity-checked v3 Kaggle bundle with all three approved Host checkpoints/metrics, graph index/weights and shared runtime; leaves v2 intact. |
| `preprocess/package_cascade_v4.py` | Publishes a distinct integrity-checked exact-time v4 Kaggle bundle, preserving v3 and recovering the hash-verified frozen GraphSAGE checkpoint from it. The checkpoint is not retrained. |
| `test/test_graph.py`, `test/test_learned_graph.py` | Index safety/causality and neural gradients/message-passing/learning/resume tests. |
| `test/test_relocated_shards.py` | Relocated shard-volume discovery from conventional and nested Kaggle package layouts. |
| `test/test_ego_cache.py` | Static cache encoding/decoding, source-line provenance, relation IDs and manifest self-digest test. |
| `code/output/provenace_graph/` | Complete index, local ego-graph caches, Kaggle cache packages, pilot/research extracts and synthetic validation reports. `kaggle_upload_seed02_ego_cache_v2/` is the current upload-ready archive (includes updated `train_gpu.py` with numpy weight export and updated notebook with result packaging cell). The older `kaggle_upload_seed02_ego_cache/` is superseded. |

The unwanted tree-column augmentation script and RF/XGB/LGBM notebooks were removed
from this branch. The retired adapter's exact bytes are stored only beside the old
checkpoint to validate its original implementation fingerprint, not as active code.
