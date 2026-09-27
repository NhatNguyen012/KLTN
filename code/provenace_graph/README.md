# Lightweight learned provenance graph

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
  past one-second snapshots. Process ancestry and host neighborhoods extend two hops.
- Runtime: NumPy only for neural operations; no PyTorch/PyG installation required.

[Design, research evidence and limitations](docs/DESIGN.md).

## Current running-job status

The last inspected full-index checkpoint contains **200,000 lines from source 1
of 106**. No builder process was running at inspection. `Ctrl+Z` on `tail -f`
suspends the viewer, not normally the background builder; the log does not establish
why the builder exited. The completed bounded pilot is not the full graph.

The original scanner files are unchanged. Its checkpoint recorded the fingerprint
of the unused, now-retired adapter too. An exact copy of that adapter is retained
only in `.graph.work/source_snapshot/` for provenance validation. The compatibility
entry point verifies every recorded implementation hash before resuming the scanner:

```bash
# From the repository root; first check without starting a scan:
python3 code/provenace_graph/model/resume_index.py --dry-run

# Resume the existing full-index checkpoint if desired:
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
Its default TRAIN cap is 20,000 balanced rows, validation/test caps 5,000 uniform
rows. These are graph-model smoke/initial-experiment budgets, not the full baseline
sample. Set `--val-limit 0 --test-limit 0` for full-partition evaluation after the
pipeline is ready. The saved metrics explicitly distinguish sampled from full scope.

```bash
python3 code/provenace_graph/model/train.py \
  --graph code/output/provenace_graph/graph \
  --baseline code/output/host_ml_seed02/model_input/manifest.json \
  --output code/output/provenace_graph/learned_model \
  --epochs 10 --evaluate-test
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
