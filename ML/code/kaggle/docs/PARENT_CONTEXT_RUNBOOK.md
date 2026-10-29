# Parent-context seed02 experiment

This is a new Host LightGBM experiment. The approved baseline and historical
GraphSAGE cascade remain unchanged. Their metrics/thresholds are not expectations
for the new feature representation.

From `/mnt/SSD_Data/optc`, build the complete frozen split once:

```bash
python3 -u ML/code/preprocess/run_parent_context_seed02.py --workers 6
```

The runner fits TRAIN vocabulary, builds parent-context shards, verifies decoding,
checks every target against frozen masks/index labels, and creates the Kaggle tar.
Each host's files are replayed chronologically; workers parallelize different hosts.
There is no extra multi-hour continuous/resume pilot. File-level checkpoints resume
interrupted scans; a changed implementation requires a fresh output namespace.
The index-label audit certifies fidelity to the frozen index, not a new raw-label audit.

Default output: `ML/code/output/host_ml_parent_context_seed02/`.
- `completion.json` exists only after successful verification and packaging.
- `logs/`: per-phase logs and exit receipts.
- `model_input/manifest.json`: parent-context features over the original seed02 targets.
- `kaggle_upload/host-input.tar`: upload this new dataset, not the baseline archive.

Import `ML/code/kaggle/notebooks/lgbm.ipynb` into Kaggle. It accepts an extracted
input or one attached `host-input.tar`; checks parent-context policy and frozen split
identity; and uses separate output/sample directories for each vocabulary identity.
TRAIN sampling seed is 1, split seed is 02. Validation chooses the threshold and
TEST uses that frozen value. Training is not run locally. The notebook exports
metrics, diagnostics, provenance, source-line errors and a Blues confusion matrix.

The old notebook is preserved exactly as `lgbm_graphsage_post_sweep_archived.ipynb`.
Regenerate the new notebook with `refresh_parent_context_notebook.py`, not the
baseline notebook generator's main entry point.

TTL optimization retains canonical schema v3 state. Its expiry schedule is a
conservative lower bound: expired state is removed at the same observe calls and
in the same order as the former full scan. The schedule is rebuilt after reload.
Existing checkpoint code-hash checks remain strict; old pilot checkpoints are
not reused by the new production run.

## Typed incoming context (checkpoint schema 4)

The parent-context build now also captures incoming PROCESS OPEN (target objectID)
and THREAD REMOTE_CREATE (target properties.tgt_pid_uuid). Both endpoints must be
valid UUIDs on the same host; no PID fallback, extra ancestor hop, labels or FLOW
features are added. Source image/principal are snapshotted from the interaction;
PROCESS OPEN command_line is deliberately not treated as source command line.
Features are edge-kind scoped, strictly earlier than the query timestamp, with
age buckets and prior same-source OPEN-to-remote-thread time gap. Equal-time
OPEN does not count as a prior OPEN. Background records update state too.

Each process retains at most 8 records per kind (16 total), independently capped,
with 24-hour incoming evidence TTL; process state still has its own TTL/capacity.
Frequent OPENs cannot evict remote-thread history. State eviction or missing logs
can still remove evidence: these features are observations, not compromise labels.
No exact count or complete interaction-history claim is made.

Old schema 3 checkpoints and previously fitted vocabularies are incompatible.
Keep old outputs intact; rebuild vocabulary and shards from the existing frozen
seed02 masks, without changing labels or split membership:

```bash
cd /mnt/SSD_Data/optc
python3 -u ML/code/preprocess/run_parent_context_seed02.py \
  --workers 6 \
  --output-dir /mnt/SSD_Data/optc/ML/code/output/host_ml_parent_incoming_seed02
```

Rerun the identical command after interruption, with unchanged code/config. The
runner fits vocabulary, builds shards, decodes/verifies, checks frozen index labels
and membership, and packages `kaggle_upload/host-input.tar`. It does not train.
Use the updated `ML/code/kaggle/notebooks/lgbm.ipynb`, which requires incoming-enabled
metadata and isolates training output by vocabulary identity. Start a fresh Kaggle
session when replacing the dataset archive to avoid previously extracted input.
Actual improvement in recall/F1 must be measured after training; none is asserted.
