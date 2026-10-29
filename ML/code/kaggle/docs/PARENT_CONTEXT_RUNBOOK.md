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
