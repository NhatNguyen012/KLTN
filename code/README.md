# Host ML seed02

The main run is `code/output/host_ml_seed02/`. This is the teacher-approved
experiment previously called v4, consolidated under a permanent name. Preprocessing
features, split assignments, vocabulary columns, trained results, and training
runtime are unchanged. Source and notebook edits for this rename only change paths.

## Layout

| Location under `output/host_ml_seed02/` | Contents |
| --- | --- |
| `index/` | Inherited source-label index, retained as provenance |
| `split/` | Frozen contextual 75/10/15 event split and masks, seed 02 |
| `vocab.json`, `vocab_metadata.json` | TRAIN-only vocabulary, 9,048 columns |
| `model_input/` | Active manifest, assets, readers, notebooks, and checkpoints |
| `model_input/volumes/ssd/` | All 358 approved sparse shards |
| `kaggle_upload/host-input.tar` | Preserved portable Kaggle input archive |
| `kaggle_ouput/` | Approved RF/XGBoost/LightGBM results; original spelling retained |
| `maintenance/` | Restoration and relocation inventories and validation logs |

The old `host_ml`, `host_ml_v3_seed02`, and `host_ml_v4_seed02` directories
are gone. Their required contents are now inside this run; no compatibility
symlinks are needed. Raw telemetry and external storage were not modified.

## Experiment identity

| Partition | Benign | Malicious |
| --- | ---: | ---: |
| TRAIN | 6,046,892 | 201,551 |
| Validation | 806,252 | 26,873 |
| Test | 1,209,379 | 40,310 |

Split seed is **02**; notebook TRAIN-sampling seed is separately **1**.
Tokenizer policy `v5_canonical_office_registry` is the approved policy name,
not an obsolete experiment. The contextual random-event baseline does not
establish temporal, process, or campaign generalization.

Historical source hashes and paths in vocabulary metadata, result provenance,
and archived packages describe the original run and are intentionally preserved.
For example, the recorded `split_file` points to its former location; the active
split is now `split/manifest.json` with the **same SHA256 and assignments**.
The active shard manifest's SSD location has changed, so its file hash changed;
its run ID, split/vocabulary identities, shard hashes, and class totals did not.
Do not manually rewrite provenance hashes or regenerate the approved artifacts.
Older audit/preprocessing checkpoints may be rejected after relocation; preserve
the completed outputs and use a new output directory for a new investigation.

## Use

From the workspace root, verify the main input without training:

```bash
python3 code/preprocess/verify_model_input.py \
  --manifest code/output/host_ml_seed02/model_input/manifest.json --decode
```

Train on Kaggle using `code/kaggle/notebooks/host_{rf,xgb,lgbm}_shards.ipynb`
and the existing upload archive. See [Kaggle runbook](kaggle/docs/KAGGLE_RUNBOOK.md)
and [diagnostics guide](kaggle/docs/XGB_DIAGNOSTICS.md).

The general split builders retain their original seed-1 defaults; they are not
commands to reproduce or replace this frozen contextual split. If explicitly
building a separate experiment, pass its seed, split, and new output paths.
For a read-only check of the approved builder inputs:

```bash
python3 code/preprocess/build_model_input.py \
  --split code/output/host_ml_seed02/split/manifest.json \
  --vocab code/output/host_ml_seed02/vocab.json \
  --vocab-metadata code/output/host_ml_seed02/vocab_metadata.json \
  --output-dir code/output/host_ml_seed02/model_input --dry-run
```
