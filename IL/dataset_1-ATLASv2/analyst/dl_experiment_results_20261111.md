# Completed DL experiments — 11 November 2026

Read [the root-cause report](dl_root_cause_20261111.md) for the raw-data evidence,
source references, label defects and code changes. All new training used CPU;
CUDA was unavailable. No experiment uses test labels to select its threshold or
checkpoint. Because these test scenarios were already repeatedly inspected,
results are exploratory, not a fresh independent generalization estimate.

## Original labels: directly comparable binary results

There are 2,369 test windows: 38 positive and 2,331 negative.
Attack macro F1 below averages classes 1–4 **over all rows**, including benign
false alarms. It differs from the historical attack-conditioned metric.

| Experiment | TP | FP | FN | Binary F1 | Attack macro F1 | Test AP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Historical v5 calibrated | 30 | 516 | 8 | 10.27% | 16.34% | 0.5040 |
| Historical v5 global, threshold 0.50 | 17 | 37 | 21 | 36.96% | 21.79% | 0.5040 |
| Same v5 weights, corrected validation calibration | 16 | 5 | 22 | **54.24%** | **23.53%** | 0.5041 |
| Retrained v6, corrected metrics/calibration, old losses + synthetic fixture replay | 17 | 21 | 21 | 44.74% | 18.75% | 0.2928 |
| Retrained v8, natural BCE, no positive-only binary loss, no replay | 12 | 4 | 26 | 44.44% | 20.00% | 0.5005 |

All retrains ran 12 epochs, seed 42, with the original source checkpoint loaded.
V6 selected checkpoint scores at threshold 0.50 and calibrated after selection.
V8 selected using validation-calibrated metrics every epoch. V6 was a controlled
reproduction of the old training objective; its synthetic source-test result
must not be interpreted as source retention. Later trainer defaults do not
reproduce v6's legacy loss settings without adjustment.

The recalibrated existing v5 checkpoint outperformed these short retrains on
test binary F1. This is evidence for repairing decision policy first. It is not
evidence that no further training could help. Twelve epochs do not reproduce
v5's original 30-epoch schedule. The v8 treatment also changes multiple training
choices together, so it does not isolate the causal effect of replay or BCE.

The v5 recalibrated threshold **0.8936129212** was chosen on validation. Its
validation F1 was 68.75% with two false positives. It should be stored with the
exact checkpoint and label/data identity; it is not a universal threshold.

An order-free MLP control was trained from scratch on exactly the encoded
categorical features, their normalized histograms/presence, host-role summary,
time-delta summaries and sequence length. Scaling was fitted on TRAIN only.
Across seeds 41/42/43, its test binary F1 was **44.44%, 53.85%, 45.16%**.
This model is a supervised target-domain diagnostic, not a continual model.
Comparable results without recurrence weaken the claim that more LSTM depth is
the immediate solution. They do not establish that temporal order never matters.

## Conservative-v2 sensitivity labels: a different benchmark

This dataset excludes S3, ignores unverified seed-only endpoint evidence and
embargoes day-boundary windows. Training has 81 positive / 2,430 negative windows;
validation 35 / 1,925; test **24 / 2,342**. Its test windows have 18 final
Exfiltration labels and six final Execution/Discovery labels. There are no final
Initial-Compromise or Lateral-Movement labels, although those actions may occur
inside mixed windows. Treating unverified seed-only events as negative is an
experimental assumption that still needs human adjudication.

| Model | Seed | TP | FP | FN | Binary F1 | Attack macro F1 (fixed four classes) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BiLSTM v7, 12 epochs | 42 | 24 | 23 | 0 | **67.61%** | 20.93% |
| Order-free MLP | 41 | 24 | 11 | 0 | 81.36% | 39.32% |
| Order-free MLP | 42 | 18 | 18 | 6 | 60.00% | 16.33% |
| Order-free MLP | 43 | 17 | 2 | 7 | 79.07% | 21.62% |

Check the JSON results for exact stage metrics; stage macro averages must use a
fixed class set even when a stage has zero test support. V7's training summary
was generated before that final reporting fix, so its reported five-stage macro
F1 of 45.81% is superseded by **36.65%** in its post-run audit. Binary metrics and
attack macro F1 are unchanged. All validation stages exist, so this correction
does not change the selected epoch.

V7 gets binary detection right but classifies none of the six Execution/Discovery
windows as that stage: one becomes Initial Compromise and five Exfiltration.
All 18 Exfiltration windows are correctly classified. Thus **100% binary recall
is not successful stage estimation**. The early-stage problem is unresolved.
The MLP's seed variability also argues against presenting one favorable run as
a reliable solution.

## What to use and what to do next

Use the corrected metric and validation-only decision policy immediately. The
v5 decision artifact in `output/research_20261111/v5_recalibrated/` references
the exact checkpoint and stores its validation threshold. Keep the original
benchmark results and conservative sensitivity results in separate tables.

The next experiment should change the **supervision and observable evidence**:

1. Adjudicate S3's time contradiction and seed-only positives against source
   lines and attack procedures. Mark unresolved events unknown, rather than
   turning model errors into convenient labels.
2. Define event-stage or multi-label window targets from actual actions and
   time intervals. Retain all relevant stages instead of the final process's
   stage. Require held-out support for every stage before claiming stage recall.
3. Add explicit event/relation type, safe command structure, source/target roles,
   direction and process-centered past context. Evaluate a network-only branch
   separately from host/network fusion. Avoid scenario/name/IOC shortcuts.
4. Restore genuine source TRAIN replay and held-out OpTC shards. Only then
   report continual-learning BWT. Synthetic fixture performance is a smoke test.
5. Compare against the order-free control across seeds, with incident-level
   recall and alert burden. Choose the protocol before inspecting new test
   outcomes, and evaluate on fresh campaigns/data before claiming generalization.

## Artifact locations

Relative to `IL/dataset_1-ATLASv2/code/DL/output/research_20261111/`:

- `audit/audit_summary.json`: corrected historical metrics, features, v5 calibration.
- `audit/v5_{val,test}_errors.csv`: original-v5 predictions with error types.
- `raw_audit/`: all source hashes, positive events, window-to-source traces.
- `corrected_v6/`, `conservative_v7/`, `natural_loss_v8/`: completed BiLSTM
  checkpoints, training histories, confusion matrices and retained logs.
- `conservative_v7/audit/`, `natural_loss_v8/audit/`: post-run probabilities,
  FP/FN/stage error CSVs and metrics over a fixed class set. These audit files
  retain the helper's historical `v5_` filename prefix; checkpoint hashes identify
  the actual model.
- `legacy_feature_probe/`, `v2_feature_probe/`: three-seed MLP controls,
  training-only transforms and predictions.
- `data_v2/`: sensitivity shards; `data_v2_identity.json`: immutable content hashes.

Eight focused regression/integration tests pass, including full-range threshold
selection, no-alert fallback, tied-score handling, benign FP inclusion, midnight
embargo, TRAIN-only vocabulary, atomic build publication and overwrite refusal.
