# LightGBM v4 conditional collision routing: completed Kaggle run

This report audits `code/output/provenace_graph/kaggle_output/lgbm_v4_conditional_collision_results/`. It compares the validation-frozen conditional policy with the unchanged exact-time v4 legacy cascade. The Kaggle run used native LightGBM 4.6.0 and the existing GraphSAGE/SQLite bundle. No model, Host preprocessing, graph schema or split was changed.

## Reproducibility and integrity

- The manifest SHA-256 is `421d1855c2ae46f01b531f242aaa265a3a23b992d2969b24d534b1b088367fc5`, matching the v4 input. The graph database, GraphSAGE model, LightGBM model and feature-schema hashes in `config.json` match the local frozen bundle.
- The full-TRAIN exact-vector registry contains 1,457 conflicting vectors. `frozen_policy.json`, validation metrics and TEST metrics contain the same selected policy. The TEST legacy confusion reproduces TP 39,732 / FP 630 / FN 578 / TN 1,208,749.
- All 1,169 final TEST errors appear once in `test_errors_full_scores.jsonl`: 587 FP and 582 FN. All 51 changed predictions appear once in `event_transition_audit.jsonl`. Their 43 FP corrections, 2 FN rescues and 6 new FN exactly reconcile the aggregate confusion change.
- The Kaggle and previous local runs have identical validation/TEST confusion, identical 51 transition event keys and identical 1,169 final-error event keys. Some native-vs-local scores differ only at floating-point roundoff (at most about `1.1e-16`).
- The final sentence of the exported `summary.md` describes the earlier local score-map run. It is generic notebook text, not the Kaggle scoring method: `validation_metrics.json` records native LightGBM scorer `4.6.0` for this run.

## Outcome

| Split | Policy | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | Legacy | 26,490 | 412 | 383 | 805,840 | 0.984685 | 0.985748 | 0.985216 | 0.000511 |
| Validation | Conditional | 26,486 | 390 | 387 | 805,862 | 0.985489 | 0.985599 | 0.985544 | 0.000484 |
| TEST | Legacy | 39,732 | 630 | 578 | 1,208,749 | 0.984391 | 0.985661 | 0.985026 | 0.000521 |
| TEST | Conditional | 39,728 | 587 | 582 | 1,208,792 | 0.985440 | 0.985562 | 0.985501 | 0.000485 |

Validation F1 rises by **0.000328**; TEST F1 rises by **0.000475** (0.0475 percentage points). On TEST, FP falls by 43 (6.83% of legacy FP), while FN rises by 4 net. Precision improves by 0.1048 percentage points; recall falls by 0.0099 points. This matches the validation direction and meets the predeclared validation acceptance rule. The earlier unconditional collision policy had TEST TP 39,597 / FP 959 / FN 713 / TN 1,208,420 and F1 0.979324 at the same 380,652 GraphSAGE calls. Band-specific thresholds avoid that policy's large regression.

The frozen rules were: collision ML <0.30 uses GraphSAGE ≥`0.999993392`; collision ML ≥0.96 uses GraphSAGE ≥`0.010082806`; 0.30≤ML<0.96 stays at GraphSAGE ≥0.95; non-collision events keep legacy decisions. The low threshold rescued 1 validation FN with 0 new FP; the high veto corrected 22 validation FP at a cost of 5 new FN. These values were selected using validation only, within budgets of 10 additional low-band FP and 10 high-band FN and a minimum validation F1 gain of 0.0001.

| TEST policy effect | Corrected | Newly introduced | Net |
| --- | ---: | ---: | ---: |
| Low-band collision rescue | 2 FN | 0 FP | 2 fewer FN |
| High-band collision veto | 43 FP | 6 FN | 43 fewer FP, 6 more FN |

The gain is computationally expensive: TEST GraphSAGE workload is **136,833 → 380,652 events** (+243,819; 2.78×), including nearly all collision events. The low-band threshold is calibrated by only one validation rescue and produced two near-duplicate TEST rescues; its stability across new hosts or campaigns is unproven. Treat the policy as a research candidate rather than a production recommendation on this single contextual split.

## Where the changes occur

The 43 corrected FP are concentrated: 33 are from `sysclient0501` on 2019-09-24, 6 from `sysclient0010` on 2019-09-24, and 4 from that host on 2019-09-25. Ten corrected FP share a `powershell.exe` `COMMAND/SHELL` Host pattern; many others are `conhost.exe` MODULE loads, thread operations or file reads. Their ML scores were 0.9624–0.9894, while GraphSAGE scores were 0.00117–0.00560, far below the conservative veto threshold.

All 6 newly introduced FN are malicious `conhost.exe` events: four from `sysclient0851` on 2019-09-24 and two from the same host on 2019-09-25. Their ML scores were 0.9750–0.9775, but each had GraphSAGE score `0.0013422344`. For example, TEST event `(2fc84b4d…, 2810261)` is a raw `LOAD MODULE` of `ucrtbase.dll` by `conhost.exe`, label 1. TEST event `(e9484f90…, 1404753)` is a raw `TERMINATE THREAD` by `conhost.exe`, label 1. Both were previously detected by the high-ML direct branch and are now vetoed.

Reconstructing the frozen ego graphs for all 51 changed events yields only 7 distinct encoded graph inputs. All 6 new FN share one *identical* input: a Process node and a Host node connected by `hosts`, no CREATE edge, with `unresolved_relation` and `truncated` flags. The graph database has no indexed parent row for the checked actors. Thus GraphSAGE sees little actor-lineage context and assigns the same low score to different malicious event types. The raw records contain `ppid`, but this audit does not establish why an indexed CREATE relation is absent; it does **not** prove that the split removed the parent. A benign corrected `conhost.exe` MODULE load `(613e6b30…, 2329748)` has a different 4-node/2-CREATE graph and score `0.004667849`; its raw event is `LOAD KernelBase.dll`, label 0.

The two rescued FN are `(e0a257e8…, 1814826)` and `(e0a257e8…, 1814831)`, both `CREATE THREAD` events on `sysclient0351` on 2019-09-25. They share one graph encoding and score `0.999993392`, despite ML score `0.138407`. They represent one repeated context rather than two independent kinds of rescue.

Among all 1,457 TRAIN-conflicting vectors, 216 have both labels represented in validation; 463 have no validation rows. The per-vector audit verified opposite-label events with identical GraphSAGE input in **93** of those 216 vectors (95 sampled pairs). These are representation limitations: a deterministic GraphSAGE model cannot separate those particular pairs using identical encoded inputs. The pair check examined one pair per vector/identical-score group; it is not an exhaustive census. Of the 26 exact Host vectors involved in changed TEST predictions, 10 had no validation rows, so the chosen rule was evaluated globally rather than validated separately for every vector.

## Residual errors and interpretation

| Final TEST route | FP | FN |
| --- | ---: | ---: |
| Unchanged middle band | 251 | 309 |
| Collision high band | 212 | 6 |
| Collision low band | 0 | 153 |
| Other legacy direct decisions | 124 | 114 |
| **Total** | **587** | **582** |

The middle band accounts for 560/1,169 residual errors and was deliberately untouched. Of the high-band collision FP, 43 were vetoed while 212 remain: most benign high-ML events do not have an extremely low graph score. The low-band policy retains 153 collision FN. Thus conditional routing provides a narrow precision gain, not a general solution to Host-vector ambiguity. Missing actor lineage, compressed Process/Host-only graphs, overlapping graph inputs, and unchanged middle-band decisions remain important limitations. The corrected seed02 split and this result do not establish generalization to disjoint processes, hosts, time periods or campaigns.

Primary machine-readable evidence: `validation_metrics.json`, `test_metrics.json`, `validation_per_vector_audit.jsonl`, `representation_limitations.json`, `event_transition_audit.jsonl`, and `test_errors_full_scores.jsonl` in the Kaggle result directory. Raw-event examples were read by `(source_id, source_line)` from the read-only files mapped in `source_index.json`; no raw telemetry was modified.
