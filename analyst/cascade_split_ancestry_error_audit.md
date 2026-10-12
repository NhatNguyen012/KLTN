# Seed02 two-stage cascade: split, ancestry, and residual errors

This audit concerns the **older measured LightGBM cascade** at `code/output/provenace_graph/kaggle_output/optc-two-stage-cascade-results/` and the **XGB cascade** at `code/output/provenace_graph/kaggle_output/xgb-two-stage-cascade-results/`. Both use the same frozen seed02 test manifest (1,249,689 events), graph database SHA-256 `9819f04c1916b53d0039cd2e1875364624b4a888a04eef0ad68b0748a42745e2`, and GraphSAGE weights SHA-256 `e115645a9ba2ae98da0ba3f35220bdb1f30570225c37cbb5bc1dbcb3fc93e8ad`. This is **not** the later LightGBM joint-policy notebook/run.

## Result and route accounting

| Model | Graph threshold | TP | FP | FN | TN | F1 | Direct FP/FN | Graph FP/FN | Missing target lookup/identity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Older LightGBM cascade | 0.95 | 39,654 | 568 | 656 | 1,208,811 | 0.984801 | 379 / 269 | 189 / 387 | 0 / 0 |
| XGB cascade | 0.85 | 39,301 | 573 | 1,009 | 1,208,806 | 0.980270 | 172 / 308 | 401 / 701 | 0 / 0 |

Both validation-selected policies route only ML scores in `[0.30, 0.96)` to GraphSAGE. Scores below 0.30 become negative; scores at least 0.96 become positive. Thus the direct-branch errors cannot be fixed by the graph's available score under these policies. XGB's lower graph threshold can accept more benign events and its frozen ML score distribution differs from LightGBM's; aggregate counts alone cannot isolate one cause of the model difference.

## Does the event split cut parent/grandparent edges?

**No.** `preprocess/build_graph.py` scans every raw line of its 106 configured sources with `observe(...)`; the split mask controls which rows are inserted into the `target` lookup table. It does not control insertion into `parent`, `fact`, `flow`, or `binding`. The graph is label-blind, and `EgoGraphs`/`Encoder` do not query TRAIN/validation/TEST labels for ancestry. Both bundles contain the same complete graph and learned weights. An observed parent can be in TRAIN, validation, TEST, or a noncandidate raw event and still be used if it passes the causal-time rule. The complete graph records zero missing identity/time rows; both cascade results report zero missing target lookups and identities.

A direct raw-log counterexample: XGB TEST FN `source_id=1b70bf046dfc4b986018604e0cfb71164280863a53edfbb18ae8446f05e76882`, line **2,379,601**, is a `MODULE LOAD` by `conhost.exe`, timestamp `2019-09-24T13:58:56.189-04:00`, label 1, ML score 0.940119, graph score 0.386566. Its observed `PROCESS CREATE` is line **2,379,576** in the same gzip source, timestamp `13:58:56.169`, 20 ms earlier, with the new conhost process as object. That CREATE is assigned to **TRAIN** (split 1), yet exists in the graph database. The graph does not use it for this TEST event because of the one-second cutoff described below. This is evidence against cross-split edge deletion.

The random event split is still a **generalization limitation**: the graph ontology audit finds all 34 hosts and 41,625 processes appear in all three partitions. Shared process context may make validation/test easier than a process-tree-held-out or temporal test. That is a different issue from parents being cut by the split.

## Measured ancestry availability among errors

The graph rounds each target timestamp down to a one-second boundary before extracting prior facts/edges. A CREATE at `56.169` is genuinely earlier than a target at `56.189`, but both round to cutoff `56.000`; the query requires CREATE time `<56.000` and drops that edge. `no CREATE edge` below means no visible CREATE edge in the *inference ego graph*, not necessarily no raw CREATE record.

| Error cohort | Events | No visible parent CREATE | Earlier CREATE in same second, excluded | No observed CREATE record | Visible parent CREATE |
| --- | ---: | ---: | ---: | ---: | ---: |
| XGB graph-routed FN | 701 | 507 | 490 | 17 | 194 |
| XGB graph-routed FP | 401 | 23 | 19 | 4 | 378 |
| XGB direct FN | 308 | 117 | 88 | 28 (plus 1 simultaneous) | 191 |
| XGB direct FP | 172 | 53 | 53 | 0 | 119 |
| LightGBM **old-baseline** FN remaining after graph | 356 | 188 | 181 | 7 | 168 |
| LightGBM **old-baseline** FP remaining after graph | 28 | 0 | 0 | 0 | 28 |

For XGB, the `test_errors.jsonl` file has all 1,582 final errors, so the XGB rows above are exhaustive. Of the 490 XGB graph FNs with same-second parent CREATE, 393 parent CREATE rows are TRAIN, 66 validation, and 119 TEST: the split membership plainly does not determine the missing edge. These 490 event errors arise from 92 distinct actors, so repeated events from an actor amplify the event count.

The older LightGBM ZIP lacks a full final error list. Its approved baseline diagnostics contain all 446 FP and 3,189 FN; applying the frozen cascade policy and the identical graph/weights reproduces 407 remaining old FP (379 direct, 28 graph) and 625 remaining old FN (269 direct, 356 graph). The final totals therefore include **161 new FP and 31 new FN** that cannot be individually audited from this result package. The LightGBM ancestry counts above apply only to the 356 traceable old-baseline graph FNs, not all 387 final graph FNs. The graph corrected 2,564 old-baseline FNs; every one of those had visible CREATE ancestry. This is an association, not proof that restoring an edge would fix every miss.

## Other causes visible in the evidence

- **Routing:** Direct errors bypass graph arbitration. XGB has 172 direct FP and 308 direct FN; older LightGBM has 379 direct FP and 269 direct FN. Some have a visible parent and some do not, but the policy ignores GraphSAGE in both cases.
- **Graph errors despite complete ancestry:** XGB has 194 graph FNs and 378 graph FPs with a visible parent CREATE; older LightGBM has at least 168 old-baseline graph FNs and 28 old-baseline graph FPs with visible ancestry. A complete edge alone is insufficient. The graph uses coarse process role/location/launch/network facts and prior context; it does not encode the target FILE/MODULE action or target object directly. The graph threshold and learned decision still matter.
- **Indistinguishable or near-indistinguishable telemetry:** `analyst/cascade_fn_fp_raw_comparisons.md` verifies opposite-label events with identical Host sparse vectors, including benign versus malicious Chrome font reads and PowerShell `Start-Sleep`. Identical tree inputs necessarily yield identical ML scores. Some pairs also receive similarly high or low graph scores. In the Chrome font FP example, the actor has two CREATE ancestry edges; the error is not caused by a missing parent. The benign updater `Start-Sleep` has a low graph score, but the old LightGBM score is ≥0.96, so direct-positive routing bypasses that useful veto.
- **Unobserved/limited context:** A small minority of XGB graph errors (17 FN, 4 FP) have no observed parent CREATE in this indexed source set. This can reflect source scope, absent CREATE telemetry, or identity/timing limitations; the result cannot distinguish these without targeted raw tracing. The one-second cutoff is not the explanation for those 21 cases.

## Conclusion and next valid experiment

The seed02 split did **not** remove parent/grandparent log events from the graph. The strongest measured graph-structure failure is the **one-second causal snapshot**, which hides a valid earlier same-second CREATE for 490/701 XGB graph FNs and 181/356 traceable older LightGBM graph FNs. This is an implementation tradeoff in the graph representation, not a split-assignment error. It is also not the sole cause: routing bypasses the graph, many wrong graph decisions already have ancestry, and sparse/coarse features collapse opposite-label behaviors.

To test causality of the snapshot issue, build a separately versioned exact-time or finer-quantum graph inference/training experiment, tune its policy on validation, then evaluate the frozen test once. Do not retrofit edges only for known TEST errors or claim that every restored edge becomes a TP. A process-tree-grouped or temporal split is a separate generalization experiment and requires retraining/evaluation under that split.
