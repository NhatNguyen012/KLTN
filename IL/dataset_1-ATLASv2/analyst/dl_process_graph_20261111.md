# Process-centered learned graphs and explicit uncertainty — 11 November 2026

This implements the next experiment after the
[graph-context BiLSTM study](dl_provenance_context_20261111.md). It changes the
representation and supervision together, then uses matched controls to separate
their effects. Original datasets, labels, splits and checkpoints remain intact.

The two reviewed-policy graph runs reach **65.6% / 64.3% binary F1 on the
original 2,369-window test benchmark**, versus 54.2% for recalibrated v5.
This is a useful binary-detection improvement, but not a completed attack-stage
estimator. Attribution remains imperfect and legacy single-stage compatibility
degrades. All results are exploratory on repeatedly inspected scenarios.

## What changed

### Explicit unknown supervision

`data/review_ledger.csv` records a decision and source lines for every window.
The review is separate from feature construction:

- Portal-only positive evidence is **unknown**, not reassigned to benign.
- S3 windows are excluded from reviewed-policy supervision because the documented
  attack start contradicts the available telemetry.
- In mixed windows, the unresolved portal event does not supply a stage target;
  other historical positive evidence remains available.
- All remaining stage targets are **weak historical process-stage labels**.
  This is not a newly verified event/tactic ground truth.

| Split | Original windows / positives | Retained windows / positives | Exclusions |
| --- | --- | --- | --- |
| TRAIN | 2,759 / 89 | 2,679 / 82 | 73 S3 windows; 7 portal-only positive windows |
| VAL | 1,960 / 40 | 1,960 / 40 | None |
| TEST | 2,369 / 38 | 2,356 / 25 | 13 portal-only positive windows |

Thirteen test positives are masked only in the retained-evidence evaluation. The
full original benchmark is still reported. Retained evidence is not certified
gold truth, and its F1 must not be substituted for the original benchmark's F1.

### Multi-label stage presence replaces last-event supervision

All stages supplied by the window's positive events are retained. Execution /
Discovery now supplies targets in **54 TRAIN windows**, compared with nine under
the old last-event rule. No additional raw events or independent attacks were
created; overlapping windows still repeat evidence.

Original multi-label TRAIN support is [54, 54, 30, 48] for the four stages.
Reviewed TRAIN support is [53, 54, 24, 48]. Reviewed TEST support is [6, 18, 7, 18].

The task is now **which stages have evidence somewhere in this completed
window**, not which stage the attacker is currently in. Presence scores and
historical single-stage F1 are different quantities.

### Learned graph model

The new model consists of:

1. Separate temporal event sequences for each observed process, encoded by a GRU.
2. Source/target semantics and existing categorical evidence, using a TRAIN-only
   vocabulary of 252 event columns.
3. Two learned message-passing layers over typed process relationships. Source
   state, relation embedding and age embedding contribute to each message.
4. Per-process stage logits pooled across processes with multiple-instance max
   pooling. Binary detection uses the largest stage score, so a separate binary
   head cannot veto every stage.

There are 17 TRAIN-fitted relation IDs including unknown/reverse directions.
Inputs include observed parents, incoming process/thread handle interactions,
and recent file-writer/image-path relationships. Thread-open remains distinct
from remote-thread creation. The construction draws on the edge-aware message
pattern in `paper-general/code/NDSS/theseus-main/models/esage_encoder.py` without
claiming to reproduce Theseus or its evaluation.

Bounds: 64 central processes, 128 graph nodes, 64 recent events per process,
two observed history hops, eight history records per relation, and 24-hour
history TTL. No central processes were omitted in this dataset. Process sequences
were truncated in 428 TRAIN, 94 VAL and 159 TEST process instances. Rare events
earlier than the retained sequence can therefore still be lost.

The prediction time is the end of the completed window. Every graph edge and
node description must be available by that timestamp. Earlier snapshots must
precede their original query event. Device event-time ordering is assumed;
late-ingestion behaviour is not evaluated.

GUIDs and full paths identify joins and audit records only. There are no labels,
review decisions, scenario/host identities, reputation fields, attack timestamps,
known-IOC flags or true ancestor/neighbor labels in the model inputs. Existing
application categories remain observable features, so executable-name shortcuts
still require scrutiny. No command or decoded payload is executed.

## Controlled experiments

Eight initial trials compare process-only versus learned graph models and
original versus reviewed supervision, for seeds 42 and 43. They train from
scratch for 20 epochs; the best checkpoint and exact FPR-constrained threshold
come from validation only. Epoch 0 is eligible. Graph residuals start at zero,
giving the matched process and graph controls identical initial logits.

The losses are binary window BCE plus weighted multi-label stage BCE. Class
weights use TRAIN targets only. There is no synthetic OpTC replay. These are
representation/supervision experiments, **not domain-incremental retention
results**; authentic source replay/test tensors are still needed for that claim.

| Model | Training supervision | Seed | Original test F1 | TP / FP / FN | Retained-evidence F1 |
| --- | --- | ---: | ---: | --- | ---: |
| Recalibrated existing v5 | Historical | — | 54.24% | 16 / 5 / 22 | 69.57% |
| Process-only | Original | 42 | 60.87% | 21 / 10 / 17 | 75.00% |
| Process-only | Original | 43 | 58.06% | 18 / 6 / 20 | 73.47% |
| Learned graph | Original | 42 | 61.97% | 22 / 11 / 16 | 75.86% |
| Learned graph | Original | 43 | 62.07% | 18 / 2 / 20 | 80.00% |
| Process-only | Reviewed | 42 | 64.29% | 18 / 0 / 20 | 83.72% |
| Process-only | Reviewed | 43 | 58.06% | 18 / 6 / 20 | 73.47% |
| Learned graph | Reviewed | 42 | **65.62%** | **21 / 5 / 17** | **82.35%** |
| Learned graph | Reviewed | 43 | **64.29%** | **18 / 0 / 20** | **83.72%** |

Retained-cohort reference v5 is recalibrated on the same VAL data, then evaluated
on the same 2,356 retained TEST windows. Its 69.57% is a different metric from
54.24% on the full original benchmark; the table keeps both explicit.

The graph improves binary F1 over its process-only control in both seeds under
both supervision policies. This small experiment does not establish statistical
reliability or fresh-campaign generalization. Additional parameters and training
choices also differ from the old BiLSTM, so the entire v5-to-new-model improvement
must not be attributed solely to graph edges.

## A further failure found by attribution, and a tested correction

Window-only supervision allows a model to explain a positive window using an
irrelevant process. In `win-32-h1_m6_w0025_c00`, the initial learned graph selected
a generic `System` node as the highest-scoring central process. This is not a
reliable attribution to the Regsvr32/PowerShell execution chain. Deleting graph
edges sometimes raised the score, further undermining a simple causal story.

I therefore built a separate `process_supervision.pt` sidecar from **current
event actor annotations**, and added a balanced process-local auxiliary loss.
Unknown processes/windows are masked. Neither these targets nor ancestor labels
are exposed to `forward()`. This is an additional supervised loss, not a token
or input that announces an attack.

Two more 20-epoch trials tested that correction:

| Reviewed graph + process loss | Original F1 | TP / FP / FN | Retained-evidence F1 |
| --- | ---: | --- | ---: |
| Seed 42 | 67.80% | 20 / 1 / 18 | 86.96% |
| Seed 43 | 51.22% | 21 / 23 / 17 | 60.87% |

Seed 42's recovered execution windows localize to `cmd.exe` in M6 `w0028` and
`powershell.exe` in S4 `w0037`, rather than `System`. It detects two of the four
historical Execution/Discovery windows. Seed 43 still has a `System` attribution
in one execution window and substantially more false positives. The additional
loss is therefore **an unstable experimental option**, not the recommended
default. Reporting only its 67.80% run would conceal a material failure.

## Stage limitations are still substantial

The reviewed graph models have retained-evidence stage-presence macro F1 of
62.38% and 75.85%. This must not be compared with old single-stage macro F1.
Execution frequently co-occurs with Exfiltration; predicting both can score well
without correctly identifying the instantaneous phase or responsible process.

As a compatibility check, forcing the reviewed graph models' outputs through a
single stage argmax gives historical attack macro F1 of **1.67% and 0%**.
The additional process-loss trials give **41.67% and 16.36%**. The old v5 value
was 23.53% after fixing its metric. These results show why the new presence
model cannot be a drop-in replacement for a single-current-stage interface.

Early binary recovery also varies. Reviewed graph seed 42 detects three windows
with historical stage 1–3 labels; seed 43 detects none. Much of the binary gain
comes from recovering all 18 Exfiltration windows and reducing false positives.
The auxiliary seed-42 model detects two actual execution windows with improved
localization, but the second seed does not confirm stable recovery.

Reliable stage progression needs reviewed action/time annotations, process-local
attribution evaluation, and a separately defined state-estimation objective.
The remaining historical process-name stage taxonomy is weak, not validated by
these experiments. Two test scenarios and overlapping windows cannot establish
broad campaign generalization.

## Why these limitations exist

| Limitation | Mechanism and evidence | Required correction |
| --- | --- | --- |
| Contradictory event targets | Process-name rules label routine Firefox portal connections positive; the S3 time gate falls after the available records. More capacity cannot reconcile these targets with the intended behaviour definition. | Keep uncertain examples explicitly unknown; adjudicate actions against raw records and scenario timelines before claiming corrected gold labels. |
| Stage information disappears | A last-positive-event target collapses co-occurring stages into one class. Multi-label presence restores that supervision but describes a different task. | Define whether the output means stage presence or current phase; obtain action/time annotations for a phase estimator. |
| Wrong process gets credit | Window-level loss rewards any process that predicts the window label, including a generic System node. Message passing does not by itself identify the responsible actor. | Evaluate process attribution separately; refine local targets and balance their loss. The tested auxiliary loss is still seed-sensitive. |
| Rare behaviour is missed | A large event window mixes ordinary activity with a few relevant actions. Bounded per-process sequences can still drop earlier evidence, and only four historical Execution/Discovery test windows are available. | Preserve sparse causal actions with bounded summaries; collect more independent execution examples and campaigns. |
| Apparent generalization is fragile | Test scenarios have been repeatedly inspected; overlapping windows repeat evidence. Two seeds measure training variability, not independent campaign variation. | Freeze this candidate, then use a new campaign/host holdout and campaign-level uncertainty estimates. |

The earlier [root-cause audit](dl_root_cause_20261111.md) documents the threshold
and metric errors and the literature evidence. The [context study](dl_provenance_context_20261111.md)
links the ML incoming-context adaptation and source-level counterfactual cases.
Together these distinguish preprocessing/label errors from representation and
evaluation limits; none alone explains the whole result.

## Candidate, artifacts and reproduction

The experimental candidate is **reviewed graph seed 42 without the process
auxiliary loss**, selected by the predeclared validation score among reviewed
training policies. Its validation binary F1 is 87.67%; its validation joint
selection score is 0.782827. The higher test-F1 auxiliary run is not selected by
looking at TEST. The candidate remains a research detector, not a certified
replacement or a proven continual-learning model.

Artifacts are under `code/DL/output/process_graph_20261111/`:

- `data/review_ledger.csv`: every window's review reason and uncertain source lines.
- `data/{train,val,test}.pt`: graph features and separately stored targets/audit IDs.
- `data/metadata.json`: feature/edge vocabularies, fit scope, caps, identities and review counts.
- `runs/`: the eight matched control experiments, checkpoints, histories and predictions.
- `process_supervision.pt`: separate current-process weak loss targets.
- `runs_process_supervised/`: the two attribution-loss trials, including the failed seed.
- `comparison.csv`, `comparison_summary.json`: all ten results, old-task compatibility and early-window diagnostics.
- `case_explanations.csv` inside audited runs: highest-scoring process, raw source lines and fixed-weight edge-removal effects.
- `candidate.json`: validation-selected experimental checkpoint and identity.
- `source_initial/`, `source_final/`: implementations before/after the attribution-loss experiment.
- `input_identity.json`, `final_source_identity.json`, `verification.json`: hashed inputs/source and regression evidence; all eight original shard arrays match their frozen context copies.
- `logs/`: preserved build, training and comparison logs.

The initial build helpers expect existing audited context artifacts and refuse
to overwrite a published dataset. Training can use a fresh output namespace:

```bash
python3 IL/dataset_1-ATLASv2/code/DL/model/train_process_graph.py \
  --output-dir /tmp/atlas_process_graph_reproduction --seeds 42 43
python3 IL/dataset_1-ATLASv2/code/DL/audit/summarize_process_graph.py \
  --include-process-supervision
python3 -m unittest discover -s IL/dataset_1-ATLASv2/code/DL/test
python3 -m unittest ML.code.test.test_incoming_context
```

Focused tests verify unknown handling, future-record invariance, target/input
separation including process-local labels, cross-sample graph isolation, identical
initial controls and gradient flow into learned graph layers. All 22 local tests
and seven original ML incoming-context tests pass. Historical Kaggle notebooks
are not synchronized to this research branch.
