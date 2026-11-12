# ATLASv2 DL low-F1 investigation — 11 November 2026

The low F1 has several concrete causes in the **labels, representation, decision
policy and training objective**. It is not adequately explained by class imbalance
or a lack of LSTM capacity. Some earlier reports also overstate the measured
performance. This investigation preserves historical checkpoints and separates
results on the old labels from sensitivity experiments with revised labels.

All evidence and new experiments are under
`../code/DL/output/research_20261111/`. No raw telemetry was modified.
The NVIDIA driver was unavailable; new inference/training used CPU float32.

## What was actually audited

- Streamed **all 1,857,763 CBC rows in 18 files**, with SHA-256 per input.
- Reconstructed the legacy 180-second windows, 30-second stride, chunk size 512,
  retained event types and scenario split. Every retained manifest sample matched
  its reconstructed stage and event count: zero mismatches.
- Audited 48,169 retained source events, including 259 refined-positive events.
  These are source-event counts, not independent attacks. Overlapping windows
  repeat evidence.
- Recomputed metrics from every historical local-run confusion matrix; strictly
  loaded the v5 checkpoint into its current attention architecture and exported
  sample-level validation/test probabilities and errors.
- Read the local ATLASv2 report, REAPr methodology, StageFinder and NDSS benchmark
  paper; checked their primary online publications.

## 1. The decision policy is demonstrably broken

`train_local.py::find_optimal_threshold` searched binary thresholds only between
0.01 and 0.50. The same model's best feasible validation threshold can be above
0.50. Per-stage calibration additionally defaulted to 0.01 when no useful
threshold satisfied its FPR budget. That fallback reintroduced the very false
alarms the budget had rejected. Independently constrained stage decisions were
then unioned with a binary decision without enforcing a final alert-rate budget.
Its precision calculation also omitted wrong-stage predictions from the negative
class. Those errors made calibration an unreliable decision rule.

Measured on **the same v5 weights and original test labels**:

| Decision policy | TP | FP | FN | Binary F1 | Benign FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Historical v5 stage-calibrated | 30 | 516 | 8 | 10.27% | 22.14% |
| Historical v5 global at 0.50 | 17 | 37 | 21 | 36.96% | 1.59% |
| Exact validation-selected global threshold, CPU | 16 | 5 | 22 | **54.24%** | **0.21%** |

The last threshold is 0.8936129212, selected using **validation only**, maximizing
binary F1 under validation FPR <=2%. Its validation F1 is 68.75%, with two FP.
Threshold recalibration changes the operating point, not ranking quality: test
average precision remains about 0.504. This is a real software fix, but early
stage recall remains poor. It is not a fresh untouched test result.

Implemented: exact tied-score threshold search over the full score range plus
the no-alert operating point; global gating; equal conditional thresholds that
cannot bypass the selected gate. Future stage-specific calibration must optimize
the *final* multiclass decision jointly and enforce its aggregate FPR.

## 2. The reported attack macro F1 excluded the false positives

The historical code filtered to `y_true > 0` before computing attack-class macro
F1. That excludes every benign false alarm. It is an attack-conditioned diagnostic,
not operational stage-classification F1. Filtering by class **labels** in the F1
calculation must retain **all rows**.

For historical v5 calibrated predictions, the reported 40.45% becomes **16.34%**
when benign false positives are included. Historical v4 becomes 22.37%, versus
the reported 24.29%. The v5 change therefore did not demonstrate the claimed
operational stage-F1 improvement. Its 309 false Initial-Compromise alerts and
192 false Lateral-Movement alerts were effectively hidden from that diagnostic.

Implemented: operational attack macro F1 includes benign rows everywhere in the
local trainer and its validation checkpoint score. Historical JSON files remain
unchanged; corrected calculations are in `audit/audit_summary.json`.

## 3. A time gate erases an entire training attack

`common_schema.py` sets S3's initial attack time to **2022-07-19 15:36 UTC**.
The actual S3 retained telemetry ends at **15:01:10 UTC**. All **758** selected
events whose actor has a REAPr attack GUID occur before that gate. None becomes a
positive training event. The copied timestamp exists in the dataset report, whose
S3 running interval and initial-step time are internally inconsistent.

The targeted endpoint trace finds REAPr-flagged `regsvr32.exe` connecting to
`ortrta.net` / 10.193.66.115:8080 at **14:33:24 UTC**, with further PowerShell
connections at 14:36 and payload traffic at 14:37. These source-line-linked
records are in `raw_audit/s3_curated_endpoint_timeline.csv`. They establish attack
infrastructure activity well before the copied gate; they do not independently
establish the exact initial-compromise timestamp.

This is not evidence that S3 has no attack. It is an unresolved source-time
contradiction. Do not silently invent a replacement timestamp or label every
pre-gate event as attack. The revised sensitivity dataset excludes S3 until its
timeline is adjudicated using the attack procedure and raw process/file evidence.

## 4. Seed endpoint membership is not a verified malicious connection

The event refiner accepts a Firefox connection if its endpoint appears in a REAPr
seed list. The upstream REAPr ATLASv2 README explicitly documents wrongly
implicated remote endpoints arising from background browsing.

The raw audit confirms ordinary `detectportal.firefox.com` and
`prod.detectportal.prod.cloudops.mozgcp.net` connections to **34.107.221.82:80**
becoming positive on both M6 hosts. These events supply all eight test windows
whose final stage is Initial Compromise. This is a direct consequence of the
local event-label policy, rather than proof that a model should detect those
connections as malicious. In addition, seed endpoints can include legitimate
attack infrastructure, so removing all seed-only matches can lose true evidence.

The conservative-v2 policy ignores seed endpoint membership while retaining the
other historical rules. This is explicitly a **sensitivity assumption**, not a
claim of newly verified ground truth. Unresolved events should ultimately receive
an unknown/review status, with separate strict and inclusive evaluation sets.

## 5. The stage target is weak supervision, often contradictory within a window

`ATLASv2_staged/add_stage_column.py` maps `payload.exe` to Exfiltration,
`python.exe` or most h2 processes to Lateral Movement, browser/Office processes
to Initial Compromise, and other processes to Execution/Discovery. It does not
derive an event's tactic from contemporaneous actions or an independently
annotated timeline. A process can perform multiple tactics. A Python HTTP server
is also part of normal activity, and a payload can execute before exfiltration.

The builder then labels each chunk with the **last positive event's** process
stage. Mixed-stage positive windows occur in **72/89 training**, **31/40
validation**, and **23/38 test** samples. Window placement can therefore change
the target without changing most of the evidence. True initial/execution events
in S4 windows can be evaluated only as Exfiltration because a later payload event
wins. Stage-1 support is just two validation windows. Four thresholds calibrated
from such support cannot be stable estimates of future performance.

Implemented: new manifests retain start/end UTC and the complete positive
`attack_stage_set`. Existing single-stage tensors are retained for controlled
comparison; the new datasets are **not a verified five-stage benchmark**.

Recommended next representation: event-level stage labels where evidence is
available, a multi-hot window target for overlapping stages, and an explicit
unknown mask for ambiguous evidence. If the objective is the attacker's current
state, define that state separately and evaluate at the window endpoint. These
are different tasks from classifying the last process's heuristic stage.

## 6. Important discriminating evidence never reaches the model

The input is four categorical fields, one host-role bit and a time delta.
The builder mixes `FLOW_START`, `PROCESS_START` and `CROSS_PROCESS`, but does not
explicitly encode event type, operation, source/target relation, command
structure, endpoint role or connection direction. Process/cross-process events
use the target basename, while labels/stages use the actor's GUID/name. Two
different actors interacting with the same target can therefore have similar
inputs and different labels. There are **481** selected events with an
attack-labeled target but an actor not in the attack-GUID set; they are negative
under this policy. That count identifies an audit cohort, not 481 proven errors.

Unknown application vocabulary is only **0.086%** of test event positions, so
generic claims that most test applications are out-of-vocabulary are unsupported.
Median sequences have **16 events in train, 9.5 in validation, 9 in test**. The
old explanation that typical test windows contain 40–80 events is inaccurate.
Signal dilution remains plausible in particular mixed windows, but has not been
isolated experimentally as the principal cause.

Add relation-aware, bounded features and process-centered past context before
adding model depth. Keep GUIDs only for joins and grouping. Never include true
ancestor labels, scenario IDs, future context or exact test IOCs as features.
Keep a network-only evaluation separate from a host/network fused task.
+
+Transfer also changes input semantics: the source subset used a constant-zero
+binary slot and 15-minute network windows; ATLAS reuses that slot for h2 host
+identity, uses 180-second windows, and mixes process events with connections.
+The target adds attention/mixed pooling to the source network's final-state
+pooling. Compatible checkpoint tensor shapes do not imply equivalent inputs or
+forward behavior. These shifts are plausible contributors requiring ablations.

## 7. Training overcorrects imbalance, and replay is synthetic

The old binary focal loss combines alpha=0.75 and pos_weight=5: before focal
modulation, positive terms have 15 times the coefficient of negative terms.
Every natural batch additionally receives a separate all-positive binary loss.
Stage-balanced sampling is combined with inverse-square-root class weights,
compensating rare stages twice. These are objective choices that can inflate
false alarms and distort conditional stage probabilities; they are not proof
that a particular loss alone caused all failures.

More seriously, `extract_optc_network_replay.py::generate_sequence` synthesizes
both replay and the apparent OpTC test features. Positive test sample IDs/counts
are read from an OpTC result CSV, but their event contents are randomly generated.
Negatives are generated too. Training and evaluation use the same pattern
generator. **The claimed +5.13% BWT and 100% source F1 do not establish retention
on real OpTC.** Original source shard tensors are not present in the local S4
artifact directory; documentation/previews are not a replacement for them.

Implemented: synthetic replay/source-test paths are no longer default inputs.
Natural BCE, no positive-only binary auxiliary loss, and uniform stage-loss
weights under balanced stage sampling are available as the new local defaults.
Checkpoint selection uses the validation-calibrated operating point. Genuine
source retention remains unmeasured until real source test shards are restored.

## 8. Split identity and uncertainty matter

The raw reconstruction finds **10 source events shared across benign day splits**
because 180-second windows straddle midnight. New construction embargoes windows
that cross a partition boundary. There are also 13 groups of exactly identical
encoded sequences across splits; that alone is not proof of shared source events,
since coarse encodings can collide. No exact same-input conflicting stage labels
were found; this does not establish sufficient semantic information.

Windows overlap by five-sixths of their duration. Thirty-eight positive windows
are not 38 independent attacks. Use scenario/process grouped uncertainty and
incident-level recall/alert counts, alongside window precision/recall/AP/FPR.
Do not bootstrap overlapping windows as if independent. Only two test scenarios
make reliable campaign-level confidence estimates difficult.

## Research basis and limits of comparison

- [ATLAS, USENIX Security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/alsaheel)
  performs symptom-guided attack investigation over causal sequences. Its headline
  F1 is not a target for an unconditioned fixed-window network classifier.
- [ATLASv2 dataset report](https://arxiv.org/abs/2401.01341) describes realistic
  human-generated background activity and the engagement timing. Its added
  background makes the original ATLAS result an especially poor numerical proxy.
- Local `DATASET/ATLASv2_staged/reapr-ground-truth/README.md` and
  `atlasv2/README.md` specify process-centric labels and warn about redundant
  attacks and spurious remote nodes. Event refinement changes that evaluation
  target and needs its own validation. The Bitbucket source could not be opened
  through the web tool; these observations use the supplied local checkout.
- [How Benchmarks and Evaluation Protocols Shape Conclusions in PIDS, v4](https://arxiv.org/abs/2608.01454)
  supports auditing semantics and keeping selection/calibration on validation.
  Its separate treatment of ATLASv2 is relevant to the shared attack structures.
- [EagleEye, eCrime 2024](https://arxiv.org/abs/2408.09217) uses richer event
  representations, including command-line information, with learned sequence
  attention. Adding a pooling layer to impoverished inputs is not a replication.
- [StageFinder, v2](https://arxiv.org/abs/2603.07560) uses fused provenance graph
  representations and temporal stage inference. It motivates a research direction;
  its reported scores do not validate this workspace's name-based stage labels.

The earlier documentation's claimed “Causal Edge Theorem” does not establish that
all ordinary DLL loads by a compromised process must be negative. Likewise, a
2% FPR budget does not impose a mathematical F1 ceiling around 43%; F1 can improve
if actual FPR decreases. Multiplying conditional stage probabilities by attack
probability cannot itself recover evidence missing from the input.

## Reproduction and deliverables

```bash
python3 -m unittest discover -s IL/dataset_1-ATLASv2/code/DL/test
python3 IL/dataset_1-ATLASv2/code/DL/audit/audit_low_f1.py
python3 IL/dataset_1-ATLASv2/code/DL/audit/audit_raw_labels.py
# Always choose a new output directory; published builds/runs are not overwritten.
python3 IL/dataset_1-ATLASv2/code/DL/preprocess/build_network_shards.py \
  --label-policy conservative-v2 --output-dir /tmp/atlasv2_new_build
python3 IL/dataset_1-ATLASv2/code/DL/model/train_local.py \
  --device cpu --epochs 12 --data-dir /tmp/atlasv2_new_build \
  --output-dir /tmp/atlasv2_new_run
```

`raw_audit/positive_events.csv` links positives to source file/line and endpoint;
`window_trace.csv` links every retained sample to its raw source lines.
`audit/v5_test_errors.csv` exports FP/FN/stage errors and scores.
`data_v2/` contains the conservative sensitivity shards; `data_v2_identity.json`
records their source/build/shard identity. The original builder fingerprint
omitted label policy and sources; future builds now include those identities.
Kaggle notebooks retain historical embedded code and must be regenerated before
claiming these local fixes apply there.

The experiment table and the recommended operating checkpoint are recorded in
the accompanying `dl_experiment_results_20261111.md` after all runs finish.
