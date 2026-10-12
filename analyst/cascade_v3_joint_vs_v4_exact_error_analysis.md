# LightGBM two-stage cascades: v3 joint policy versus v4 exact-time graph

## Scope and comparability

This compares the actual downloaded folders:

- `code/output/provenace_graph/kaggle_output/optc-two-stage-cascade-results/`: **v3 one-second graph + joint policy**, NOT the original 98.48% legacy-policy run. Its validation-selected rule routes ML ≥0.10 to GraphSAGE, with low/middle/high graph thresholds 0.995/0.95/0.70.
- `code/output/provenace_graph/kaggle_output/lgbm-two-stage-cascade-results/`: **v4 exact-microsecond graph + legacy cascade policy**. Its validation-selected rule is ML <0.30 direct negative; 0.30≤ML<0.96 graph at 0.95; ML≥0.96 direct positive.

Both have the same full TEST manifest SHA-256 `421d1855c2ae46f01b531f242aaa265a3a23b992d2969b24d534b1b088367fc5`, 1,249,689 events, frozen LightGBM checkpoint/threshold 0.94016, frozen GraphSAGE weights and graph SQLite. Both reproduce the approved LightGBM baseline exactly: TP 37,121, FP 446, FN 3,189, TN 1,208,933. Their bundle hashes differ because the ego-graph inference code differs. Neither selected thresholds on TEST labels. The v4 GraphSAGE checkpoint was trained on one-second snapshots, so this is an inference-input change, not retraining.

| Test evaluation | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| v3 joint policy, measured folder | 38,603 | 594 | 1,707 | 1,208,785 | 0.984846 | 0.957653 | 0.971059 |
| v3 **legacy policy on same v3 scores**, from `old_vs_joint_policy.json` | 39,654 | 568 | 656 | 1,208,811 | 0.985878 | 0.983726 | 0.984801 |
| v4 exact-time graph + legacy policy, measured folder | 39,732 | 630 | 578 | 1,208,749 | 0.984391 | 0.985661 | 0.985026 |

The v4-versus-v3-joint gain is **1.397 F1 percentage points**, but two factors changed. The controlled legacy-policy comparison isolates the exact-time graph's observed effect: **78 additional TP, 78 fewer FN, 62 additional FP, F1 +0.0225 percentage points**. Direct branches are identical (379 FP and 269 FN); all these changes occur in the common 0.30–0.96 graph band. The v4 validation-selected policy stayed at the legacy 0.30/0.96/0.95 gates.

## Exact event transitions between the two downloaded folders

Keyed by `(source_id, source_line)`, all final errors reconcile exactly:

| Error | Shared | v3 joint only, corrected by v4 | v4 only, new error | v3 total | v4 total |
| --- | ---: | ---: | ---: | ---: | ---: |
| FP | 472 | 122 | 158 | 594 | 630 |
| FN | 571 | 1,136 | 7 | 1,707 | 578 |

The transition mechanisms are mutually exclusive by LightGBM score band:

- **Middle 0.30–0.96, same decision rule:** Exact-time graph restores prior same-second CREATE ancestry and changes the score across 0.95 for **78 malignant events (FN→TP)** and **62 benign events (TN→FP)**. Every one of these 140 events had no CREATE edge under v3 and has ancestry under v4. This is the directly measured effect of the time fix on final decisions.
- **High ML ≥0.96, policy difference:** v3 joint GraphSAGE rejected **1,058 malignant events (FN→TP under v4's direct-positive rule)**. Conversely, v3 graph veto correctly rejected **96 benign events** that v4's direct-positive rule makes FP. Some graph scores also change with exact time, so the 1,058 are not all solely caused by the policy; the shared decision-rule counterfactual above isolates the time effect.
- **Low ML <0.30, policy difference:** v3 joint rescued **7 malignant events** that v4 directly rejects (TP→FN), but also promoted **122 benign events** that v4 directly rejects (FP→TN). These 129 examples have unchanged graph scores between v3 and v4 in the recomputation.

Across the union of 2,466 event errors, local recomputation from the hash-matched SQLite graph and frozen GraphSAGE weights matched every exported non-null v3/v4 graph score within 1e-6; LightGBM scores matched across both error exports. The machine-readable per-event comparison is in `code/output/provenace_graph/audit_v3_joint_vs_v4_exact/union_errors.jsonl` and aggregate counts in its `summary.json`. This union is sufficient for the observed error transitions; it is not a full-test score export.

## Raw-log tracebacks

The source-line numbers below are decompressed JSONL lines. Raw files were streamed read-only; only selected fields are summarized. Event labels are the evaluation target, even when a benign-labeled event occurs inside a suspicious process chain.

1. **FN rescued by the exact-time fix:** TEST `source_id=1b70bf046dfc4b986018604e0cfb71164280863a53edfbb18ae8446f05e76882`, line **2,422,567**, in `host-malicious/2019-09-24/AIA-1-25/...sysclient0005.json.gz`, is a label-1 `MODULE LOAD` of `kernel32.dll` by `cmd.exe` at `14:00:57.719`. Its PROCESS CREATE is line **2,422,529** at `14:00:57.610`, 109 ms earlier. ML 0.955292 falls in the graph band. CREATE edges go **0→2**, graph score **0.386566→0.997976**, changing FN→TP at 0.95. This is a direct mechanism trace, not merely a correlation.
2. **New FP caused by the same fix:** TEST `source_id=3ddf9b820509de09fdff0400395b44a012f23cc40a7ce6f61931bf2e934a69ce`, line **2,982,008**, in `host-malicious/2019-09-23/AIA-401-425/...sysclient0402.json.gz`, is a label-0 `MODULE LOAD` of `msvcrt.dll` by `PING.EXE` at `13:29:34.937`. Parent CREATE line **2,981,994**, six milliseconds earlier, launches PING from `powershell.exe` toward `142.20.57.226`. ML is 0.896068. CREATE edges **0→2**, graph score **0.926600→0.998326**, changing TN→FP. The graph now recognizes risky process context, but the target module-load event remains benign-labeled.
3. **FN due purely to high-score veto, not missing ancestry:** TEST `source_id=13a33d9d3facc4474f8f5d92e1f6e512a38c05902c866c8c30075a0bbb98f15e`, line **3,113,813**, in `host-malicious/2019-09-23/AIA-851-875/...sysclient0874.json.gz`, is a label-1 `OPEN PROCESS` by `conhost.exe`. ML is **0.993033**; both graph versions have two CREATE edges and identical score **0.495238**. v3's 0.70 high-band graph gate makes FN; v4's direct-positive rule makes TP. The time fix does not explain this transition.
4. **FP because high-score direct routing loses a useful veto:** TEST `source_id=1b70bf046dfc4b986018604e0cfb71164280863a53edfbb18ae8446f05e76882`, line **2,461,557**, is a label-0 Chrome `MODULE LOAD` of `davhlpr.dll`. ML **0.991115**, graph **0.141269** in both versions, and both have two CREATE edges. v3 joint graph veto makes TN; v4 direct-positive makes FP. The graph has context, but v4's route does not consult it.
5. **Persistent FP despite full ancestry:** Same sysclient0005 source, line **2,380,855**, is a label-0 Chrome `FILE READ` of `COMICBD.TTF`. ML **0.971660**, graph **0.997730** in both versions, with two CREATE edges. It is FP under both policies. The matched opposite-label same-vector Chrome font case in `analyst/cascade_fn_fp_raw_comparisons.md` shows that the Host vector collides and the graph rates the browser contexts similarly; this is not an ancestry gap.
6. **Persistent FN despite full ancestry:** Same sysclient0005 source, line **2,408,546**, is a label-1 `THREAD TERMINATE` by `sppsvc.exe`. ML **0.235908**, graph **0.001555** in both versions, with two CREATE edges. v3 joint and v4 both predict benign. The raw event looks like a common service action, while the event label is malicious; the available ML and graph representation does not encode enough discriminating evidence for this case.
7. **Restored edge does not always rescue:** `source_id=05e3664ca50f224173a28d22741416165a5ec8225d9c0700446930c9479d01be`, line **2,723,374**, is a label-1 `FILE READ` of a `CONHOST.EXE` prefetch file. Its conhost CREATE is seven milliseconds earlier. CREATE edges **0→2**, but GraphSAGE score **0.163975→0.076762**: the event stays FN. Adding an edge can lower as well as raise the learned risk score.

## Root causes of the remaining v4 errors

The v4 error ZIP lists **630 FP and 578 FN**. The fixed graph has zero missing target lookups and identities. Among its **309 graph-routed FNs**, only **8** lack a visible CREATE edge; the other **301** have ancestry yet score below 0.95. All **251 graph-routed FPs** have visible CREATE ancestry and score at least 0.95. Thus missing parent context is no longer the dominant residual cause.

The fixed gate still directly produces **379 high-ML FP** and **269 low-ML FN**. V4's diagnostic `test_errors_full_scores.jsonl` shows 105 of those high-ML FP have graph score <0.95, and 53 of the low-ML FN have graph score ≥0.95. These are *candidate* veto/rescue cases only; v3 joint demonstrated that broad rerouting also causes many other FNs/FPs. Any new policy must be selected on validation, then frozen for test.

The remaining graph mistakes reflect the learned model's coarse prior process/host facts, its inability to directly inspect the target event's file/module/action, overlapping raw behavior across opposite event labels, and the validation-selected 0.95 decision threshold. A complete parent edge is necessary for some successful rescues but is not sufficient to classify an event correctly. The existing frozen GraphSAGE weights were trained on one-second graphs; exact-time inference changes their input distribution. This test comparison cannot establish whether retraining on exact-time graphs would improve generalization.

A read-only pass over every v4 error's raw JSONL line confirms the concentration in ordinary-looking subevents. Of 309 graph FNs, 121 are `MODULE/LOAD`, 59 `FILE/READ`, and 144 have `conhost.exe` as image; 64 have `MicrosoftEdgeCP.exe`. Of 251 graph FPs, 80 have `lwabeat.exe`, 62 `cmd.exe`, and 43 `conhost.exe` as image. Of 379 high-ML direct FPs, 111 are Chrome, 108 PING, and 85 PowerShell image events. These are event counts, often repeated within the same actor, not independent root incidents. The reproducible action/image tally is in `code/output/provenace_graph/audit_v3_joint_vs_v4_exact/raw_event_summary.json`.
