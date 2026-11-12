# Workspace file-role map

The historical root `code/` layout in AGENTS.md has moved into domain branches.
This map covers the ATLASv2 DL investigation (2026-11-11).

| Path | Role |
| --- | --- |
| `IL/dataset_1-ATLASv2/code/preprocess/` | Shared CBC adapter, heuristic event labels, scenario split, process stage lookup; also used by Host ML. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/build_network_shards.py` | Local sequence builder; four categorical fields, host-role bit, time deltas; generated shards under `preprocess/output/`. |
| `IL/dataset_1-ATLASv2/code/DL/model/bilstm.py` | Packed BiLSTM, attention pooling, binary and conditional stage heads. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/provenance_context.py` | Label-blind CBC graph context: actor/relation structure, observed parent, typed incoming edges and recent image writer; strict past and bounded state. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/build_provenance_context.py` | Fits extra vocabulary on TRAIN events and enriches frozen legacy shards without changing base tensors, labels or membership; publishes under `DL/output/provenance_context_20261111/data/`. |
| `IL/dataset_1-ATLASv2/code/DL/model/train_provenance_context.py` | Paired none/event/graph BiLSTM ablations from identical v5 weights; zero-initialized optional context projection, validation-only selection, per-sample predictions. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/process_graph_data.py` | Label-blind window-end two-hop graph construction and separately invoked weak-label review; process sequences, typed edges and explicit unknown masks. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/build_process_graph.py` | Builds new process-graph datasets and a source-line-linked review ledger from existing audited events; original artifacts stay frozen. |
| `IL/dataset_1-ATLASv2/code/DL/model/process_graph.py` | Process GRU, optional two-layer typed message passing, and multi-label multiple-instance stage presence; no separate binary veto head. |
| `IL/dataset_1-ATLASv2/code/DL/model/train_process_graph.py` | Process/graph × original/reviewed supervision experiment from scratch; validation-only calibration/checkpoints; outputs under `DL/output/process_graph_20261111/`. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/build_process_supervision.py` | Separate weak targets for current-process auxiliary loss; unknown windows/processes are masked, no neighbour/ancestor labels become inputs. |
| `IL/dataset_1-ATLASv2/code/DL/audit/summarize_process_graph.py` | Original and retained-evidence cohort comparisons, legacy-stage compatibility and early-window diagnostics. |
| `IL/dataset_1-ATLASv2/code/DL/audit/explain_process_graph.py` | Highest-scoring central process, raw source lines and fixed-weight edge removal for each baseline FP/FN case. |
| `IL/dataset_1-ATLASv2/code/DL/audit/trace_provenance_errors.py` | Source-line-linked error graphs and audit-only supervision annotations. |
| `IL/dataset_1-ATLASv2/code/DL/audit/occlude_provenance_context.py` | Fixed-weight event deletion and context-group occlusion diagnostics; not a model-selection tool. |
| `IL/dataset_1-ATLASv2/code/DL/audit/summarize_provenance_experiments.py` | Paired six-run tables, prediction changes and scientific comparison figure. |
| `IL/dataset_1-ATLASv2/analyst/dl_provenance_context_20261111.md` | Graph traceback cases, adaptation from ML/paper code, paired DL experiments and leakage boundaries. |
| `IL/dataset_1-ATLASv2/analyst/dl_process_graph_20261111.md` | Ten learned process/graph trials, explicit unknown supervision, process attribution, failed auxiliary correction and validation-selected research candidate; artifact identities under `DL/output/process_graph_20261111/`. |
| `IL/dataset_1-ATLASv2/code/DL/model/dataset.py` | Shard readers, replay buffer, batching. |
| `IL/dataset_1-ATLASv2/code/DL/model/train_local.py` | Local incremental training and validation-only threshold selection. |
| `IL/dataset_1-ATLASv2/code/DL/model/decision_policy.py` | Shared, testable metrics and FPR-constrained threshold policy. |
| `IL/dataset_1-ATLASv2/code/DL/audit/` | Reproducible post-run and raw-data diagnostics; outputs under `DL/output/research_20261111/`. |
| `IL/dataset_1-ATLASv2/code/DL/audit/train_feature_probe.py` | Three-seed target-domain MLP control over encoded event histograms; tests whether recurrence adds value. |
| `IL/dataset_1-ATLASv2/code/DL/preprocess/extract_optc_network_replay.py` | Historical synthetic fixture generator; does not extract real OpTC tensors. No longer a default trainer input. |
| `IL/dataset_1-ATLASv2/code/DL/test/` | Focused regression tests for the research fixes. |
| `IL/dataset_1-ATLASv2/code/DL/notebook/` | Kaggle notebooks; historical embedded code is not automatically synchronized with local changes. |
| `IL/dataset_1-ATLASv2/analyst/dl_root_cause_20261111.md` | Evidence, experiments, literature, limitations and next experiments. |
| `DATASET/ATLASv2_staged/add_stage_column.py` | Historical process-name/host heuristic stage annotator; stages are weak supervision, not independently verified event-stage truth. |
| `DATASET/ATLASv2_staged/RESEARCH_POLICY_20261111.md` | Label status, sensitivity-policy scope and requirements for a verified replacement. |

Existing run directories and source datasets are preserved. Research experiments use
new output directories and never overwrite earlier checkpoints.
