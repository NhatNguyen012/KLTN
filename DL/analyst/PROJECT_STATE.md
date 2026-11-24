# KLTN — PROJECT STATE / HANDOFF (Updated 2026-11-22)

## Current Architecture

**A multi-source context-aware framework for advanced persistent threat (APT) detection** on DARPA OpTC:

1. **Host ML Agent (LightGBM baseline & context-aware)**:
   - Structure-aware semantic tokenization (AST launchers, switches, operands, principals, path roles).
   - Past-only causal process context tracking (`process_context_tracker.py`).
   - Achieves F1 **99.63%** on Host event evaluation.

2. **Host Deep Learning Agent (Causal Triplet BiLSTM Multi-Task)**:
   - **Sequence Formulation:** Fixed length $L = 3$ Causal Provenance Sequence:
     $$S = [E_{\text{incoming}}, E_{\text{parent}}, E_{\text{current}}]$$
     Replaces the noisy, interleaved 15-minute / 3-minute flat window.
   - **Feature Integration:** Ingests the 10,000+ structure-aware tokens from Host ML via `CausalStepEmbedding` (`nn.EmbeddingBag`).
   - **Multi-Task Prediction Heads:**
     1. Binary Head: `is_malicious`
     2. Scenario Attribution Head: `SC1_EmpireStaging`, `SC2_CustomEmpireLateral`, `SC3_MaliciousUpdate`
     3. MITRE ATT&CK Stage Head: 10 Tactics (Execution, Defense Evasion / T1055 Injection, AMSI, Discovery, Credential Access, Lateral Movement, Persistence, C2, Exfiltration)
   - **Attention Pooling:** Automatically learns attention weights across Incoming, Parent, and Current event steps.

3. **Labeling System (Decoupled Sidecar Indexing)**:
   - Located at `DATASET/Preprocess/`.
   - Generates compact sidecar catalog `optc_multitask_labels_v1.json.gz` (7.68 MB) covering all 360,567 malicious events.
   - Raw dataset remains 100% immutable (read-only).
   - In-memory $O(1)$ dynamic lookup (59ns latency, 16.8M events/sec).

## Completed Work & Verification

- `DATASET/Preprocess/generate_multitask_labels.py`: Passed tests, generated v1 catalog.
- `DATASET/Preprocess/label_catalog.py`: Verified $O(1)$ in-memory lookups.
- `DATASET/Preprocess/test_multitask_labeling.py`: 3/3 tests passed.
- `DL/01_code/causal_bilstm/causal_dataset.py`: Verified batch collation with offsets.
- `DL/01_code/causal_bilstm/model_causal_bilstm.py`: Verified BiLSTM + Attention + 3 heads.
- `DL/01_code/causal_bilstm/trainer.py`: Verified multi-task loss and metric tracking.
- `DL/01_code/causal_bilstm/test_causal_bilstm.py`: 2/2 integration tests passed on GPU CUDA.
- `DL/00_docs/CAUSAL_BILSTM_ARCHITECTURE.md`: Full theoretical & operational guide.
- `DL/04_notebooks/15_BiLSTM_Causal_MultiTask_Kaggle_T4x2.ipynb`: Kaggle Jupyter Notebook with Dual T4 (T4x2) DDP execution.
- `DL/03_datasets/kaggle_causal_bilstm_t4x2_upload.zip`: Self-contained 44.85 MB dataset package ready for Kaggle upload.
