# KLTN Network Deep Learning Context For AI Agent

## 1. Project Overview

Thesis: **A Multi-Source Context-Aware Framework for Advanced Persistent
Threat Detection**

Vietnamese title: **Khung phát hiện mối đe dọa dai dẳng nâng cao (APT)
dựa trên dữ liệu đa nguồn và nhận biết ngữ cảnh**

Students: - Nguyễn Nhật Nguyễn - Võ Ngọc Hoàng Lâm

The project builds a Deep Learning framework for Advanced Persistent
Threat (APT) detection using: - Host telemetry from eCAR/provenance
data. - Network telemetry from Bro/Zeek data.

The main idea is context-aware fusion instead of using only one data
source.

------------------------------------------------------------------------

## 2. Dataset

Dataset: DARPA OpTC.

Raw data location:

    E:/
    ├── bro/
    │   └── 2019-09-25/
    │       ├── conn*.log.gz
    │       ├── http*.log.gz
    │       └── other Zeek logs
    └── eCAR host telemetry

The pipeline:

    eCAR (host events)
            +
    Bro/Zeek (network events)
            |
            v
    Joined network dataset
            |
            v
    Preprocessing
            |
            v
    Deep Learning model

------------------------------------------------------------------------

## 3. Work done by Võ Ngọc Hoàng Lâm

Main responsibility: **Network Deep Learning Agent**

### Dataset processing

Completed: - Analyze Bro/Zeek logs. - Build network feature contract. -
Join network telemetry. - Generate reproducible preprocessing pipeline.

Important folders:

    artifacts/
    step04_network_joined_v1/
    step04_network_preprocess_v1_1/

Outputs: - joined parquet dataset - preprocessing specification -
feature mapping - normalization statistics

------------------------------------------------------------------------

## 4. Feature Processing

### Categorical features

Examples:

-   app_family
-   proto
-   service
-   conn_state
-   resp_port_class

Processing:

    string category
          |
          v
    integer ID
          |
          v
    embedding vector

Special values: - UNK - MISSING

### Numerical features

Examples: - duration - bytes - packets

Processing:

    raw value
     |
     log1p
     |
     z-score normalization
     |
     model input

Statistics are calculated only from TRAIN.

### Temporal/Binary features

Examples: - delta_t_log1p - has_missed_bytes

Purpose: Keep event order and missing traffic information.

------------------------------------------------------------------------

## 5. Deep Learning Models

### BiLSTM Baseline

Input:

Processed network event sequence.

Flow:

    Feature sequence
            |
    Embedding
            |
    BiLSTM
            |
    Classifier
            |
    Benign/Malicious

### Mixed-Type Self-Attention

Purpose: Learn interaction between different feature types.

Instead of simple concatenation:

    Categorical + Numerical + Temporal

The model learns which feature group is important depending on context.

Example:

A connection may be normal alone.

But:

    rare destination
    +
    unusual traffic
    +
    abnormal process behavior

can indicate an attack.

------------------------------------------------------------------------

## 6. Previous Experiments

### Host split result

Initial DL experiment achieved extremely high metrics.

Problem:

Metrics close to 1.0 indicate possible data leakage.

Need to check: - split strategy - preprocessing - normalization -
duplicated samples - feature mapping

------------------------------------------------------------------------

## 7. LOSO Experiment

LOSO: Leave One Scenario Out.

Purpose: Test generalization to unseen attack scenarios.

Previous approach: Train on some scenarios and test on another scenario.

Supervisor feedback: This split is not appropriate because unseen attack
campaigns are too different.

Next: Randomize scenarios and retrain.

------------------------------------------------------------------------

## 8. Supervisor Feedback

1.  Host split DL results likely contain leakage.

Action: Audit pipeline before retraining.

2.  Scenario split is incorrect.

Action: Use random scenario split.

3.  Binary labels are limited.

Current:

    0 = benign
    1 = malicious

Possible future: Consider multilabel dataset.

Order: Fix leakage -\> retrain -\> evaluate -\> consider new dataset.

------------------------------------------------------------------------

## 9. Teammate Work - Nguyễn Nhật Nguyễn

Main responsibility: ML baseline branch.

Completed: - Dataset analysis. - Traditional ML experiments. - Models: -
LightGBM - XGBoost - Random Forest

Also analyzed: - label quality - provenance relationship - ML baseline
performance.

------------------------------------------------------------------------

## 10. Current TODO

### Task 1 (24-25/09)

Retrain Deep Learning after leakage audit.

Outputs: - new metrics - confusion matrix - PR curve - ROC curve

### Task 2 (24-25/09)

Scenario validation.

Objectives: - Verify split strategy. - Compare old/new results. -
Analyze failure cases.

------------------------------------------------------------------------

# AI Agent Reading Guide

Read in this order:

## 1. Research description

    DeCuongChiTiet_NguyenNhatNguyen_VoNgocHoangLam.docx

## 2. Dataset joining

    artifacts/step04_network_joined_v1/

    Read:
    - network_feature_contract.json
    - network_join_exact_report.json
    - STEP_04B_NETWORK_EXACT_JOIN.md

## 3. Preprocessing

    artifacts/step04_network_preprocess_v1_1/

    Read:
    - network_preprocess_spec.json
    - network_category_maps.json
    - network_numeric_stats.json

## 4. LOSO

    artifacts/step05f_loso_preprocess_v1/
    artifacts/step05f_d_loso_validation/

## 5. Model

    bilstm_baseline_v1/

    Read:
    - metrics.json
    - history.csv
    - test_predictions.csv

## 6. Training notebooks

    kaggle/
    - 05B_BiLSTM_Kaggle.ipynb
    - 05E_Mixed_Type_Self_Attention_Kaggle.ipynb

------------------------------------------------------------------------

## Current Research Question

Are previous perfect DL metrics caused by real learning ability or
hidden data leakage?

Do not redesign the model before completing leakage audit.
