# STEP 05A — Kaggle Dataset validation + DataLoader contract

## Trạng thái

**PASS — READY TO UPLOAD/TRAIN**

## Mục tiêu

Validate dataset sinh bởi STEP 04D trước khi upload/train trên Kaggle.

## Checks

- Integrity files: **PASS**
- Frozen preprocessing: **PASS**
- Manifest/split leakage: **PASS**
- Manifest vs dataset_manifest: **PASS**
- NPZ shard structure/content: **PASS**

## Split summary

### TRAIN

- Samples: **164,605**
- Positive: **399**
- Events: **61,751,292**

### VAL

- Samples: **35,134**
- Positive: **84**
- Events: **13,164,701**

### TEST

- Samples: **29,245**
- Positive: **83**
- Events: **10,710,192**

## Training imbalance

- TRAIN sample-level `pos_weight`: **411.5438596491228**

Baseline recommendation:

```text
BCEWithLogitsLoss(pos_weight=TRAIN_NEG/TRAIN_POS)
```

Không kết hợp `pos_weight` lớn với aggressive oversampling trong baseline đầu tiên.

## DataLoader contract

Sequence batch:

```text
x_cat          [B,T,C]
x_num          [B,T,N]
x_num_missing  [B,T,N]
x_bin          [B,T,1]
delta_t_log1p  [B,T,1]
attention_mask [B,T]
labels         [B]
```

Padding chỉ thực hiện trong batch.

Graph transport format:

```text
APP nodes + REMOTE_ENDPOINT nodes
edge_index từ app_local_id -> remote_local_id
reverse edges có thể thêm khi train GNN
```

## Leakage

- Distinct hostnames: **620**
- Hostnames xuất hiện ở nhiều split: **0**
- Duplicate sample IDs: **0**

## Next step

Upload private Kaggle Dataset và chạy DataLoader smoke test trên Kaggle, sau đó train BiLSTM baseline.
