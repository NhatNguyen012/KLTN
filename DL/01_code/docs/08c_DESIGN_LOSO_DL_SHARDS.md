# STEP 05F-D — Design / anti-leakage notes

## Source-of-truth split

LOSO assignment không lấy từ STEP 04B physical folder:

```text
split=train/val/test
```

vì đó là original hostname split.

LOSO source-of-truth:

```text
STEP 05F-B frozen host_split_holdout_scenario_X.csv
```

Mỗi query đọc tất cả original supervised Parquet và remap bằng hostname.

## Preprocessing

Mỗi fold dùng đúng frozen STEP 05F-C artifacts của chính fold đó.

Không reuse preprocessing của fold khác.

## Time grouping

Giữ fix từ STEP 04D v1.1:

```text
UTC logical day derived from event timestamp
```

Source path date không được xem là sample boundary.

Trong mỗi day:

```text
hostname
+ 15-minute window_start
+ chunk_index(MAX_EVENTS=512)
```

là sample identity.

## Label

```text
sample label = 1
iff sample contains >=1 positive event
```

## Fair comparison

LOSO BiLSTM và Mixed-Type sẽ dùng cùng generated fold datasets.

Chỉ architecture thay đổi.

## Graph transport

Shard vẫn giữ:

```text
edge_app_local
edge_remote_local
```

nên sau này cùng fold có thể dùng cho GraphSAGE/GAT nếu cần.

Raw remote IP không được export vào model tensors.
