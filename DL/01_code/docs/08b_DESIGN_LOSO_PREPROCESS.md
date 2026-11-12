# STEP 05F-C — Design notes

## Vì sao phải fit lại preprocessing?

Current Network preprocessing được fit trên current TRAIN.

LOSO thay đổi TRAIN membership.

Một scenario bị hold out có thể từng đóng góp:

```text
category frequencies
category vocabulary
numerical mean/std
active/inactive feature decisions
```

cho preprocessing cũ.

Dùng preprocessing cũ sẽ làm unseen-scenario experiment không sạch.

## Vì sao không scan 3 folds riêng?

Naive:

```text
3 folds
x categorical scan
x numerical scan
= 6 full scans
```

Optimized:

```text
2 full scans total
-> exact per-host sufficient statistics
-> aggregate per fold
```

Categorical counts cộng được chính xác theo host.

Numerical `log1p mean/std` được tái tạo chính xác từ:

```text
count
sum
sum of squares
```

của từng host.

## Leakage boundary

Per-host profile được phép tạo từ toàn dataset vì nó chỉ chứa sufficient statistics theo host.

Quan trọng là khi tạo một fold's learned preprocessing:

```text
only host profiles whose loso_split == TRAIN
```

được dùng để xây:

```text
category map
numeric mean/std
active feature decision
```

VAL/TEST profiles chỉ được dùng sau đó để audit OOV/missing.

## Không materialize split copies

Không copy 85.6M rows thành 3 joined datasets.

Frozen mapping là source-of-truth:

```text
hostname -> LOSO split
```

STEP 05F-D sẽ apply mapping trực tiếp khi build shards.
