# STEP 04A FAST V2 — Profile dữ liệu Network (Bro + eCAR-Bro)

## Trạng thái

**READY_FOR_REVIEW**

## Mục tiêu

Quét toàn bộ Bro và eCAR-Bro để hiểu schema, label, hostname và khả năng join trước khi tạo Network DL dataset.

STEP 04A chỉ là profiling gate. Exact full join được thực hiện ở STEP 04B để tránh làm công việc nặng hai lần.

## Vì sao dùng FAST V2

- V1 lưu mọi `bro_uid`/`uid` vào SQLite nên DB tăng rất nhanh.
- FAST V2 vẫn đọc **toàn bộ raw files**, nhưng chỉ lưu deterministic sample của UID.
- Sampling rule: `blake2b64(uid) % 1000 == 0` (~0.100%).
- Exact all-record join được để sang STEP 04B, khi joined event table được materialize và dùng trực tiếp cho DL.

## Leakage boundary

- Frozen STEP 02 manifest được verify bằng SHA-256.
- Không random split event.
- STEP 04A chưa fit category map, scaler hay model.
- TRAIN-only preprocessing statistics sẽ fit ở STEP 04C.

## Full scan

- eCAR-Bro files: **156/156**
- eCAR-Bro records: **92,097,521**; parse errors: **0**
- Bro files: **3,954/3,954**
- Bro records: **1,012,131,447**; parse errors: **24,243**

## Deterministic sampled UID join

- Sampled unique eCAR-Bro UID: **91,903**
- Sampled UID seen in Bro: **91,880**
- Estimated match rate: **99.975%**
- Sampled hostname coverage: **100.000%**
- Sampled frozen-split coverage: **93.014%**
- Sampled split counts: `{"test": 10647, "train": 61677, "val": 13159}`
- Sampled labels by split: `{"test": {"missing": 10647}, "train": {"missing": 61677}, "val": {"missing": 13159}}`

## Conflict diagnostics trên UID sample

- Duplicate sampled UID trong eCAR-Bro: **26**
- Hostname conflict: **0**
- eCAR label conflict: **0**
- Bro label conflict: **0**

## Runtime artifact

- Compact checkpoint DB: `D:\UIT\KLTN\artifacts\step04_network_profile_fast_v2\network_profile_fast_v2.sqlite3`
- `network_join_profile_fast_v2.json` chứa report machine-readable.

## Decision gate

Review match rate, split coverage, label distribution, actual fields và conflict diagnostics trước STEP 04B.

## Next step

STEP 04B — build exact joined Network event table một lần và freeze Network feature contract.
