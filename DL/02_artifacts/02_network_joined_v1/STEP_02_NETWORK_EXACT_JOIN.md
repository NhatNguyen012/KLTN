# STEP 04B — Exact join Network (Bro conn + eCAR-Bro)

## Trạng thái

**COMPLETED — READY FOR REVIEW**

## Mục tiêu

Tạo exact joined Network event table một lần để làm nguồn dữ liệu chuẩn cho Network DL.

## Join là gì trong STEP này?

`join` là ghép hai record từ hai nguồn khác nhau khi chúng cùng mô tả một network connection.

Khóa join:

```text
eCAR-Bro.properties.bro_uid == Bro conn.uid
```

Bro cung cấp network statistics + target label; eCAR-Bro bổ sung hostname/application context.

## Leakage boundary

- Frozen STEP 02 hostname split được SHA-256 verify.
- Không random split event.
- Hostname không có trong frozen split được gán `unmatched_split`.
- STEP 04B chưa fit category map/scaler.
- `label` là target-only và không được dùng làm predictive feature.

## Input

- Frozen manifest: `D:\UIT\KLTN\artifacts\step02_label_split_v1_1\split_manifest_frozen.csv`
- Manifest SHA-256: `dbc8467ea27ab8a47515ae816e5758d558a5994a2b74c5929b7a640bc4abcafe`
- STEP 04A report: `D:\UIT\KLTN\artifacts\step04_network_profile_fast_v2\network_join_profile_fast_v2.json`
- STEP 04A checkpoint DB: `D:\UIT\KLTN\artifacts\step04_network_profile_fast_v2\network_profile_fast_v2.sqlite3`

## Canonical Network event

Chỉ dùng Bro `conn.*.log.gz` làm base connection table để tránh một UID bị nhân lên khi xuất hiện ở `ssl/http/dns/...`.

## Output

- Joined dataset: `D:\UIT\KLTN\artifacts\step04_network_joined_v1\joined`
- Parquet được partition theo `split/date`.
- `unmatched_split` được giữ riêng để audit, không dùng baseline supervised training.

## Kết quả exact join

- eCAR raw rows: **92,097,521**
- Unique eCAR `bro_uid`: **92,071,089**
- Duplicate UID: **26,347**
- Hostname-conflict UID: **0**
- Unmatched-split UID: **6,419,570**
- Joined unique UID rows: **92,045,755**
- Exact join rate: **99.972%**
- Missing-label joined rows: **0**
- Rows by split: `{"test": 10710192, "train": 61751292, "unmatched_split": 6419570, "val": 13164701}`
- Labels by split: `{"test": {"0": 10706992, "1": 3200}, "train": {"0": 61733236, "1": 18056}, "unmatched_split": {"0": 6419570}, "val": {"0": 13161236, "1": 3465}}`

## Feature contract

Predictive candidates:

```text
categorical: app_family, direction, proto, service, conn_state, local_orig, local_resp
numerical: duration, orig_bytes, resp_bytes, missed_bytes,
           orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes
```

Join/audit only:

```text
uid, hostname, ts, date, split
```

Graph construction only ban đầu:

```text
orig_h, orig_p, resp_h, resp_p
```

## Note

Exact joined Network event table đã được materialize. Chưa fit category map/scaler; chờ review STEP 04B trước STEP 04C.

## Next step

STEP 04C — derive semantic network categories và fit category maps/numeric scaler trên TRAIN only.
