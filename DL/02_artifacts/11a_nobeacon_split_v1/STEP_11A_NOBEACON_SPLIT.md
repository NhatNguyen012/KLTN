# STEP 11A — Mapping split cho dataset no-beacon (seed_1)

## Trạng thái

**PASS** (script `01_code/pipeline/11a_make_nobeacon_split.py`)

## Định nghĩa beacon

Beacon PowerShell của Scenario 2 chạy qua đêm 24→25/09 tới C2 `202.6.172.98:443` (STEP 09 §8.4). Loại ở **mức event**: mọi event có `resp_h` = `202.6.172.98`. IP này chỉ xuất hiện trong event positive (không có event benign nào), nên không có nhiễu nhãn khi loại.

## Giữ nguyên split

Host → split giữ nguyên STEP 10A seed_1 (gate `same_assigned_split_as_10a`). Chỉ thay đổi số event/positive event của các host có beacon.

## Số liệu

- Event: 85,626,185 → 85,612,773 (loại 13,412).
- Positive event: 24,721 → 11,309 (loại 13,412 = 54.3%).

| split | host | event | positive event |
|---|---:|---:|---:|
| train | 434 | 62,057,568 | 8,721 |
| val | 93 | 12,337,336 | 1,526 |
| test | 93 | 11,217,869 | 1,062 |

Positive event còn lại theo scenario × split:

| scenario | train | val | test |
|---|---:|---:|---:|
| scenario_1 | 6,740 | 1,391 | 899 |
| scenario_2 | 1,955 | 135 | 0 |
| scenario_3 | 26 | 0 | 163 |

Event bị loại theo host:

| host | scenario | split | event bị loại |
|---|---|---|---:|
| `sysclient0010` | scenario_2 | train | 2,104 |
| `sysclient0069` | scenario_2 | train | 2,105 |
| `sysclient0203` | scenario_2 | train | 2,102 |
| `sysclient0358` | scenario_2 | train | 2,101 |
| `sysclient0501` | scenario_2 | val | 809 |
| `sysclient0618` | scenario_2 | test | 2,097 |
| `sysclient0851` | scenario_2 | train | 2,094 |

Gate: ✅ same_hosts_as_10a, ✅ same_assigned_split_as_10a, ✅ event_conservation, ✅ positive_conservation, ✅ removed_events_all_positive, ✅ removed_only_on_gt_positive_hosts, ✅ each_split_has_positive

## Lưu ý

- Mapping vẫn đánh dấu các host beacon là `gt_positive_host_group=True` (theo ground truth); một số host có thể còn rất ít hoặc không còn positive event.
- Số positive window còn lại ở TEST/VAL rất nhỏ (xem STEP 11D); kết quả train trên dataset này chỉ có ý nghĩa thăm dò.
- sha256 `host_split_frozen.csv`: `c3fd7c4f320b464dd07a92e738cd8ff489c8950e40e5e40b3a675212a6115f97`; contract sha256: `32105d531c313596adbe67aea6c2351a85a2a39273663bece1bfc975cbb1050f`.
