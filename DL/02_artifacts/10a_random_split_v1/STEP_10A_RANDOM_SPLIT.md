# STEP 10A — 3 split ngẫu nhiên host-disjoint, stratify theo scenario

## Trạng thái

- Script: `step10a-random-scenario-split-v1.0` (`01_code/pipeline/10a_random_scenario_split.py`)
- Sinh lúc: `2026-10-01T03:18:26`
- Trạng thái: **PASS** (mọi gate của cả 3 seed)

## Thiết kế

- Đơn vị: hostname; tỉ lệ 70/15/15; universe = 620 host có dòng mạng trong joined data (nguồn: artifact remap STEP 08A, thư mục `frozen`; chỉ dùng cột host/scenario).
- Policy host positive **import nguyên** từ `00_ground_truth_and_split.py` (`build_split_assignment`): scenario ≥3 host có mặt ở train/val/test; scenario 2 host → train + test; host benign chia ngẫu nhiên để đạt quota 70/15/15.
- Seed: chuỗi `KLTN_OPTC_RANDOM_SCENARIO_SPLIT_V1|seed=k`, k = 1, 2, 3; xếp thứ tự bằng sha256 như 00 (tái lập được, không phụ thuộc numpy/OS).
- Kiểm chứng import policy: với seed gốc `KLTN_OPTC_SPLIT_V1_1`, 29 host positive tái tạo đúng split gốc: **True**.
- `heldout_scenario = NONE` (không có scenario giữ riêng); cột split của mapping tên `assigned_split` (08b/08c/08d ở mode random đọc cột này).

## Kết quả từng seed

### seed_1  (`KLTN_OPTC_RANDOM_SCENARIO_SPLIT_V1|seed=1`)

- Status: **PASS**; contract sha256: `0183e79847708b25e3429ffdeab4f490e7855ba7358fdfbfadaf90911e4655c8`
- `host_split_frozen.csv` sha256: `98165cec18bdd5ef6276394f2fc8c2a15793b693278d0b70b7f74f57f11dc161`

| split | host | host positive (GT) | host có positive event | event | positive event |
|---|---:|---:|---:|---:|---:|
| train | 434 | 20 | 20 | 62,068,074 | 19,227 |
| val | 93 | 5 | 4 | 12,338,145 | 2,335 |
| test | 93 | 4 | 4 | 11,219,966 | 3,159 |

Scenario × split (host positive / positive event):

| scenario | train | val | test |
|---|---|---|---|
| scenario_1 | 12 host / 6,740 ev | 3 host / 1,391 ev | 2 host / 899 ev |
| scenario_2 | 7 host / 12,461 ev | 2 host / 944 ev | 1 host / 2,097 ev |
| scenario_3 | 1 host / 26 ev | 0 host / 0 ev | 1 host / 163 ev |

Host positive của TEST: `sysclient0104` (scenario_1, 450 ev), `sysclient0255` (scenario_1, 449 ev), `sysclient0618` (scenario_2, 2,097 ev), `sysclient0051` (scenario_3, 163 ev)

Gate: ✅ hostname_unique, ✅ split_values_valid, ✅ covers_all_source_hosts, ✅ host_overlap_train_val_zero, ✅ host_overlap_train_test_zero, ✅ host_overlap_val_test_zero, ✅ event_conservation, ✅ positive_event_conservation, ✅ scenario_coverage_policy, ✅ train_has_positive_events, ✅ val_has_positive_events, ✅ test_has_positive_events, ✅ heldout_scenario_not_used

### seed_2  (`KLTN_OPTC_RANDOM_SCENARIO_SPLIT_V1|seed=2`)

- Status: **PASS**; contract sha256: `34c94fd86cd76fe7ef7875f70c75b6141e34df37e029256072b51e39fbfa624e`
- `host_split_frozen.csv` sha256: `5600ab2a4c5656fa8f8ec866a961b3d547fd9ce604928246fe4aa35fd6eab6be`

| split | host | host positive (GT) | host có positive event | event | positive event |
|---|---:|---:|---:|---:|---:|
| train | 434 | 20 | 19 | 61,122,797 | 14,649 |
| val | 93 | 5 | 5 | 11,010,382 | 6,991 |
| test | 93 | 4 | 4 | 13,493,006 | 3,081 |

Scenario × split (host positive / positive event):

| scenario | train | val | test |
|---|---|---|---|
| scenario_1 | 12 host / 5,429 ev | 3 host / 2,785 ev | 2 host / 816 ev |
| scenario_2 | 7 host / 9,194 ev | 2 host / 4,206 ev | 1 host / 2,102 ev |
| scenario_3 | 1 host / 26 ev | 0 host / 0 ev | 1 host / 163 ev |

Host positive của TEST: `sysclient0355` (scenario_1, 449 ev), `sysclient0660` (scenario_1, 367 ev), `sysclient0203` (scenario_2, 2,102 ev), `sysclient0051` (scenario_3, 163 ev)

Gate: ✅ hostname_unique, ✅ split_values_valid, ✅ covers_all_source_hosts, ✅ host_overlap_train_val_zero, ✅ host_overlap_train_test_zero, ✅ host_overlap_val_test_zero, ✅ event_conservation, ✅ positive_event_conservation, ✅ scenario_coverage_policy, ✅ train_has_positive_events, ✅ val_has_positive_events, ✅ test_has_positive_events, ✅ heldout_scenario_not_used

### seed_3  (`KLTN_OPTC_RANDOM_SCENARIO_SPLIT_V1|seed=3`)

- Status: **PASS**; contract sha256: `d447bc2ebae995b513b58fbac0208285fa96f5b4c97bb3d156fbc47174b12eee`
- `host_split_frozen.csv` sha256: `8b820f5cb172678e80a1072e179fbb8cb757429dc80f57a52f6336d12de9c5d0`

| split | host | host positive (GT) | host có positive event | event | positive event |
|---|---:|---:|---:|---:|---:|
| train | 434 | 20 | 19 | 60,461,805 | 18,052 |
| val | 93 | 5 | 5 | 12,081,151 | 3,502 |
| test | 93 | 4 | 4 | 13,083,229 | 3,167 |

Scenario × split (host positive / positive event):

| scenario | train | val | test |
|---|---|---|---|
| scenario_1 | 12 host / 6,740 ev | 3 host / 1,391 ev | 2 host / 899 ev |
| scenario_2 | 7 host / 11,286 ev | 2 host / 2,111 ev | 1 host / 2,105 ev |
| scenario_3 | 1 host / 26 ev | 0 host / 0 ev | 1 host / 163 ev |

Host positive của TEST: `sysclient0104` (scenario_1, 450 ev), `sysclient0503` (scenario_1, 449 ev), `sysclient0069` (scenario_2, 2,105 ev), `sysclient0051` (scenario_3, 163 ev)

Gate: ✅ hostname_unique, ✅ split_values_valid, ✅ covers_all_source_hosts, ✅ host_overlap_train_val_zero, ✅ host_overlap_train_test_zero, ✅ host_overlap_val_test_zero, ✅ event_conservation, ✅ positive_event_conservation, ✅ scenario_coverage_policy, ✅ train_has_positive_events, ✅ val_has_positive_events, ✅ test_has_positive_events, ✅ heldout_scenario_not_used

## 3 split có thực sự khác nhau không?

Nếu hai split độc lập hoàn toàn ngẫu nhiên, số host TEST chung kỳ vọng ≈ 13.9.

| A | B | chung train | chung val | chung test | chung test positive | chung test benign | Jaccard test | TEST positive giống hệt |
|---|---|---:|---:|---:|---:|---:|---:|---|
| seed_1 | seed_2 | 299 | 12 | 16 | 1 | 15 | 0.0941 | False |
| seed_1 | seed_3 | 306 | 11 | 17 | 2 | 15 | 0.1006 | False |
| seed_1 | original | 301 | 13 | 14 | 1 | 13 | 0.0809 | False |
| seed_2 | seed_3 | 303 | 12 | 17 | 1 | 16 | 0.1006 | False |
| seed_2 | original | 303 | 11 | 14 | 1 | 13 | 0.0809 | False |
| seed_3 | original | 303 | 17 | 8 | 2 | 6 | 0.0447 | False |

- Các seed khác nhau ở tập TEST: **True**.

TEST positive host mỗi seed:

- seed_1: sysclient0051, sysclient0104, sysclient0255, sysclient0618
- seed_2: sysclient0051, sysclient0203, sysclient0355, sysclient0660
- seed_3: sysclient0051, sysclient0069, sysclient0104, sysclient0503
- original: sysclient0051, sysclient0402, sysclient0503, sysclient0851

## Lưu ý khi đọc kết quả

- Policy cho SC2 (10 host) và SC3 (2 host) chỉ 1 host vào TEST ⇒ số positive window TEST dao động mạnh giữa các seed (ví dụ SC3: 163 vs 26 positive event tuỳ host nào vào TEST). Đây là đặc tính của policy, không phải lỗi; không so sánh tuyệt đối metric giữa các seed mà không báo cáo host TEST.
- `sysclient0974` là host GT-positive nhưng có 0 positive event mạng; vẫn được stratify như host positive, nên `host positive (GT)` có thể lớn hơn `host có positive event` ở một split.
- Positive window theo scenario × split sẽ có ở STEP 10D sau khi build shards.
- Không có bước chọn lại seed sau khi xem kết quả: nếu gate fail, script dừng.

## File

- `02_artifacts/10a_random_split_v1/seed_{k}/host_split_frozen.csv`, `fold_contract.json`, `split_report.json`
- `02_artifacts/10a_random_split_v1/split_overlap_report.json`

## Ghi chú bổ sung (sau khi sinh)

- **Scenario 3 luôn đưa `sysclient0051` vào TEST ở cả 3 seed** (và split gốc). Đây là trùng hợp của hàm băm: với seed 4–10 kết quả lẫn lộn (seed 4, 5, 8, 9 chọn `sysclient0351`). Không chọn lại seed. Hệ quả: host SC3 "thật sự mới" (163 positive event) luôn ở TEST, host SC3 còn lại (26 event) luôn ở TRAIN, nên 3 seed không cho biết dao động do chọn host SC3.
- Ngoài các file theo từng seed, có thêm `random_split_contract.json` (contract gộp, folds `seed_1..3`, có sha256) cho 08b/08c; script tự sinh sau khi tạo các seed (`--combine-only` nếu muốn chạy riêng).
- Cột split của mapping tên `assigned_split`; các khóa nguồn trong `fold_contract.json` tên `remap_contract_sha256`, `remap_contract_file_sha256` (không dùng tên "loso").
- Artifact này được sinh lại sau khi đổi tên cột/khóa; split (host nào vào split nào) giống hệt lần sinh đầu vì hàm băm và seed không đổi.
