#!/usr/bin/env python3
"""Sinh STEP_S2..S5 (*.md, tiếng Việt) từ checks.json/spec thật của pipeline v2. Chạy sau khi S5 PASS."""
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")
V = "D:/UIT/KLTNv2/02_artifacts/22_v2_pipeline/"


def J(p):
    return json.load(open(V + p, encoding="utf-8"))


sp = J("S3_preprocess/data/preprocess_spec.json")
c4, c5, sm, ck2 = J("S4_shards/checks.json"), J("S5_validate/checks.json"), J("S2_windows_split/split_summary.json"), J("S2_windows_split/checks.json")
pos, tot = sm["positive_windows_by_scenario_and_split"], sm["totals_by_split"]
st = c4["stats"]

s2 = f"""# S2 — Cửa sổ và split (cấp cửa sổ, phân tầng theo scenario)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s2_windows_split.py` (4 giây).

## Mục đích
Gom flow thành cửa sổ (hostname, 15 phút) và chia 70/15/15 để **mọi scenario tấn công có mặt đủ ở TRAIN, VAL, TEST**. Đây là đầu vào của S3 (chọn cửa sổ TRAIN để fit) và S4 (gán split cho sample).

## Input
`S1_join/data/flows_joined.parquet`; `02_artifacts/11_dataset_overview_v1/hosts_625.csv` (620 máy có cả log host và log mạng, và scenario của 29 máy bị tấn công).

## Cách làm
- 620 máy, cửa sổ = `floor(ts/900)*900` (UTC); `n_chunks = ceil(n_flows/512)`; nhãn cửa sổ = có ≥ 1 flow dương.
- Tầng: tên scenario (cửa sổ dương) hoặc `benign_<ngày UTC>` (cửa sổ benign); mỗi tầng cắt 70/15/15 theo thứ tự băm sha256 của `KLTN_OPTC_WINDOW_STRATIFIED_V1|seed=1|hostname|window_start_epoch` (tái lập được).
- **Không host-disjoint** (yêu cầu của người dùng 2026-10-12, ngoại lệ so với quy tắc trong `CLAUDE.md`): 613/620 máy có cửa sổ ở cả ba split. Mọi chunk của một cửa sổ nằm cùng một split.

## Output (`data/windows.csv`, {ck2['windows']:,} dòng)
Trường: `hostname, window_start_epoch, window_start_utc, date_utc, scenario, n_flows, n_chunks, n_positive_flows, label, stratum, split` (mô tả trong `schema.json`; xem nhanh `preview.csv`, `preview_record.json`). Thống kê trong `split_summary.json`.

## Kết quả
| Cửa sổ dương theo scenario | train | val | test |
|---|---:|---:|---:|
| SC1 | {pos['scenario_1']['train']} | {pos['scenario_1']['val']} | {pos['scenario_1']['test']} |
| SC2 | {pos['scenario_2']['train']} | {pos['scenario_2']['val']} | {pos['scenario_2']['test']} |
| SC3 | {pos['scenario_3']['train']} | {pos['scenario_3']['val']} | {pos['scenario_3']['test']} |

| Split | Cửa sổ | Cửa sổ dương | Flow | Flow dương | Sample (chunk) |
|---|---:|---:|---:|---:|---:|
""" + "\n".join(f"| {s} | {tot[s]['windows']:,} | {tot[s]['positive_windows']} | {tot[s]['flows']:,} | {tot[s]['positive_flows']:,} | {tot[s]['samples']:,} |" for s in ("train", "val", "test")) + f"""

Kiểm tra (`checks.json`, PASS): đúng 620 máy; bảo toàn {ck2['flows_in_windows']:,} flow; mỗi scenario có mặt ở cả 3 split; tỉ lệ cửa sổ 0.70 / 0.15 / 0.15. **Đối chiếu với STEP 21A** (cùng thuật toán, cửa sổ lấy từ bảng cũ): cùng tập 110,402 cửa sổ và gán split giống hệt từng cửa sổ.

## Hạn chế
SC3 chỉ có 6 cửa sổ dương (4/1/1) nên số liệu riêng cho SC3 không có ý nghĩa thống kê. Cửa sổ TEST có "bản sao" cùng máy ở TRAIN (80/81 cửa sổ dương TEST có cửa sổ dương cùng máy ở TRAIN, theo STEP 21A), nên điểm đo khả năng nhận ra mẫu và máy đã thấy, không đo phát hiện trên máy chưa từng thấy.
"""
open(V + "S2_windows_split/STEP_S2_WINDOWS_SPLIT.md", "w", encoding="utf-8", newline="\n").write(s2)

cf, nf = sp["categorical"]["fields"], sp["numeric"]["fields"]
rows = "\n".join(f"| `{f}` | {'có' if v['active'] else 'không'} | {v['n_distinct_non_missing']} | {v['n_missing']:,} | " + ", ".join(f"{e['value']} ({e['train_count']:,})" for e in v['vocab'][:3]) + " |" for f, v in cf.items())
nrows = "\n".join(f"| `{c}` | {'có' if v['active'] else 'không'} | {v['log1p_mean']:.4f} | {v['log1p_std']:.4f} | {v['n_missing']:,} |" for c, v in nf.items())
s3 = f"""# S3 — Preprocess (fit chỉ trên TRAIN)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s3_preprocess.py` (30 giây), dùng chung `v2_common.py`.

## Mục đích
Tạo **một file** `data/preprocess_spec.json` chứa toàn bộ từ điển category, thống kê numeric, trường nào dùng cho model và vì sao (thay cho 4 JSON rời của bản cũ). Đầu vào của S4.

## Input
`S1_join/data/flows_joined.parquet` ∩ các cửa sổ `split = train` của `S2_windows_split/data/windows.csv`. **Phạm vi fit: {sp['fit']['n_windows']:,} cửa sổ, {sp['fit']['n_flows']:,} flow; không dùng nhãn, VAL, TEST.**

## Cách làm (giữ như bản cũ để mô hình dùng lại được)
- Category: giá trị chữ thường (thiếu/`-`/`(empty)` → `<MISSING>` id 1; ngoài từ điển → `<UNK>` id 0); từ điển xếp theo số lần xuất hiện trong TRAIN giảm dần, id từ 2; `min_train_frequency` = 5 cho `app_family` và `service`, 1 cho còn lại. `resp_port_class`, `orig_port_class`, `*_ip_scope` dẫn xuất theo quy tắc ghi trong spec.
- Numeric: `log1p(max(x,0))` → z-score theo TRAIN (`stddev_pop`) → clip ±10; thiếu → 0.0 kèm mask; `has_missed_bytes` = `missed_bytes > 0`.
- **Quy tắc active (đổi nhỏ so với bản cũ):** category cần ≥ 2 giá trị, mỗi giá trị ≥ 5 flow TRAIN (hoặc thiếu/có giá trị đều ≥ 5 flow); numeric cần log1p std ≥ 0.01. Lý do: trong split cấp cửa sổ có đúng 1 flow `direction = inbound` (phiên RDP của `sysclient0051`, flow dương) lọt vào TRAIN và với quy tắc cũ sẽ bật cả feature `direction` thành đường tắt; với quy tắc mới feature này vẫn inactive như bản cũ.

## Output
`data/preprocess_spec.json` (phạm vi fit, từ điển, thống kê, thứ tự cột model, dấu vân tay sha256 `{sp['fingerprint_sha256'][:16]}…`), `data/vocab.csv` (từ điển dạng bảng), `schema.json`, `preview.csv` (thống kê numeric), `preview_record.json` (mã hóa từng bước của một flow tấn công và một flow benign), `checks.json`.

Thứ tự cột vào model: category `{sp['model_input_layout']['x_cat_columns']}`; numeric `{sp['model_input_layout']['x_num_columns']}`; nhị phân `has_missed_bytes`; cộng `delta_t_log1p`. Gồm 5 category/7 numeric của bản cũ và thêm hai category host `image_dir_class`, `principal_class`.

## Field lấy từ host (eCAR-Bro) trong input của mô hình
| Field | Nguồn | Ý nghĩa |
|---|---|---|
| `app_family` | `image_path` | Tên tiến trình tạo ra flow (`firefox.exe`, `powershell.exe`…) |
| `image_dir_class` | `image_path` | Tiến trình chạy từ đâu: `SYSTEM32`, `PROGRAM_FILES`, `TEMP_OR_APPDATA`, `BARE_NAME`, … |
| `principal_class` | `principal` | Loại tài khoản chạy tiến trình: `DOMAIN_USER`, `SYSTEM_ACCOUNT`, `ADMINISTRATOR`, `SYSADMIN`, `NONE` |
Mọi feature còn lại là Bro conn. `pid`, `ppid`, `actor_id` vẫn chỉ là cột audit. **Lưu ý đã đo trên toàn bộ dữ liệu:** `principal_class = ADMINISTRATOR` có 13,297 flow dương và 0 flow benign (tài khoản của Red Team), nên là tín hiệu rất mạnh nhưng là đặc điểm của testbed; `image_dir_class = TEMP_OR_APPDATA` có 138 flow dương so với 69 benign (gồm tiến trình độc hại của SC3 chạy từ Temp).

| Category | Active | Số giá trị | Thiếu (TRAIN) | Top 3 (số flow) |
|---|---|---:|---:|---|
{rows}

| Numeric | Active | log1p mean | log1p std | Thiếu |
|---|---|---:|---:|---:|
{nrows}

`missed_bytes` inactive (std 0.0023 < 0.01), thay bằng cờ `has_missed_bytes`.

## Hạn chế
`app_family` có {cf['app_family']['n_distinct_non_missing']} giá trị khác nhau trong TRAIN, {cf['app_family']['n_distinct_dropped_below_min_freq']} giá trị hiếm (< 5 flow) bị đưa về `<UNK>`, ví dụ `notepad++.exe` (tiến trình của SC3), nên model chỉ thấy nó như `<UNK>`.
"""
open(V + "S3_preprocess/STEP_S3_PREPROCESS.md", "w", encoding="utf-8", newline="\n").write(s3)

s4 = f"""# S4 — Shards (mã hóa và đóng gói sample)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s4_shards.py` (12 phút).

## Mục đích
Mã hóa từng flow bằng `preprocess_spec.json` và đóng gói thành sample cho mô hình. Đầu vào của bước train.

## Input
`S1_join/data/flows_joined.parquet`, `S2_windows_split/data/windows.csv` (gán split), `S3_preprocess/data/preprocess_spec.json`.

## Cách làm
- Sample = các flow của một (hostname, cửa sổ 15 phút) sắp theo (`ts`, `uid`), cắt chunk mỗi 512 flow; nhãn sample = có ≥ 1 flow dương.
- Mỗi flow: {len(sp['model_input_layout']['x_cat_columns'])} id category, 7 z-score numeric + 7 cờ thiếu, 1 cờ `has_missed_bytes`, `delta_t_log1p` = ln(1 + giây từ flow trước trong chunk) (flow đầu = 0), và hai chỉ số cục bộ `edge_app_local`, `edge_remote_local`.
- Các sample của mỗi split được xáo trộn có seed (20261013) rồi chia thành các file khoảng 1 triệu flow, nên mỗi file trộn nhiều máy và nhiều ngày.

## Output (4.6 GB, {sum(st[s]['shards'] for s in st)} file `.npz`)
- `shards/{{train,val,test}}/*.npz`: khóa và kiểu mô tả trong `shard_format.json` (giữ như bản cũ để dùng lại mã mô hình).
- `data/samples.csv`: 1 dòng = 1 sample (`sample_id, split, date, hostname, window_start_epoch, window_start_utc, chunk_index, label, event_count, positive_event_count, app_node_count, remote_node_count, shard_file, shard_sample_index`); `schema.json`, `preview.csv`.
- `decoded_preview.json`: ba sample (một mỗi scenario) với flow raw cạnh vector đã mã hóa trong shard và bản mã hóa lại bằng Python.

| Split | Sample | Sample dương | Flow | Flow dương | Số file |
|---|---:|---:|---:|---:|---:|
""" + "\n".join(f"| {s} | {st[s]['samples']:,} | {st[s]['positive_samples']} | {st[s]['events']:,} | {st[s]['positive_events']:,} | {st[s]['shards']} |" for s in ("train", "val", "test")) + """

Kiểm tra (`checks.json`, PASS): số flow, flow dương và sample của mỗi split bằng đúng `windows.csv`; `sample_id` duy nhất; chunk tối đa 512 flow.
"""
open(V + "S4_shards/STEP_S4_SHARDS.md", "w", encoding="utf-8", newline="\n").write(s4)

ps = c5["positive_samples_by_scenario_split"]
s5 = f"""# S5 — Validate (kiểm tra chéo và giải mã ngược)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s5_validate.py` (44 giây). Kết quả: **PASS**.

## Đã kiểm
| Kiểm tra | Kết quả |
|---|---|
| `checks.json` của S1, S2, S3, S4 | cả bốn PASS |
| Phạm vi fit S3 = cửa sổ TRAIN của S2 | khớp ({sp['fit']['n_windows']:,} cửa sổ, {sp['fit']['n_flows']:,} flow); không dùng nhãn/VAL/TEST |
| Mỗi cửa sổ chỉ ở một split; `samples.csv` khớp `windows.csv` | đúng; nhãn cửa sổ = max nhãn sample |
| Sample dương theo scenario (train / val / test) | SC1 {ps['scenario_1']['train']} / {ps['scenario_1']['val']} / {ps['scenario_1']['test']} · SC2 {ps['scenario_2']['train']} / {ps['scenario_2']['val']} / {ps['scenario_2']['test']} · SC3 {ps['scenario_3']['train']} / {ps['scenario_3']['val']} / {ps['scenario_3']['test']} |
| **Giải mã ngược {c5['decode_samples_checked']} sample** (150 dương, 250 benign) so với flow raw trong S1 | cùng số flow; 0 flow sai id category; sai số z-score lớn nhất {c5['decode_max_abs_diff_x_num']:.2e}; 0 sai cờ thiếu / `has_missed_bytes` / nhãn; sai số `delta_t` lớn nhất {c5['decode_max_abs_diff_delta_t']:.2e} |

Từng sample đã so: `sample_verification.csv`.

## Ý nghĩa
Chứng minh đường đi raw → shard không làm mất hay đổi flow, và bước mã hóa SQL (S4) khớp với quy tắc Python đọc được (S3, `preview_record.json`). Sau bước này có thể đóng gói (S6) và train.
"""
open(V + "S5_validate/STEP_S5_VALIDATE.md", "w", encoding="utf-8", newline="\n").write(s5)
print("reports ok")
