# STEP 22 — Pipeline Network DL v2: build lại từ raw, mỗi bước có input/output đọc được — KẾ HOẠCH (chờ xác nhận)

Ngày: 2026-10-13. Chưa chạy gì. Mã mới ở `01_code/pipeline_v2/` (không sửa pipeline cũ); output ở `02_artifacts/22_v2_pipeline/S1_… S5_…`. Artifact cũ giữ nguyên.

## 1. Quyết định đã chốt (theo yêu cầu 2026-10-12/13)
- Build lại từ raw (E:), không dùng lại parquet/shards/preprocess cũ.
- Split cấp cửa sổ, phân tầng theo scenario (STEP 21A), **một** split (seed cố định), không host-disjoint (ngoại lệ có chủ ý so với CLAUDE.md).
- Train **một lần** (một seed), giữ **đủ** feature (không drop `app_family`, không ablation, không beacon holdout).
- Mô hình giữ nguyên kiến trúc BiLSTM và Mixed-Type; chỉ viết lại notebook cho gọn (không còn `DROP_APP_FAMILY`, `RUN_SUFFIX`, `HOLDOUT_TAG`).

## 2. Quy ước chung cho mọi bước
Mỗi thư mục bước `S?_…/` chỉ gồm các file sau, không tách nhỏ thêm:
| File | Nội dung |
|---|---|
| `data/…` | Output chính của bước (parquet cho bảng lớn; CSV/JSON cho bảng nhỏ). Đây là **đầu vào duy nhất** của bước sau. |
| `schema.json` | Mọi trường của output: tên, kiểu, nguồn (trường raw nào), công thức, ý nghĩa, ví dụ thật, vai trò (khóa / feature / nhãn / audit). |
| `preview.csv` và `preview_record.json` | Dòng thật mở được bằng Excel (có cả tấn công và benign, đủ 3 scenario) và một bản ghi thật dạng "trường: giá trị". |
| `checks.json` | Kết quả kiểm tra tự động (đếm dòng, bảo toàn, phạm vi fit…); bước sau từ chối chạy nếu `checks.json` không PASS. |
| `STEP_S?_*.md` | Báo cáo tiếng Việt: mục đích, input (đường dẫn + schema), cách làm, output, số liệu, hạn chế. |

## 3. Các bước, input → output
| Bước | Input | Output chính | Ghi chú |
|---|---|---|---|
| **S1 join** | `E:\bro\<ngày>\conn.*.log.gz` (22 trường, có `label`), `E:\ecar-bro\…\ecarbro.json.gz` (FLOW có `bro_uid`) | `flows_joined.parquet`: 1 dòng = 1 flow. Bro 21 trường + `hostname`, `app_family`, `image_path`, `direction`, `ecar_l4protocol`, `ecar_occurrence_count`, `ts_utc`, `date_utc`, `window_start_epoch`, cộng 4 cột **chỉ để audit**: `actor_id, pid, ppid, principal` (không vào feature, không vào shards) | Khóa `bro_uid = uid`; giữ 1 dòng mỗi uid (bản ghi eCAR-Bro sớm nhất); **inner join đã chốt**: chỉ giữ flow có eCAR-Bro như bản cũ. Kèm bảng audit nhỏ `unmatched_flows_audit.csv` (flow độc hại không ghép được). Không còn cột `split`. |
| **S2 windows + split** | `flows_joined.parquet`, bảng máy → scenario (29 máy bị tấn công) | `windows.csv` (~110 nghìn dòng): `hostname, window_start_epoch, window_start_utc, date_utc, scenario, n_flows, n_chunks, n_positive_flows, label, stratum, split` + `split_summary.json` | Phân tầng 70/15/15 theo scenario (cửa sổ dương) và theo ngày (cửa sổ benign), thuật toán STEP 21A. 620 máy có cả log host và mạng (như bản cũ; 123 máy chỉ có mạng bị loại). |
| **S3 preprocess (fit chỉ trên TRAIN)** | `flows_joined.parquet` ∩ cửa sổ `split=train` | **Một file** `preprocess_spec.json`: phạm vi fit (số cửa sổ, flow), từ điển từng trường category (`value → id`, đếm trên TRAIN, quy tắc active/inactive kèm lý do), thống kê numeric (log1p, mean, std, clip ±10, tỉ lệ thiếu), cờ binary, cách tính `delta_t`, dấu vân tay sha256; kèm `vocab.csv` để mở bằng Excel | Thay cho 4 file JSON rời của bản cũ. Feature giống bản cũ: category `app_family, proto, service, conn_state, resp_port_class`; numeric `duration, orig_bytes, resp_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes`; binary `has_missed_bytes`; thời gian `delta_t_log1p`. |
| **S4 shards** | `flows_joined.parquet`, `windows.csv`, `preprocess_spec.json` | `shards/{train,val,test}/*.npz` (khoảng 1 triệu flow mỗi file, ~90 file) + `samples.csv` (1 dòng = 1 sample: `sample_id, split, hostname, window_start_epoch, chunk_index, label, n_flows, n_positive_flows, shard_file, shard_index`) + `shard_format.json` (khóa npz, kiểu, shape, ý nghĩa) + `decoded_preview.json` (vài sample: flow raw cạnh vector đã mã hóa) | Sample = cửa sổ 15 phút, chunk ≤ 512 flow, nhãn sample = có ≥ 1 flow dương (như cũ). Khóa npz giữ như cũ để dùng lại loader. |
| **S5 validate** | S1–S4 | `validation_report.json` + md | Bảo toàn số flow và flow dương qua từng bước; không cửa sổ val/test nào nằm trong phạm vi fit; decode ngược mẫu ngẫu nhiên từ shard và so với flow raw. |
| **Train** | `shards`, `samples.csv`, `preprocess_spec.json` | `bilstm_v2/`, `mixed_v2/`: `metrics.json`, `predictions.csv` (sample + hostname + cửa sổ + scenario + điểm), `threshold.json`, `history.csv` | Kaggle, 1 seed (42), không drop, tối đa 8 epoch như cũ. Ngưỡng chọn trên VAL, TEST chạy một lần. |
| **Report** | predictions + `windows.csv` | Bảng kết quả theo scenario (SC1/SC2/SC3) và theo cửa sổ | |

## 4. Ước lượng (chưa đo; sẽ chạy thử một ngày trước khi chạy cả bộ)
| Bước | Dung lượng ghi | Thời gian dự kiến | Cơ sở |
|---|---:|---|---|
| S1 | ~3 GB (bản cũ: 2.9 GB parquet) | 40–90 phút, giới hạn bởi đọc ổ E: (HDD) | Đếm dòng 313 file `conn` (14.3 GB nén) mất 492 s; chưa đo phần đọc 92.1M JSON eCAR-Bro (6.5 GB nén) |
| S2 | vài chục MB | vài phút | Gộp theo cửa sổ trên parquet |
| S3 | < 1 MB | 3–10 phút | Aggregation trên TRAIN |
| S4 | ~4.4 GB | 15–25 phút | STEP 10C: build 11–14 phút/seed |
| S5 | vài MB | 5–10 phút | |
| Train (Kaggle) | — | BiLSTM ~130 s/epoch, Mixed-Type ~400 s/epoch (STEP 10G) | |
Tổng ghi trên D: khoảng 8 GB (còn trống ~156 GB); DuckDB có thể dùng thêm 10–20 GB tạm.

## 5. Cần từ người dùng
1. **Gắn ổ E:** (raw `bro`, `ecar-bro`, `a_new_hope_for_darpa_optc`) khi tôi báo bắt đầu S1; chỉ đọc, không ghi vào E:.
2. Xác nhận kế hoạch và ước lượng ở trên, đặc biệt: (a) giữ 620 máy như bản cũ, (b) thêm cột audit `actor_id/pid/ppid/principal` ở S1, (c) giữ inner join.

## 6. Bổ sung 2026-10-13 (trả lời hai câu hỏi của người dùng)
**A. Bốn cột `actor_id, pid, ppid, principal`.** Chỉ là khóa để tra ngược sang log host sau này (cha là ai, command line); KHÔNG phải feature và KHÔNG đưa vào model v2. Fusion hiện có là mức điểm (STEP 17, ghép `p_net` với điểm host theo (hostname, 15 phút): cải thiện 2 / 1,103 cửa sổ). Fusion mức đặc trưng (đưa field host vào input model) mới ở mức thiết kế nháp (STEP 20), chưa có code hay train; không chặn việc build lại v2.

**B. Inner join và flow độc hại bị loại.** Trong 4,590 flow độc hại bị loại, 4,190 là của `dc1` (không nằm trong 620 máy supervised nên vốn không vào train/val/test); trong 620 máy chỉ mất khoảng 400 flow (`sysclient0051` 325, `sysclient0351` 41, `sysclient0501` 28, còn lại ~6). Đã kiểm trên parquet cũ: IP nguồn ↔ hostname gần như 1–1 (742/743 máy có đúng 1 IP, không IP nào thuộc 2 máy; riêng `sysclient0051` xuất hiện thêm IP C2 `53.192.68.50` ở cột nguồn), nên khôi phục hostname cho flow thiếu eCAR-Bro bằng IP là khả thi.
Phương án đề xuất cho S1: **giữ inner join** và thêm bảng audit `unmatched_flows_audit.csv` (mọi flow Bro có `label = 1` không ghép được: uid, ts, hostname suy từ IP, đích, `conn_state`, lý do), cùng bảng đếm flow không ghép theo (máy, ngày) để biết chính xác kích thước nếu muốn left join. Left join đầy đủ cho 620 máy (tối đa ~290M dòng, ~3.2 lần; parquet ~9 GB, shards ~14 GB, train lâu gấp ~3) đổi bản chất dữ liệu và không so sánh được với kết quả đã chốt; chỉ thêm riêng ~400 flow độc hại sẽ tạo đường tắt `app_family = <MISSING>` ⇒ dương.

## 7. Chốt 2026-10-13
- **Inner join là quyết định chính thức:** chỉ giữ flow có bản ghi eCAR-Bro, như bản cũ. Vẫn giữ `unmatched_flows_audit.csv` (khoảng 4.6 nghìn dòng, chỉ để biết chính xác phần bị loại; không đưa vào train).
- **Giữ** bốn cột `actor_id, pid, ppid, principal` ở S1 làm cột audit (ước lượng thêm ~0.5–1 GB parquet, chưa đo). Không dùng làm feature, không đưa vào shards; `pid/ppid` chỉ là số, không dùng để suy cha–con (xem `PHAN_TICH_OPTC_SC3_BEACON_VA_FIELD_HOST.docx`).
- Trạng thái: chờ gắn ổ E: để viết và chạy thử S1 (một ngày), rồi báo số đo thật trước khi chạy cả bộ.

## 8. Hoàn thành S1–S6 (2026-10-13)
S1–S5 đã chạy từ raw và đều PASS (báo cáo `STEP_S1…S5_*.md` trong từng thư mục); S6 đã đóng gói `03_datasets/v2_network_dl_kaggle_upload` và sinh notebook `04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb`, `07d_Mixed_Type_Kaggle_v2_final.ipynb`. Thay đổi so với kế hoạch: bước gộp S1 mất 81 phút (không phải vài phút); quy tắc active của S3 thêm ngưỡng 5 flow. Việc kế tiếp (train Kaggle, S7): xem `00_docs/ai_agent/HANDOFF_V2_PIPELINE.md`.
