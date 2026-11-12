# STEP 14 — Lớp "đọc được" cho pipeline OpTC (mục lục)

Ngày: 2026-10-07. Mục đích: mỗi bước của pipeline có một thư mục với (1) dữ liệu CSV mở được bằng Excel, (2) một file JSON mẫu một bản ghi thật, (3) một file `.md` giải thích mục đích, đầu vào, cách làm, đầu ra và bước sau nhận gì. Dùng để viết báo cáo khóa luận và NCKH.

**Nguyên tắc:** không sửa shard hay artifact cũ. Các file ở đây được **sinh lại từ dữ liệu đã có** và đối chiếu với shard `.npz` (xem S5). Vì vậy 12 run Kaggle hiện có vẫn dùng đúng dữ liệu này và không phải train lại.

## Luồng tổng quát

```text
S0 Dữ liệu thô          S1 Flow đã ghép         S2 Nhãn              S3 Chia host
eCAR (host) + Bro  ──►  1 dòng = 1 flow   ──►  nhị phân + đa nhãn ─►  train/val/test
(.json.gz, .log.gz)     (92M dòng)              (flow, window)        theo hostname
                                                                          │
S5 Mẫu cửa sổ + gói Kaggle  ◄──  S4 Đặc trưng (mã hóa, chỉ fit TRAIN)  ◄──┘
   (chuỗi flow của 1 host trong 15 phút)

Nhánh host:   S6 đặc trưng host theo cửa sổ 15 phút (từ eCAR thô)
Ghép hai nhánh: S9 bảng đầu vào fusion (host × cửa sổ: p_net, đặc trưng host, nhãn)
Dataset phụ:  S8 Unraveled (chỉ network, nhãn theo giai đoạn APT)
```

## Thư mục và nội dung

| Thư mục | Trả lời câu hỏi | File chính | Mô tả |
|---|---|---|---|
| `S0_raw_schema/` | Dữ liệu thô gồm những trường gì? | `fields_ecar_event.csv`, `fields_bro_conn.csv`, `sample_*.json` | [S0_RAW_SCHEMA.md](S0_raw_schema/S0_RAW_SCHEMA.md) |
| `S1_network_flows/` | Một flow sau khi ghép trông thế nào? | `fields_flow.csv`, `flows_sample.csv`, `sample_flow.json` | [S1_NETWORK_FLOWS.md](S1_network_flows/S1_NETWORK_FLOWS.md) |
| `S2_labels/` | Nhãn được gán thế nào, ở mức nào? | `label_rules.csv`, `window_labels_multilabel.csv` | [S2_LABELS.md](S2_labels/S2_LABELS.md) |
| `S3_split/` | Host nào thuộc train/val/test? | `host_split_all.csv`, `split_summary.csv` | [S3_SPLIT.md](S3_split/S3_SPLIT.md) |
| `S4_features/seed_{1,2,3}/` | Từng cột được mã hóa ra sao? | `feature_spec.csv`, `vocab_*.csv`, `numeric_normalization.csv` | [S4_FEATURES.md](S4_features/S4_FEATURES.md) |
| `S5_window_samples/` | Model nhìn thấy gì? | `sample_windows.json`, `window_flows_raw_vs_encoded.csv` | [S5_WINDOW_SAMPLES.md](S5_window_samples/S5_WINDOW_SAMPLES.md) |
| `S6_host_branch/` | Đặc trưng host theo cửa sổ | `host_window_features.csv`, `sample_host_malicious_events.json` | [S6_HOST_BRANCH.md](S6_host_branch/S6_HOST_BRANCH.md) |
| `S8_unraveled/` | Dataset phụ Unraveled | `fields_unraveled_flow.csv`, `unraveled_sample_flows.csv` | [S8_UNRAVELED.md](S8_unraveled/S8_UNRAVELED.md) |
| `S9_fusion_inputs/` | Bảng ghép host và network | `window_fusion_table_seed1.csv` | [S9_FUSION_INPUTS.md](S9_fusion_inputs/S9_FUSION_INPUTS.md) |

(Không có S7: số thứ tự S7 để dành cho đầu ra của model, chưa làm.)

## Liên hệ với các step cũ

| Lớp đọc được | Artifact gốc (không sửa) | Script tạo lớp đọc được |
|---|---|---|
| S0 | `E:\ecar-bro`, `E:\bro`, `E:\host-*` | `01_code/pipeline/14_build_readable_layer.py` (S0) |
| S1 | `02_artifacts/02_network_joined_v1/joined/` (parquet) | `14_build_readable_layer.py` (S1) |
| S2 | `D:\UIT\KLTN\KLTN-main\a_new_hope_for_darpa_optc\labelling\`, `02_artifacts/12b_multilabel_stage_v1/` | `14_build_readable_layer.py` (S2) |
| S3 | `02_artifacts/10a_random_split_v1/`, `02_artifacts/11_dataset_overview_v1/hosts_625.csv` | `14_build_readable_layer.py` (S3) |
| S4, S5 | `03_datasets/random_network_dl_v1_1_15m/seed_{k}/` | `14b_readable_features_and_windows.py` |
| S6, S8, S9 | `02_artifacts/12c_host_features_v1/`, `03_datasets/unraveled_v1_clean/` | `14c_readable_host_unraveled_fusion.py` |

## Đã kiểm chứng
- S5 tái tạo mã hóa của 3 cửa sổ thật từ dữ liệu thô và so với mảng trong shard `.npz`: **`x_cat` giống hệt, `x_num` lệch tối đa 4.3×10⁻⁷ (sai số float32), cờ thiếu và `x_bin` giống hệt** (file `S5_window_samples/verification_vs_npz_shard.json`).
- S1: tổng 92,045,755 flow, 24,721 flow tấn công, 743 host (đếm lại trực tiếp từ parquet).

## Lưu ý
- Giờ trong các file ghi rõ UTC hoặc EDT (UTC−4). Cửa sổ 15 phút của hai múi giờ trùng nhau vì chênh lệch 4 giờ là bội của 15 phút.
- File mẫu không chứa toàn bộ dữ liệu (92 triệu flow nằm ở parquet cũ; ở đây là mẫu 2,000 flow và các bảng tổng hợp). Cách lấy dữ liệu đầy đủ được ghi trong từng file `.md`.
