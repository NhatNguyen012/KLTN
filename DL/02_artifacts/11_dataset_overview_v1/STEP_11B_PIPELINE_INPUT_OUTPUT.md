# STEP 11B — Từ dữ liệu thô tới 2 model: đầu vào và đầu ra của từng bước

> Số liệu lấy từ split ngẫu nhiên `seed_1` (`02_artifacts/10b_random_preprocess_v1/seed_1`, `03_datasets/random_network_dl_v1_1_15m/seed_1`). Ví dụ ở §8 đã được **đối chiếu từng event với tensor thật trong shard** (30/30 event khớp).

## 0. Trả lời nhanh: không chỉ có 2 loại (categorical và numeric)

File `network_feature_contract.json` (ảnh bạn gửi) chỉ là **danh sách ứng viên** sau bước join, chia theo **vai trò**, không phải đầu vào model:

| Vai trò trong contract | Cột | Dùng làm đầu vào model? |
|---|---|---|
| `join_only_or_audit` | `uid, hostname, ts, date, split, ecar_occurrence_count` | **Không** (chỉ để ghép, chia split, sắp xếp) |
| `target_only` | `label` | **Không**, là **đáp án** (nhãn) |
| `categorical_candidates` | `app_family, direction, proto, service, conn_state, local_orig, local_resp` | Có thể |
| `numerical_candidates` | `duration, orig_bytes, resp_bytes, missed_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes` | Có thể |
| `graph_construction_only_initial` | `orig_h, orig_p, resp_h, resp_p` (IP và cổng) | **Không** làm feature; chỉ dẫn xuất `resp_port_class` và dựng đồ thị cho GNN |
| `cross_source_validation_or_optional` | `ecar_l4protocol` | Không (đối chiếu chéo) |

Sau bước **preprocessing** (chỉ fit trên TRAIN), model nhận **4 nhóm đầu vào** (cộng một mặt nạ), không phải 2:

| Nhóm | Số cột thực dùng | Cột | Dạng |
|---|---:|---|---|
| Categorical (phân loại) | **5** | `app_family, proto, service, conn_state, resp_port_class` | số nguyên ID (0 = `<UNK>` lạ, 1 = `<MISSING>` thiếu) |
| Numeric (số) | **7** | `duration, orig_bytes, resp_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes` | số thực: `log1p` → z-score (TRAIN) → cắt ±10 |
| Mặt nạ thiếu của numeric | 7 | cùng 7 cột trên | 0/1 (1 nếu giá trị bị thiếu) |
| Binary | **1** | `has_missed_bytes` (= 1 nếu `missed_bytes > 0`) | 0/1 |
| Thời gian | **1** | `delta_t_log1p` | số thực = `ln(1 + khoảng cách giây tới flow trước)` |

6 cột categorical bị loại vì **hằng số trên TRAIN** (`direction, local_orig, local_resp, orig_ip_scope, resp_ip_scope, orig_port_class`); `missed_bytes` bị thay bằng cờ `has_missed_bytes` vì độ lệch chuẩn quá nhỏ (0.0018) nên z-score không ổn định.

---

## 1. Toàn cảnh

```text
RAW (E:\)            JOIN              SPLIT           PREPROCESS         DỰNG SAMPLE           MODEL
eCAR-Bro + Bro  ──►  bảng flow  ──►  gán TRAIN/VAL/ ──► ID + z-score  ──►  chuỗi ≤512 flow  ──► 1 xác suất
(.json.gz,.log.gz)   92M dòng        TEST theo host     (fit TRAIN)        / (host, 15 phút)      / sample
```

| Bước | Đầu vào | Xử lý | Đầu ra |
|---|---|---|---|
| 1. Raw | 156 file eCAR-Bro + 313 file Bro `conn` | đọc `.gz` | record JSON / dòng log |
| 2. Join (STEP 04B) | eCAR-Bro (`bro_uid`, host, process) + Bro conn (`uid`, ts, proto…, `label`) | khớp `bro_uid == uid`, khử trùng | **parquet 92,045,755 dòng** (mỗi dòng = 1 flow) |
| 3. Split theo host | parquet + bảng host → split | gán mỗi host vào TRAIN/VAL/TEST (host-disjoint) | `host_split_frozen.csv` |
| 4. Preprocess (STEP 10B) | flow của host TRAIN | dẫn xuất `resp_port_class`; đếm giá trị → bảng ID; tính mean/std log1p; chọn feature | `category_maps.json`, `numeric_stats.json`, `preprocess_spec.json` |
| 5. Dựng sample (STEP 10C) | parquet + 3 file JSON ở bước 4 | gom theo (host, cửa sổ 15 phút), sắp theo thời gian, cắt chunk ≤ 512, mã hóa | **shards `.npz`** + `network_sample_manifest.csv` |
| 6. DataLoader | shards | đệm (padding) tới độ dài lớn nhất trong batch, tạo mặt nạ | **tensor batch** |
| 7. Model | tensor batch | BiLSTM hoặc Mixed-Type Self-Attention | **1 logit / sample** |
| 8. Đầu ra | logit | sigmoid → xác suất → so với ngưỡng (chọn trên VAL) | **0 = benign, 1 = tấn công** cho từng window |

---

## 2. Bước 2 — Join: mỗi dòng là một flow

Đầu vào:
- eCAR-Bro (`object=FLOW`): `bro_uid, hostname, pid, principal, image_path` (process), `src_ip/port, dest_ip/port`.
- Bro `conn`: `uid, ts, id.orig_h/p, id.resp_h/p, proto, service, duration, orig_bytes, resp_bytes, conn_state, orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes, missed_bytes, local_orig, local_resp, history, label`.

Xử lý: `eCAR-Bro.bro_uid == Bro conn.uid`; giữ một dòng/`uid`; `app_family` là họ process lấy từ `image_path`.

Đầu ra (cột parquet): `uid, ts, hostname, label, app_family, direction, orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, date, split`. Kết quả: 92,045,755 flow, trong đó 85,626,185 flow thuộc 620 host dùng để train/đánh giá.

## 3. Bước 4 — Preprocessing (chỉ fit trên TRAIN của split đó)

1. **Dẫn xuất `resp_port_class`** từ cổng đích: `443 → PORT_443_HTTPS`, `80 → PORT_80_HTTP`, `8080 → PORT_8080_HTTP_ALT`, `53 → PORT_53_DNS`, `445 → PORT_445_SMB`, cổng khác → `WELL_KNOWN_OTHER / REGISTERED / EPHEMERAL / OTHER`.
2. **Categorical → ID:** chuẩn hóa chuỗi (cắt khoảng trắng, chữ thường), đếm trên TRAIN, giá trị đủ phổ biến nhận ID 2, 3, …; giá trị chưa từng thấy ở TRAIN thành `<UNK>` = 0; thiếu thành `<MISSING>` = 1. Kích thước từ điển ở `seed_1`: `app_family` 67, `proto` 4, `service` 5, `conn_state` 7, `resp_port_class` 9.
3. **Numeric:** `x → log1p(x) → (log1p(x) − mean_TRAIN) / std_TRAIN → cắt về [−10, +10]`; thiếu thì điền 0 (bằng trung bình TRAIN) và đặt cờ thiếu = 1.
4. **Binary:** `has_missed_bytes = 1 nếu missed_bytes > 0`.
5. **Chọn feature:** trường nào hằng số trên TRAIN thì bỏ; không dùng nhãn để chọn feature.

Vì fit riêng trên TRAIN của từng seed, từ điển và mean/std của 3 seed hơi khác nhau (ví dụ `app_family` có 67, 63, 62 giá trị).

## 4. Bước 5 — Dựng sample (đơn vị mà model nhìn thấy)

- **Sample = một chuỗi các flow của MỘT host trong MỘT cửa sổ 15 phút** (`window_start = floor(ts/900)*900`), sắp theo `(ts, uid)`.
- Nếu cửa sổ có hơn **512** flow thì cắt thành các **chunk** liên tiếp tối đa 512 flow (ví dụ một cửa sổ 830 flow thành chunk 0 gồm 512 flow và chunk 1 gồm 318 flow).
- `delta_t_log1p` của flow đầu mỗi chunk = 0; các flow sau = `ln(1 + ts − ts_trước)`.
- **Nhãn của sample** = 1 nếu chunk có **ít nhất một** flow positive, ngược lại 0. Nhãn từng flow không đưa vào model.
- Mỗi shard `.npz` lưu **nối dài** các flow của nhiều sample:

| Mảng | Hình dạng | Ý nghĩa |
|---|---|---|
| `x_cat` | N × 5 (uint16) | ID của 5 cột categorical |
| `x_num` | N × 7 (float32) | 7 số đã chuẩn hóa |
| `x_num_missing` | N × 7 (0/1) | cờ thiếu của 7 số |
| `x_bin` | N × 1 (0/1) | `has_missed_bytes` |
| `delta_t_log1p` | N (float32) | khoảng cách thời gian |
| `sample_offsets`, `sample_labels` | | ranh giới từng sample và nhãn 0/1 |
| `edge_app_local`, `edge_remote_local` | | chỉ phục vụ model đồ thị (GraphSAGE/GAT), 2 model này không dùng |

(N = tổng số flow trong shard.) Không có `label` từng flow, `hostname`, IP hay thời gian tuyệt đối trong tensor.

Quy mô `seed_1`: TRAIN 165,326 sample (444 positive), VAL 33,245 (39), TEST 30,413 (83).

## 5. Bước 6 — DataLoader

`collate_sequence_batch` ghép B sample thành một batch, đệm (padding) bằng 0 tới độ dài lớn nhất T (≤ 512) và tạo mặt nạ:

| Tensor | Hình dạng |
|---|---|
| `x_cat` | [B, T, 5] (số nguyên) |
| `x_num` | [B, T, 7] |
| `x_num_missing` | [B, T, 7] |
| `x_bin` | [B, T, 1] |
| `delta_t_log1p` | [B, T, 1] |
| `attention_mask` / `lengths` | [B, T] / [B]: vị trí nào là flow thật |
| `labels` | [B] (0/1) |

Nếu bật `DROP_APP_FAMILY`, cột `app_family` của `x_cat` (cột 0) bị đặt về 0 (`<UNK>`) ở đây, cho cả train, val và test.

## 6. Bước 7 — Hai model nhận đầu vào như thế nào

**BiLSTM baseline** (79,790 tham số):
1. Mỗi cột categorical đi qua một bảng nhúng riêng (embedding): kích thước 16, 4, 4, 5, 6 = **35 chiều** cho 5 cột.
2. Ghép (nối) thành **một vector 51 chiều cho mỗi flow**: 35 (categorical) + 7 (numeric) + 7 (mặt nạ thiếu) + 1 (binary) + 1 (`delta_t`).
3. `Linear 51→64 + LayerNorm + GELU` → vector sự kiện 64 chiều.
4. **BiLSTM hai chiều** (hidden 64) đọc cả chuỗi flow theo thời gian; lấy trạng thái cuối của hai chiều → 128 chiều.
5. Bộ phân loại (MLP) → **1 logit**.

**Mixed-Type Self-Attention** (146,305 tham số), cấu trúc hai tầng:
1. **Mỗi flow thành 14 "token"** (mỗi token 64 chiều): 5 token categorical (embedding), 7 token numeric (giá trị × trọng số học được + bias, cộng vector "thiếu" nếu thiếu), 1 token binary, 1 token `delta_t`; mỗi token cộng thêm embedding "tên cột" và "loại cột".
2. **Tầng 1, self-attention giữa các cột trong cùng một flow** (14 token nhìn nhau, 4 head): model học tổ hợp nào của các cột quan trọng; lấy trung bình 14 token → **vector 64 chiều cho flow**.
3. Cộng embedding vị trí (thứ tự flow trong chuỗi).
4. **Tầng 2, self-attention giữa các flow trong chuỗi** (2 lớp, có mặt nạ để bỏ phần đệm); lấy trung bình có mặt nạ → 64 chiều.
5. MLP → **1 logit**.

Cả hai model nhận cùng 5 tensor ở §5; khác nhau ở chỗ BiLSTM ghép phẳng rồi đọc tuần tự, còn Mixed-Type để các cột "nhìn nhau" rồi các flow "nhìn nhau".

## 7. Bước 8 — Đầu ra và cách chấm

- Đầu ra: **một số thực (logit) cho mỗi sample**; `sigmoid(logit)` = xác suất window đó chứa tấn công.
- Hàm mất mát: `BCEWithLogitsLoss` với `pos_weight = số sample âm / số sample dương` của TRAIN (≈ 371 ở `seed_1`) vì positive rất hiếm (~0.27%).
- Chọn **checkpoint** theo PR-AUC trên VAL, chọn **ngưỡng** theo F1 cao nhất trên VAL; TEST chỉ chạy một lần.
- Dự đoán cuối: `xác suất ≥ ngưỡng ⇒ 1 (tấn công)`; xuất `val_predictions.csv`, `test_predictions.csv` (cột `sample_id, label, probability, prediction`) và `metrics.json` (Precision, Recall, F1, PR-AUC, ROC-AUC).

---

## 8. Ví dụ thật: một window beacon SC2 đi qua toàn bộ pipeline

Window của `sysclient0618` lúc 2019-09-24 20:00 UTC, **30 flow**, cả 30 là positive (beacon `202.6.172.98:443`, mỗi ~30 giây). Hai flow đầu:

| Cột | Flow 0 (raw) | → mã hóa | Flow 1 (raw) | → mã hóa |
|---|---|---|---|---|
| `app_family` | `powershell.exe` | **5** | `powershell.exe` | 5 |
| `proto` | `tcp` | 2 | `tcp` | 2 |
| `service` | `ssl` | 2 | `ssl` | 2 |
| `conn_state` | `SF` | 2 | `SF` | 2 |
| cổng đích `443` | | `PORT_443_HTTPS` = 2 | | 2 |
| `duration` (giây) | 0.0635 | z = −0.056 | 0.0776 | z = −0.024 |
| `orig_bytes` | 667 | z = −0.593 | 667 | −0.593 |
| `resp_bytes` | 2277 | z = −0.096 | 2277 | −0.096 |
| `orig_pkts` | 6 | z = −0.775 | 6 | −0.775 |
| `orig_ip_bytes` | 919 | z = −0.970 | 919 | −0.970 |
| `resp_pkts` | 8 | z = −0.487 | 8 | −0.487 |
| `resp_ip_bytes` | 2609 | z = −0.172 | 2609 | −0.172 |
| `missed_bytes` | 0 | `has_missed_bytes` = 0 | 0 | 0 |
| `delta_t_log1p` | (flow đầu) | **0.000** | cách flow 0 là 30.1 giây | `ln(1+30.1)` = **3.438** |

Cách tính z-score (ví dụ `orig_bytes` = 667): `log1p(667) = 6.504`; TRAIN có mean = 6.828, std = 0.545 ⇒ `(6.504 − 6.828) / 0.545 = −0.593`.

Điều đáng nhìn: **cả 30 flow gần như giống hệt nhau** (cùng ID, cùng số, `delta_t` = 3.44 lặp lại). Đó chính là chữ ký của beacon mà model nhận ra, kể cả khi bỏ `app_family` (cột đầu của `x_cat` về 0).

Kiểm chứng: tôi tự biến đổi 30 flow thô theo spec rồi so với mảng `x_cat, x_num, x_bin, delta_t_log1p` thật trong shard `test_2019-09-24_0001.npz` (sample có chỉ số 362 trong shard): **30/30 flow khớp**. Window dài hơn 512 flow (ví dụ cùng host, 19:45 UTC, 830 flow) được cắt thành 2 sample: 512 và 318 flow.

## 9. Điều cần nhớ
- Categorical và numeric chỉ là **hai trong bốn nhóm** đầu vào; còn có binary và thời gian, kèm mặt nạ thiếu.
- `hostname, uid, ts, IP, label` **không** là feature. Nhãn chỉ dùng để chấm và tính trọng số mất mát.
- Model không nhìn từng flow riêng lẻ mà nhìn **chuỗi flow của một host trong 15 phút**; nhãn là của cả chuỗi.
- Mọi thống kê (từ điển, mean/std) chỉ tính trên TRAIN của split tương ứng để không rò rỉ.
