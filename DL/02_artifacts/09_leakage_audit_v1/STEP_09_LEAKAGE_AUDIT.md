# STEP 09 — Leakage Audit cho pipeline Network Deep Learning (host split)

> **Ghi chú đổi tên (2026-10-01):** báo cáo này viết trước khi dọn dẹp thư mục. Tên step cũ trong bài (04A–05F, `artifacts/step…`, `kaggle/…`) tương ứng tên mới trong `00_docs/RENAME_MAP.csv` (04A→01, 04B→02, 04C→03, 04D→04, 05A→05, 05B→06 BiLSTM, 05E→07 Mixed-Type, 05F→08 LOSO, 05G→09).

## Trạng thái

**AUDIT COMPLETE — CHƯA RETRAIN.** Tài liệu này chỉ kết luận về tính đúng đắn của experiment (experimental validity). Chưa đổi kiến trúc, chưa đổi dataset, chưa train lại.

- Ngày audit: 2026-10-01
- Dataset được audit: `network-dl-v1.1-15m` (preprocess fingerprint `a24ef2cc…0839`)
- Model được audit: `bilstm_baseline_v1/`, `mixed_type_attention_v1/`
- Script tái lập: `01_code/pipeline/09_leakage_audit.py` (read-only)

---

## 0. Kết luận ngắn (TL;DR)

**Câu hỏi:** Metric DL gần 1.0 là do model học được attack behavior, hay do data leakage (rò rỉ dữ liệu)?

**Trả lời:** Không đúng hẳn vế nào.

1. **Không tìm thấy data leakage kỹ thuật theo nghĩa hẹp.** Split theo host sạch (0 host overlap, 0 source-IP overlap). Vocabulary và mean/std fit trên TRAIN only. Checkpoint và threshold chọn trên VAL, TEST chỉ chạy một lần. Không có label, hostname, IP hay timestamp trong tensor.
2. **Metric vẫn không chứng minh model học được APT behavior.** Trên dataset hiện tại, bài toán gần như tầm thường (trivially separable), vì ba nguyên nhân có bằng chứng:
   - **Label proxy / shortcut feature (đặc trưng "đi tắt"):** mọi network event có `app_family = powershell.exe` đều malicious. Có 24,503/24,503 event PowerShell nằm trong positive window, 0 nằm trong negative window. Một luật một dòng *"window có ≥1 event powershell.exe"* đạt **TEST F1 = 0.975** (P = 1.000, R = 0.952), ngang BiLSTM (F1 = 0.976).
   - **Campaign-level duplication (trùng lặp ở mức chiến dịch tấn công):** cùng một C2 beacon (khoảng 30 kết nối mỗi 15 phút, cùng C2 server, cùng bytes và timing) chạy trên nhiều host. Host split đặt các bản sao của cùng beacon vào cả TRAIN và TEST. 72/83 positive window của TEST đến từ một host (`sysclient0851`), với khoảng cách tới TRAIN positive gần nhất là **0.001** (thang z-score; hai negative ngẫu nhiên cách nhau 2.14). 76/83 test positive window có "template" đã có trong TRAIN.
   - **Window shape đã đủ để phân lớp:** chỉ dùng 4 số nguyên metadata (`event_count, app_node_count, remote_node_count, chunk_index`), không dùng feature mạng nào, vẫn đạt **TEST ROC-AUC = 0.9994**, F1 = 0.887.
3. **Tập đánh giá quá nhỏ và tập trung:** 83 positive window trên TEST đến từ 4 host, trong đó một host chiếm 87%. Chênh lệch BiLSTM và Mixed-Type chỉ là 2–3 window. **Không thể kết luận model nào tốt hơn.**

**Diễn giải:** Nghi ngờ của giảng viên là đúng: metric này không đáng tin như một thước đo khả năng phát hiện APT. Tuy nhiên cơ chế không phải rò rỉ train→test qua pipeline. Cơ chế là **shortcut learning (học đường tắt) + evaluation design không đo generalization (khả năng tổng quát hóa)**. Hệ quả cho bước tiếp theo: chỉ đổi split (kể cả "random scenario split") nhiều khả năng **vẫn cho ~1.0**, vì host split hiện tại đã được stratify theo scenario (xem §11).

---

## 1. Phạm vi và cách audit

| Folder / file | Đã đọc | Ghi chú |
|---|---|---|
| `artifacts/step04_network_profile_fast_v2/` | report + md | profile trước join |
| `artifacts/step04_network_joined_v1/` | contract, join report, md, `step04b_state.sqlite3` | thêm 7 partition parquet (xem dưới) |
| `KLTN_bootstrap_step01/scripts/04b_build_exact_network_join.py` | toàn bộ phần join | |
| `artifacts/step04_network_preprocess_v1_1/` | spec, maps, numeric stats, review, fingerprint | |
| `scripts/04c_fit_network_preprocessing.py`, `04c_finalize…v1_1.py` | phần fit map/stats | |
| `scripts/04d_build_network_dl_shards_v1_1.py` (+ base v1.0) | query window/chunk/label | |
| `kaggle/network_dl_v1_1_15m/` | README, build_config, dataset_manifest, **toàn bộ** `network_sample_manifest.csv` (228,984 samples), **26 shard .npz chứa mọi positive sample** (5.69M events) | |
| `kaggle/05B_BiLSTM_Kaggle.ipynb`, `05E_Mixed_Type_Self_Attention_Kaggle.ipynb` | toàn bộ code train/eval | |
| `bilstm_baseline_v1/`, `mixed_type_attention_v1/` | config, metrics, threshold, history, val/test predictions, attention_audit | |
| `artifacts/step05f_*` + `KLTN_bootstrap_step01/step05f_*` | LOSO remap, preprocess, shards summary, validation | |

**Giới hạn:** phân tích mức event trên joined parquet chỉ dùng các partition `test 23–25/9`, `val 24–25/9`, `train 24–25/9`: 5,777,537 events, 16,634/24,721 positive events. Phân tích mức window (sample) dùng toàn bộ manifest và toàn bộ positive window. Script `09_leakage_audit.py` quét lại **toàn bộ** shards và joined parquet trên máy local để xác nhận.

---

## 2. Checklist tổng hợp

| # | Hạng mục | Kết quả | Bằng chứng chính |
|---|---|---|---|
| 7.1 | Join key eCAR↔Bro | ✅ PASS | `ecar.properties.bro_uid == bro_conn.uid`, exact join 99.97% |
| 7.2 | Duplicate connection / 1 flow nhiều split | ✅ PASS | dedup 1 row/uid; `uid` xuất hiện ở >1 split: 0 |
| 7.3 | Label trong feature / field chứa attack info | ✅ PASS (trực tiếp) · ⚠️ **FAIL (gián tiếp: `app_family`)** | tensor không có label/scenario/host/IP; nhưng `powershell.exe` ⇒ 100% malicious |
| 8.1 | Category vocab từ TRAIN only | ✅ PASS | `04c…py` L433 `train = counts.get("train")` |
| 8.2 | Mean/std từ TRAIN only | ✅ PASS | `train_observed + train_missing = 61,751,292` = đúng số TRAIN rows |
| 9.1 | Host overlap | ✅ PASS | train∩test = train∩val = val∩test = ∅ |
| 9.2 | Source IP overlap | ✅ PASS | `orig_h` overlap = 0; `orig_h`↔hostname 1:1 |
| 9.3 | Destination IP overlap | ⚠️ WARNING | chỉ ~64 destination IP trong toàn bộ dữ liệu; 99.97% test positive events đi tới C2 endpoint đã có trong TRAIN positive (IP **không** là feature) |
| 9.4 | Flow duplication | ✅ PASS (cùng flow) · ⚠️ **FAIL (cùng template)** | không có uid trùng; nhưng 93.9% event trong test positive window có signature giống hệt TRAIN positive |
| 10.1 | Window overlap | ✅ PASS | tumbling window `floor(ts/900)*900`, không overlap |
| 10.2 | Sort timestamp | ✅ PASS | `row_number() OVER (PARTITION BY hostname, window_start ORDER BY ts, uid)` |
| 10.3 | Chunk 512 gây leakage | ✅ PASS | mọi chunk của 1 window cùng host ⇒ cùng split; 0 duplicate (host, window, chunk) |
| 11.1 | Validation chỉ dùng chọn checkpoint/threshold | ✅ PASS | early stop theo VAL PR-AUC; threshold = max F1 trên VAL |
| 11.2 | Test dùng để tune | ✅ PASS | TEST chạy một lần sau khi freeze; metric tính lại từ CSV khớp `metrics.json` |
| — | Sức mạnh thống kê của TEST | ❌ **FAIL** | 83 positive / 4 host; 1 host = 72 window |
| — | Baseline tầm thường | ❌ **FAIL** | rule 1 dòng F1 0.975; metadata-only ROC-AUC 0.9994 |

---

## 3. Audit Dataset JOIN (Mục 7)

### 3.1 Join có đúng không?

- **Join key:** `eCAR-Bro.properties.bro_uid == Bro conn.uid`. Bro chỉ lấy `conn.*.log.gz` (canonical connection table), tránh nhân bản uid qua `ssl/http/dns`.
- **eCAR dedup:** một row mỗi `bro_uid` (`arg_min` theo `ecar_ts`), hostname conflict = 0.
- **Bro duplicate:** giữ row sớm nhất mỗi uid (`QUALIFY row_number() … = 1`).
- **Kết quả:** 92,045,755 joined rows, exact join rate 99.972%. Kiểm tra lại trên 5.78M events đã stage: `uid` trùng = 0, `uid` xuất hiện ở >1 split = 0.
- **Nhiều event map vào một sample:** có, và đây là thiết kế: một sample = (hostname, 15-min window, chunk).

### 3.2 Vấn đề data hygiene (không ảnh hưởng feature)

- **Folder eCAR-Bro bị ingest hai lần:** `E:\ecar-bro\evaluation\23Sep-Night` và `…\23Sep-night` (khác hoa/thường) đều được xử lý (10 file × 25,727 records mỗi folder, `step04b_state.sqlite3`). Đây là nguồn chính của 26,347 "duplicate UID". Dedup theo uid đã triệt tiêu tác động, và `ecar_occurrence_count` **không** là feature, nên không gây leakage. Nên sửa ở inventory để tránh nhầm lẫn về sau.
- **Ngày 25/9 gần như không có benign data:** folder `evaluation\25Sept` chỉ có ~31.7k eCAR-Bro records. Ở ngày 25/9, TEST có 57 positive / 82 negative window (41% positive), trong khi các ngày khác < 0.5%. Model không thấy ngày trực tiếp, nhưng đây là base-rate shift (dịch chuyển tỉ lệ nền) theo ngày cần ghi nhận.

### 3.3 Label đến từ đâu?

- Label là cột **`label` có sẵn trong Bro conn logs** (`join_policy.label_source = "Bro conn label"`). STEP 04A thấy 71,726 dòng `label=1` trên 1.01B dòng Bro. Sau join còn 24,721 positive events.
- eCAR-Bro **không có label** (`ecar_label: missing` 100%).
- Repo **không ghi lại** cách cột `label` của Bro được tạo (ai gán, theo tiêu chí gì). Đây là câu hỏi mở quan trọng (§12).

### 3.4 Label có xuất hiện trong feature không?

- **Trực tiếp: không.** Shard `.npz` chỉ có `x_cat` (5 cột), `x_num` (7), `x_num_missing`, `x_bin` (1), `delta_t_log1p`, edge local ids và sample metadata. Không có `label` event-level, `scenario_id`, `hostname`, IP hay timestamp tuyệt đối.
- **Gián tiếp: có, qua `app_family`.** Trên 5.78M events đã stage:

| app_family | label=0 | label=1 | tỉ lệ malicious |
|---|---:|---:|---:|
| powershell.exe | 0 | 16,422 | **100%** |
| biguwcmnsucig.exe | 0 | 140 | 100% |
| ckfgw.exe, gup.exe, movingonup.exe, filetransfer1000.exe, … | 0 | ~30 | 100% |
| cmd.exe | 6,758 | 7 | 0.1% |
| firefox.exe | (≈5.6M) | 0 | 0% |

  PowerShell chiếm 98.7% positive events. Trên toàn dataset (04B report), tổng số event `powershell.exe` là 24,503, và cả 24,503 đều nằm trong positive window.

> **Diễn giải:** `app_family` là feature hợp lệ lúc triển khai (process name quan sát được). Nhưng trong OpTC, benign traffic gần như 100% là `firefox.exe` (user simulation), còn PowerShell không bao giờ tạo network traffic benign. Vì vậy `app_family` trở thành **label proxy (đặc trưng thay thế nhãn)**. Nếu cột `label` của Bro được gán dựa trên process của red team, feature này gần như chính là luật gán nhãn.

---

## 4. Audit Feature Engineering (Mục 8)

### 4.1 Categorical: vocabulary

- `build_category_maps()` (`04c_fit_network_preprocessing.py`) chỉ dùng `counts["train"]`, min frequency, rồi gán id. VAL/TEST chỉ dùng cho OOV audit (`val_UNK_rate`, `test_UNK_rate`).
- Quyết định active/inactive (`04c_finalize…v1_1.py`) dựa trên TRAIN cardinality/std; `label_used_for_feature_selection = false`.
- **Kết luận: PASS.**
- **Quan sát:** 6/11 categorical là hằng số trên TRAIN. `orig_ip_scope = resp_ip_scope = PUBLIC_IPV4`, `local_orig = local_resp = F`, `direction = outbound`. Chỉ 5 categorical active: `app_family(62) · proto(4) · service(5) · conn_state(8) · resp_port_class(8)`. Không gian feature rất hẹp, nên `app_family` nổi bật.

### 4.2 Numerical: mean/std

- `build_numeric_stats()` chỉ đọc `numeric_profile["train"]`.
- Kiểm chứng số học: `duration.train_observed (61,745,738) + train_missing (5,554) = 61,751,292` = đúng số TRAIN rows của STEP 04B.
- Transform: `log1p → TRAIN z-score → clip ±10`. `missed_bytes` được thay bằng `has_missed_bytes`.
- **Kết luận: PASS.**

---

## 5. Audit Dataset Split (Mục 9)

### 5.1 Split hiện tại

Split đơn vị hostname, 70/15/15, stratify theo **scenario của positive host** (`02_prepare_ground_truth_and_split_v1_1.py`).

| split | samples | positive | hosts | positive hosts |
|---|---:|---:|---:|---:|
| train | 164,605 | 399 | 432 | 19 (+1 GT host không có positive event mạng) |
| val | 35,134 | 84 | 94 | 5 |
| test | 29,245 | **83** | 94 | **4** |

Positive window trong TEST theo host:

| host | scenario | positive windows |
|---|---|---:|
| sysclient0851 | scenario_2 | **72** |
| sysclient0402 | scenario_1 | 4 |
| sysclient0051 | scenario_3 | 4 |
| sysclient0503 | scenario_1 | 3 |

### 5.2 Host overlap: ✅ PASS

Theo manifest, `train ∩ test = train ∩ val = val ∩ test = ∅`. Ở mức IP: `orig_h` overlap = 0, và `orig_h` ↔ hostname là 1:1.

### 5.3 IP overlap

- **Source IP:** 0 overlap.
- **Destination IP:** trong 5.78M events đã đọc, mỗi split chỉ có ~64 destination IP (internet giả lập của OpTC); 100% test events đi tới IP đã thấy trong TRAIN. IP **không** nằm trong tensor, nên đây không phải leakage trực tiếp.
- **Quan trọng:** mọi positive event đi tới **3 C2 server** (cộng 1 event RDP nội bộ). TEST dùng cùng C2 với TRAIN:

| C2 endpoint (positive events) | train* | val* | test |
|---|---:|---:|---:|
| 202.6.172.98:443 | 9,213 | 2,104 | 2,094 |
| 132.197.158.98:80 | 2,066 | 0 | 943 |
| 53.192.68.50:8080 / :80 | 26 | 0 | 162 |

  \*train/val: chỉ partition 24–25/9 đã stage. 99.97% test positive events đi tới endpoint đã có trong TRAIN positive.

### 5.4 Flow duplication

- **Cùng một flow ở nhiều split:** không (uid unique, host-disjoint).
- **Cùng một pattern/template ở nhiều split:** có, và rất nặng (§8.3). Ví dụ đúng kiểu mà prompt cảnh báo: *TRAIN host A 10:00 connection X — TEST host B connection X*. Ở đây là beacon PowerShell tới `202.6.172.98:443` trên `sysclient0069/0203/0358/0618` (train), `sysclient0010` (val) và `sysclient0851` (test), giống nhau tới từng bytes và nhịp thời gian.
- **Benign cũng có đồng bộ:** trong 5.78M events đã đọc, 23,681 benign events có cùng (dst, port, timestamp đến ms, orig/resp bytes) giữa các split. Traffic firefox được script hóa và chạy đồng thời trên nhiều host.

---

## 6. Audit Sequence Construction (Mục 10)

| Kiểm tra | Code | Kết quả |
|---|---|---|
| Window | `floor(ts/900)*900` theo `(hostname, window_start)` | tumbling, **không overlap** ✅ |
| Sort | `row_number() OVER (… ORDER BY ts, uid)` | chronological ✅ |
| Chunk 512 | `chunk_index = floor(rn/512)` | chunk cùng window → cùng host → cùng split ✅; 0 duplicate key ✅ (fix v1.1 logical-day đã xử lý lỗi duplicate sample của v1.0) |
| delta_t | `ln(1+ts−prev_ts)` trong chunk, event đầu = 0 | chỉ tương đối, không có absolute time ✅ |
| Sample label | `max(event labels)`: positive nếu ≥1 positive event | 90.5% positive window "thuần" (mọi event đều positive) |

**Hệ quả của thiết kế window:** positive window có hình dạng rất đặc trưng. Median `event_count` = 30 (so với 512 cho negative), `remote_node_count` = 1 (so với 6), `chunk_index` = 0. Riêng thông tin này đã đủ để phân lớp (§8.2).

---

## 7. Audit Model Training (Mục 11)

| Kiểm tra | BiLSTM (05B) | Mixed-Type (05E) |
|---|---|---|
| Checkpoint selection | VAL PR-AUC ✅ | VAL PR-AUC ✅ |
| Threshold | max F1 trên VAL ✅ (0.00075) | max F1 trên VAL ✅ (0.00045) |
| TEST | 1 lần sau khi freeze ✅ | 1 lần sau khi freeze ✅ |
| Recompute từ `test_predictions.csv` | TP 80 · FP 1 · FN 3 ✅ khớp | TP 82 · FP 0 · FN 1 ✅ khớp |
| pos_weight | TRAIN neg/pos = 411.5 ✅ | 411.5 ✅ |

**Cảnh báo (không phải leakage):**

1. **VAL bị bão hòa (saturated):** VAL PR-AUC = 1.0 từ epoch 2 (BiLSTM) và epoch 5 (Mixed-Type). Early stopping và chọn threshold gần như không có tín hiệu phân biệt.
2. **Threshold nằm đúng tại positive VAL thấp nhất** (`sysclient0005`, window không phải PowerShell). Việc TEST bắt được 3/4 window của host "mới" `sysclient0051` phụ thuộc vào threshold cực thấp này. Đây là tín hiệu mong manh.
3. **Attention audit (05E):** trên VAL, negative window dồn attention vào `app_family` (0.50); positive window dồn vào `service`, `resp_port_class`, `app_family`. Kết quả nhất quán với shortcut ở §3.4. (Attention không phải causal importance.)
4. `bilstm_baseline_v1/metrics.json` có mtime 25/09 22:29, trong khi run là 23/09 16:34. Nội dung vẫn khớp predictions, nhưng nên ghi chú provenance.

---

## 8. Bằng chứng thực nghiệm: shortcut và near-duplicate

### 8.1 Baseline luật một dòng

> Dự đoán positive ⇔ window có ≥ 1 event `app_family = powershell.exe`.

| split | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| train | 395 | 0 | 4 | 164,206 | 1.000 | 0.990 | 0.995 |
| val | 81 | 0 | 3 | 35,050 | 1.000 | 0.964 | 0.982 |
| **test** | **79** | **0** | **4** | **29,162** | **1.000** | **0.952** | **0.975** |

FP = 0 là đúng theo cấu trúc dữ liệu: cả 24,503 event PowerShell đều nằm trong positive window.

### 8.2 Baseline metadata-only (không dùng feature mạng)

HistGradientBoosting trên `event_count, app_node_count, remote_node_count, chunk_index`, threshold chọn trên VAL:

| TEST | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| metadata-only | 0.922 | 0.855 | 0.887 | 0.905 | **0.9994** |

### 8.3 So sánh với DL (TEST)

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | FN / FP |
|---|---:|---:|---:|---:|---:|---|
| Rule "has powershell" | 1.000 | 0.952 | 0.975 | — | — | 4 / 0 |
| Metadata-only HGB | 0.922 | 0.855 | 0.887 | 0.905 | 0.9994 | 12 / 6 |
| BiLSTM | 0.988 | 0.964 | 0.976 | 0.974 | 0.9979 | 3 / 1 |
| Mixed-Type Self-Attention | 1.000 | 0.988 | 0.994 | 0.999 | 1.0000 | 1 / 0 |

Recall theo host trên TEST:

| host | windows | BiLSTM | Mixed-Type | Rule | Khoảng cách tới TRAIN positive gần nhất |
|---|---:|---:|---:|---:|---:|
| sysclient0851 | 72 | 70 | 72 | 72 | **0.001** |
| sysclient0402 | 4 | 4 | 4 | 4 | 0.18 |
| sysclient0503 | 3 | 3 | 3 | 3 | 0.02 |
| sysclient0051 | 4 | 3 | 3 | 0 | **27.2** (thực sự mới) |

- Phần DL làm hơn luật một dòng chỉ nằm ở **4 window của `sysclient0051`** (scenario 3). Cả hai model bắt được 3/4, và phụ thuộc vào threshold rất thấp (§7).
- BiLSTM và Mixed-Type chênh nhau **2–3 window** trên 83. Ở cỡ mẫu này, **không đủ để kết luận Mixed-Type tốt hơn BiLSTM**.

### 8.4 Near-duplicate (gần trùng lặp)

- **Mức event:** 93.9% event trong TEST positive window (99.3% event PowerShell) có signature (5 categorical + 7 numeric làm tròn 0.05σ) giống hệt một event trong TRAIN positive window. Với VAL: 99.0%.
- **Mức window:** 96.4% TEST positive window gần một TRAIN positive hơn mọi TRAIN negative trong cùng các shard ngày tấn công (11.7k window).
- **Template:** gom positive window theo vector tổng hợp (làm tròn 1σ). 431/566 positive window toàn dataset chung **một** template, là beacon PowerShell khoảng 30 s tới `202.6.172.98:443`, chạy qua đêm 24→25/9 trên 6 host (4 train, 1 val, 1 test). 76/83 TEST positive window có template đã xuất hiện trong TRAIN.

---

## 9. LOSO (step05f)

- Pipeline LOSO sạch về kỹ thuật. Preprocessing refit trên TRAIN hosts của từng fold (`only host profiles whose loso_split == TRAIN`). Host disjoint, validation 3 fold PASS.
- **Scenario ≈ ngày** trong dữ liệu mạng: scenario_1 = 23/9 (78 positive window), scenario_2 = 24–25/9 (482), scenario_3 = 25/9 (6). Vì vậy LOSO thực chất là *leave-one-day-out*, và:
  - fold hold-out scenario_2: TRAIN chỉ còn 59 positive window, `pos_weight = 2,730`;
  - fold hold-out scenario_3: TEST chỉ có 6 positive window.
- Không có file metric của lần train LOSO trong repo nên không audit được kết quả. Nhận xét của giảng viên ("unseen campaign quá khác") phù hợp với phân tích này: giữa các scenario, C2 server, công cụ và nhịp beacon đều khác nhau.

---

## 10. Trả lời câu hỏi nghiên cứu

> *"Metric DL gần hoàn hảo trước đây là vì model thật sự học được attack behavior, hay vì pipeline có data leakage?"*

- **Pipeline không có data leakage kỹ thuật** (split, preprocessing, threshold, sequence đều PASS).
- **Metric gần hoàn hảo cũng không phải bằng chứng model học được APT behavior tổng quát.** Nó phản ánh ba điều:
  1. dataset có **shortcut**: `powershell.exe` ⇒ malicious, một luật một dòng đạt F1 0.975;
  2. host split khiến TEST là **bản sao gần như y hệt của TRAIN** ở mức campaign: cùng C2, cùng beacon template;
  3. TEST quá nhỏ và tập trung (4 host, 1 host = 87%).
- Có thể nói model "học được" nhận diện **beacon PowerShell của chiến dịch đã thấy**. Chưa có bằng chứng model nhận diện hành vi APT **mới** (chỉ có 4 window của `sysclient0051` là mới, và kết quả trên đó mong manh).

Thuật ngữ phù hợp để viết trong luận văn: *shortcut learning (học đường tắt)* và *campaign-level contamination / near-duplicate evaluation (đánh giá trên dữ liệu gần trùng lặp ở mức chiến dịch)*. Không nên dùng "overfit" (không có bằng chứng về train–test gap), cũng không nên dùng "leakage do preprocessing" (đã kiểm chứng là không có).

---

## 11. Đề xuất cho retrain (CHỜ QUYẾT ĐỊNH, chưa thực hiện)

**Lưu ý quan trọng về feedback "random scenario split":** host split v1.1 **đã** stratify theo scenario: TRAIN/VAL/TEST đều có host scenario_1 và scenario_2. Nếu "random scenario distribution" được hiện thực là random host split giữ tỉ lệ scenario, kết quả gần như chắc chắn **lại ≈ 1.0**, vì hai nguyên nhân gốc (shortcut `app_family` và template trùng lặp) không thay đổi. Cần trao đổi lại với giảng viên để thống nhất mục tiêu của split mới.

Các thí nghiệm đề xuất, để chọn:

| ID | Thí nghiệm | Mục đích |
|---|---|---|
| E0 | **Luôn báo cáo baseline** rule-PowerShell + metadata-only cạnh DL | DL chỉ được coi là "học behavior" nếu vượt baseline trên phần khó |
| E1 | **Feature ablation (loại bỏ đặc trưng):** bỏ `app_family`, hoặc gộp mọi app ≠ firefox thành `OTHER_APP` | đo xem model còn nhận ra beacon qua timing/bytes/port không |
| E2 | **Grouped / deduplicated evaluation:** group = (scenario × C2 endpoint/template); template trong TEST không có trong TRAIN; hoặc tối thiểu báo cáo metric sau khi gộp window trùng template | đo generalization thật trong cùng phân phối attack |
| E3 | **Repeated random host split theo scenario** (≥5 seeds) + mean ± std + recall theo host + host-level detection (host có ≥1 window bị bắt) + bootstrap CI theo host | hiện thực feedback của giảng viên nhưng có độ tin cậy thống kê |
| E4 | **Hard-negative set (mẫu âm khó):** benign window có app ≠ firefox (cmd.exe, conhost.exe, appidcertstorecheck.exe → 53.192.68.50…) | đo FPR ở vùng dễ nhầm |
| E5 | LOSO giữ làm **stress test** (phụ lục), không làm kết quả chính | theo feedback |

Metric đề xuất cho so sánh Before/After: Precision, Recall, F1, PR-AUC, ROC-AUC, confusion matrix, **cộng thêm** recall theo host, recall@FPR cố định và kết quả có/không `app_family`.

---

## 12. Câu hỏi mở / cần xác nhận

1. **Nguồn gốc cột `label` trong Bro conn logs:** ai gán, theo tiêu chí gì (C2 IP + time window? process của red team? file ground truth nào)? Nếu label được gán theo process thì `app_family` gần như chính là labeling rule, và E1 trở thành bắt buộc.
2. Beacon qua đêm 24→25/9 trên 6 host được coi là **một** attack instance hay 6? Câu trả lời quyết định cách group ở E2.
3. Có giữ `app_family` trong mô hình chính không? Giữ thì hợp lệ về triển khai nhưng phải báo cáo shortcut; bỏ thì đo behavior "thuần mạng".
4. Folder `23Sep-Night` / `23Sep-night` trùng: nên loại một bản ở inventory.

---

## 13. Reproduce

```text
python 01_code/pipeline/09_leakage_audit.py --project-root D:\UIT\KLTNv2
```

Output: `02_artifacts/09_leakage_audit_v1/audit_evidence.json`. Script read-only và cần `pandas, numpy, scikit-learn, pyarrow`. Phần [C] quét toàn bộ shards; phần [F] đọc toàn bộ joined parquet với filter `label==1 OR app_family=='powershell.exe'`.
