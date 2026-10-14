# Kiểm tra nhánh Lam và sửa high-level architecture — 14/10/2026

Đã clone riêng nhánh `Lam` từ `NhatNguyen012/KLTN` vào `Temp/Lam-review/`, commit `5e283bc0c707f5cf90029d0a2c407873720d46b7` (Network DL, 14:00:54 +07:00). Không merge vào nhánh `Nguyen`, không sửa checkout Lam, không chạy pipeline hoặc huấn luyện. Checkout gốc có thay đổi chưa commit nên giữ nguyên. Lệnh fetch đầu tiên bị sandbox chặn ghi `.git/FETCH_HEAD`; clone riêng thành công sau khi được cho phép truy cập mạng.

[Hình đã sửa PNG](../image/host_apt_high_level_lam_verified/high_level_design.png) · [SVG](../image/host_apt_high_level_lam_verified/high_level_design.svg) · [Bằng chứng kiểm tra JSON](verification.json).

## Kết luận trực tiếp từ code

Nhánh DL v2 là **network flow classification được bổ sung context từ host**. Nó đọc `bro/conn.*.log.gz` và `ecar-bro/**/ecarbro.json.gz`. Nó không đọc trực tiếp `host-begnin/` hay `host-malicious/` trong pipeline v2, cũng không lấy prediction từ Host ML làm input của hai DL model hiện tại. Hai nguồn join theo `uid = properties.bro_uid`, lấy bản ghi eCAR-Bro sớm nhất khi trùng, loại hostname conflict và giữ flow matched. SQL tạm dùng LEFT JOIN nhưng lọc `e_uid IS NOT NULL`, nên output có ngữ nghĩa INNER JOIN. [s1_join.py](../../Temp/Lam-review/01_code/s1_join.py:91).

### Feature thực sự active

| Nhóm | Feature | Nguồn |
|---|---|---|
| Host context | `app_family`, `image_dir_class`, `principal_class` | eCAR-Bro `properties.image_path`, `principal` |
| Network categorical | `proto`, `service`, `conn_state`, `resp_port_class` | Bro conn; cổng đích được phân nhóm |
| Numeric | `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes` | Bro conn |
| Numeric missingness | Một mask cho mỗi numeric feature | Giá trị thiếu trong input |
| Binary | `has_missed_bytes` | `Bro missed_bytes > 0` |
| Time | `delta_t_log1p` | `ln(1 + max(0, ts − ts_prev))`; đầu mỗi chunk bằng 0 |

Tổng 7 categorical + 7 numeric + 7 numeric masks + 1 binary + 1 delta-time. Mixed-Type biểu diễn thành **16 feature tokens**, vì missingness được cộng vào numeric token, không tạo thêm bảy token. [preprocess spec](../../Temp/Lam-review/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json), [v2_common.py](../../Temp/Lam-review/01_code/v2_common.py:43).

`actor_id`, `pid`, `ppid`, raw hostname/IP, raw principal không phải input trực tiếp. Tuy nhiên principal **có ảnh hưởng qua `principal_class`**, image_path qua hai field dẫn xuất. Parent process identity/command line chưa có trong input DL. `history` lưu để audit, không active. Các mảng `edge_app_local`, `edge_remote_local` được ghi trong shard nhưng **hai model forward hiện tại không sử dụng chúng**; không vì tên mảng edge mà vẽ GNN trong DL.

Không thấy input DNS query logs, HTTP application logs hoặc orchestration logs riêng trong pipeline v2. `service=http` hoặc port-class DNS không đồng nghĩa có raw HTTP/DNS event sequence.

### Window, chunk và target

- Bin cố định theo UTC: `floor(ts/900)*900`, theo từng hostname. Đây là fixed/tumbling bins, không phải sliding window tùy ý như giả định trước.
- Trong mỗi bin, sắp flow theo `(ts, uid)`, cắt từng **chunk ≤ 512 flow**.
- Sample key là `(hostname, window_start_epoch, chunk_index)`; nhãn sample = có ít nhất một flow malicious **trong chunk**. Một bin dương có thể chứa cả chunk âm và chunk dương.
- `window.label = max(flow.label)` dùng ở S2; `chunk.label` tính lại ở S4. Không sao chép nhãn dương của window cho mọi chunk.
- Ground truth flow lấy từ `Bro conn.label` của bộ corrected OpTC; scenario chỉ dùng cho stratification/audit, không phải target model.
- Hai model dự đoán một binary logit → sigmoid → threshold; không có multi-label head hay unknown detector.

Bằng chứng: [s1_join.py](../../Temp/Lam-review/01_code/s1_join.py:185), [s2_windows_split.py](../../Temp/Lam-review/01_code/s2_windows_split.py:53), [s4_shards.py](../../Temp/Lam-review/01_code/s4_shards.py:59).

Các feature như duration/total bytes/packets mô tả flow đã được ghi nhận. Binning theo flow-start `ts` không chứng minh tất cả feature đã sẵn sàng ngay cuối bin. Khi thiết kế online, phải quy định flow finalization/observation time và độ trễ; chưa được đo trong repo. Vì vậy hình mới không khẳng định causal streaming hay phát hiện ngay lúc flow bắt đầu.

### Hai model là hai baseline độc lập

**BiLSTM:** embedding categorical + numeric + missing masks + binary + delta-time → per-flow Linear/LayerNorm/GELU (64 chiều) → 1-layer bidirectional LSTM, hidden 64 mỗi chiều → concatenate hai final hidden state (128 chiều) → binary MLP. 80,657 tham số theo config.

**Mixed-Type:** 7 categorical + 7 numeric + binary + delta-time → 16 feature tokens (64 chiều) có field/type embeddings → 1 feature self-attention block (4 heads) → mean trên feature tokens → flow vector → learned positional embedding → 2 temporal self-attention blocks (4 heads) → masked mean qua flow → binary MLP. 147,329 tham số theo config. `causal_mask=false`; padding mask khác với causal mask.

Đây là self-attention trong một chuỗi flow có feature hỗn hợp, **không phải cross-attention giữa nhánh Host ML và nhánh DL**. Không có nối BiLSTM → Mixed-Type hoặc ensemble hai model đã được triển khai trong bản final.

Bằng chứng được trích nguyên văn, không chạy, từ cell 7 của mỗi notebook:
- [BiLSTM source](extracted/06d_BiLSTM_Kaggle_v2_final.py.txt:73)
- [Mixed-Type source](extracted/07d_Mixed_Type_Kaggle_v2_final.py.txt:81)
- [BiLSTM config](../../Temp/Lam-review/05_models/v2_final/bilstm_v2/config.json)
- [Mixed-Type config](../../Temp/Lam-review/05_models/v2_final/mixed_v2/config.json)

## Split và kết quả đã đối chiếu

DL dùng window split 70/15/15, seed 1; train model seed 42. Stratify positive windows theo scenario và benign windows theo ngày. Mọi chunk của một window ở cùng split; **không host-disjoint**. Preprocess chỉ fit TRAIN, checkpoint theo VAL PR-AUC, threshold theo VAL F1.

Đã đếm độc lập CSV windows: 110,402 unique host/windows, TRAIN 77,281 / VAL 16,561 / TEST 16,560. TEST có **81 positive windows**, khác **82 positive chunks**. Đã đối chiếu CSV predictions: mỗi model có 34,413 TEST samples/chunks.

| Model | TP | FP | FN | TN | F1 tính lại |
|---|---:|---:|---:|---:|---:|
| BiLSTM | 80 | 0 | 2 | 34,331 | 0.987654 |
| Mixed-Type | 81 | 0 | 1 | 34,331 | 0.993865 |

Ngưỡng lưu của cả hai = 1.0. Kết quả trên là kiểm tra arithmetic của prediction artifact đã có, không phải inference hoặc train lại. Báo cáo của Lam ghi luật đơn giản có `powershell.exe` đạt F1 0.994 và một seed chỉ chênh một positive sample; không đủ kết luận Mixed-Type ưu việt hoặc generalize sang host/dataset mới. [S7 report](../../Temp/Lam-review/02_artifacts/22_v2_pipeline/S7_results/STEP_S7_RESULTS.md).

## Những phần architecture phải sửa

1. Tách input Host ML từ `host-begnin/host-malicious` với input DL từ `bro + ecar-bro`; không vẽ toàn bộ host activity logs đi vào DL như hiện đã làm.
2. Gọi nhánh hiện tại **Network Flow DL with Host-derived Context**. Muốn gọi endpoint-only thì cần triển khai adapter và đánh giá lại với feature thật có ở endpoint; không chỉ đổi tên box.
3. Ghi fixed 15-minute bin + chunk ≤ 512, prediction cấp chunk. Fusion phải có bước gộp chunk→window, host event→window và hợp đồng label chung.
4. Vẽ BiLSTM và Mixed-Type như hai lựa chọn độc lập. Self-attention nội bộ không chứng minh learned fusion đã có.
5. Gating/source masks/cross-attention là tích hợp đề xuất. [STEP20](../../Temp/Lam-review/02_artifacts/20_fusion_design_v1/STEP_20_FUSION_DESIGN.md) ghi rõ draft, chưa cài đặt. Tài liệu có nhắc score-level fusion STEP17 lịch sử, nhưng mã/artifact đầy đủ STEP17 không nằm trong export này; không coi là v2 fusion đã được xác minh.
6. Nhánh Host hiện có learned GraphSAGE/cascade riêng; phải phân biệt gating của cascade Host với gating giữa Host và Network DL.
7. Unknown detection, incremental-learning trigger, registry và rollout là module mục tiêu, không phải tính năng đã thấy trong code Lam.
8. Hình hiện tại không thêm Network Sensor triển khai mới: nó ghi đúng **nguồn dataset Zeek** đang dùng. Mong muốn của thầy về OS/service-only collection là target khác và cần thay representation/train lại khi không đủ trường.

## Hệ quả khi tích hợp và thêm dataset

Frozen Host seed02 là event split 75/10/15; DL v2 là window split 70/15/15. Không ghép hai TEST hiện tại rồi tuyên bố joint TEST độc lập: cùng host/window có thể chứa event mà base Host model đã train. Cần kiểm tra giao tập theo source/time/host và xây protocol chung, scoring ngoài tập fit cho việc học fusion. Giữ nguyên baseline đã duyệt; thí nghiệm joint là artifact mới.

Ba dataset đã đề xuất trước là ứng viên mở rộng **host/service telemetry**, không được coi là drop-in compatible với checkpoint DL này. Muốn áp dụng checkpoint không train lại phải tái tạo đúng semantics/order của field, vocabulary, normalization và missingness. Thiếu `conn_state`, packet/byte statistics hoặc process context thì không chỉ điền 0 và gọi là tương đương. Dataset có network flow nhưng không có process-linked context cũng chưa khớp. Phân biệt kiểm thử model giữ nguyên, train adapter/model mới và fine-tune trên TRAIN mới; báo cáo coverage riêng.

Đối với Linux, `app_family` và quy tắc `image_dir_class`/`principal_class` hiện được thiết kế theo Windows; cần đánh giá OOV và mapping semantics. Multi-label cần target/head/loss thích hợp; nhiều dataset không tự đổi binary output hiện có.

## Phạm vi xác minh và khả năng chạy lại

Đã đọc source preprocessing, source model trong notebook, config, schema, split CSV, predictions và report; đã đối chiếu số lượng/metrics bằng stdlib, kiểm tra SVG và ảnh. Chưa chạy training, chưa load pickle/PyTorch checkpoints, chưa quét raw corpus.

Export GitHub chứa `01_code/*.py` nhưng một số tài liệu còn trỏ `01_code/pipeline_v2/`. Mã còn hardcode `D:/UIT/KLTNv2`, `E:/...`. `hosts_625.csv`, shards và joined parquet được tham chiếu nhưng không có trong export đã clone; loader `network_dl_dataset_v1_1.py` được nhúng trong notebook và được notebook ghi ra khi chạy; do vậy clone này đủ để xác định architecture, chưa phải gói tái chạy toàn pipeline tại máy này.
