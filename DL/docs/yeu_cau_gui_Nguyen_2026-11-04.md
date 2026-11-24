# Yêu cầu gửi Nguyễn (nhánh Host) — từ Lâm (nhánh DL), 2026-11-04

Bối cảnh một dòng: Lâm sẽ làm DL theo hợp đồng của Nguyễn (DL dùng **sự kiện host**, không dùng L3/L4/Zeek) và cần đúng khóa, nhãn, split và ngữ cảnh tiến trình của Nguyễn để hai nhánh khớp nhau và có thể fusion mức điểm. Zip `KLTN-main.zip` bản 04/11 **không có thư mục `output/`** và đã bỏ nhiều tài liệu `ML/analyst`, nên dưới đây là những thứ chỉ Nguyễn có. Mỗi mục ghi: xin gì, nằm ở đâu (theo README của Nguyễn), ý nghĩa, dùng để làm gì. Ưu tiên P0 → P3.

Quy ước khóa (lấy từ `process_context_tracker.py`, mong giữ nguyên khi xuất): `host` = hostname viết thường, bỏ tên miền (`sysclient0201`); `uuid` = UUID viết thường; thời gian = **micro giây kể từ epoch UTC** (số nguyên). Bản ghi eCAR gốc dùng giờ EDT có offset, nhớ nói rõ nếu xuất giờ khác.

## P0 — Kiểm chứng kết quả và khóa hàng (nhỏ, vài MB)
1. **`ML/code/output/host_ml_parent_incoming_seed02/kaggle_output/lgbm_kaggle_results/results/lgbm_metrics.json` và `confusion_matrix.png`.** Chỉ số VAL/TEST của F1 0.9963 (TP 40,123, FP 109, FN 187, ngưỡng 0.87427). *Ý nghĩa:* README ghi số này nhưng zip không có file; Lâm cần file gốc để trích dẫn đúng.
2. **Điểm theo từng sự kiện của LightGBM (VAL và TEST):** bảng `(source_id, source_line, event_id nếu có, split, label, score)`. Nếu notebook chưa xuất, xin xuất thêm. *Ý nghĩa:* Lâm dùng để fusion mức điểm (điểm LightGBM của sự kiện + điểm DL cho cùng sự kiện/cửa sổ) và so FP/FN đúng từng dòng. `(source_id, source_line)` là khóa hàng mà `host_shards.py`/`build_model_input.py` đang dùng; xin kèm cách ánh xạ sang `id` (UUID) của bản ghi eCAR gốc.
3. **`experiment_identity.json`, `completion.json`, `scope.json`, `frozen_label_membership_verification.json`, `vocab_metadata.json` (có thể bỏ `vocab.json` 511 KB nếu nặng) và `model_input/manifest.json`.** *Ý nghĩa:* định danh thí nghiệm (SHA-256 mã nguồn, TTL 86,400 s, ngưỡng dung lượng), phạm vi dữ liệu (số host, số file, số dòng đã đọc), và biên bản đối chiếu nhãn 100% với mask đóng băng. Lâm cần để chứng minh hai nhánh dùng cùng dữ liệu và cùng nhãn.

## P0 — Mask split và nhãn (để DL dùng đúng split của Nguyễn)
4. **`ML/code/output/host_ml_seed02/split/` (mask phân vùng đóng băng seed 02, manifest) và `host_ml_seed02/index/manifest.json`.** *Ý nghĩa:* mask cho biết mỗi sự kiện thuộc TRAIN/VAL/TEST. Nếu DL tự chia lại thì không thể fusion và dễ rò rỉ chéo giữa hai nhánh. Xin kèm: định dạng (mỗi `source_id` một mảng bit hay danh sách dòng), cách duyệt theo thứ tự file, và nguồn nhãn (`ground_truth_corrected_all_evts.json.gz`, khóa theo `id` sự kiện).

## P1 — Bảng tiến trình (thay cho việc Lâm quét lại log ~17 giờ)
5. **Bảng tiến trình theo máy**, xuất từ tracker (hoặc từ sự kiện `PROCESS/CREATE`), một dòng cho mỗi tiến trình:
   `host, proc_uuid, parent_uuid, created_t, terminated_t (nếu có), image_path, parent_image_path, command_line, principal, pid, first_seen_t, last_seen_t`.
   Định dạng Parquet hoặc CSV nén; phạm vi: đúng các host/ngày nằm trong cohort mà Nguyễn đã dựng shards (nói rõ danh sách host, ngày). Ví dụ một dòng lấy từ `sample_ecar.json`: `CREATE`, `actorID` = cha, `objectID` = con (`proc_uuid`), `properties.command_line`, `properties.image_path` (con), `properties.parent_image_path` (cha).
   *Ý nghĩa:* DL cần với mỗi sự kiện biết tiến trình nào làm và cha là ai tại thời điểm đó (chỉ bằng chứng `< t`). Chỉ mục graph SQLite cũ của Nguyễn chỉ có "first-seen" và không có dòng lệnh đầy đủ; bảng này khắc phục điều đó.
6. **Thống kê độ phủ của tracker theo host (và nếu được theo ngày, theo nhãn):** `query_count, has_actor_metadata, actor_metadata_missing, actor_uuid_missing, has_parent, parent_missing, parent_conflict, actor_expired, evicted_count, pid_reuse_conflict_count` (đây là `tracker.stats` trong `process_context_tracker.py`). *Ý nghĩa:* cho biết bao nhiêu sự kiện thực sự có ngữ cảnh. Lâm đo thử trên một máy được 100% nhưng chỉ 53 actor; cần số toàn corpus. Xin nói rõ `pid_reuse_conflict_count` lớn (Lâm thấy ~40,700 trên một máy 6 ngày) có phải bình thường không.
7. **Cách truy vấn ngữ cảnh tại một thời điểm cho sự kiện không phải PROCESS** (FILE, REGISTRY, MODULE, FLOW nếu còn dùng): chữ ký hàm, đầu vào cần (`hostname, actorID, timestamp`), và xác nhận gọi `get_context_tokens` trực tiếp (bỏ qua `tokenize_record`) là đúng ý. *Ý nghĩa:* tokenizer bỏ qua FLOW nên Lâm gọi trực tiếp; cần xác nhận không trái thiết kế.

## P1 — Hợp đồng DL (tối thiểu, để Lâm biết đơn vị mẫu)
8. **Bản mô tả hợp đồng đầu vào DL theo Nguyễn**, tối thiểu trả lời: (a) mẫu DL là gì (một chuỗi sự kiện host theo máy/cửa sổ thời gian nào, độ dài tối đa, padding); (b) loại sự kiện nào được chọn (PROCESS/CREATE, FILE, REGISTRY, ...); (c) mỗi sự kiện đưa trường nào vào (`app_family`, `image_dir_class`, `delta_t`, thêm dòng lệnh/cha?), thứ tự cột và từ điển; (d) nhãn mẫu = nhãn nào (OR nhãn sự kiện?); (e) thời điểm quyết định (online hay theo cửa sổ). Có thể chỉ là `input_schema.json` hoặc vài dòng. *Ý nghĩa:* "hợp đồng" ở đây là thỏa thuận giữa hai nhánh về đơn vị mẫu, trường vào và split; không có nó Lâm không thể chuyển BiLSTM/Mixed-Type từ chuỗi flow sang chuỗi sự kiện host đúng ý Nguyễn.

## P2 — Dataset mới (THEIA, ATLASv2) và fine-tune
9. **Có adapter nào đưa THEIA/ATLASv2 về sự kiện giống eCAR chưa?** Nếu có, xin mã/mô tả ánh xạ (ATLASv2: `endpoint.event.procstart` → PROCESS/CREATE, `process_cmdline`, `parent_path`, `process_hash`; THEIA: `EVENT_EXECUTE`, `parentSubject`) và cách xử lý `ACTION_PROCESS_DISCOVERED`. *Ý nghĩa:* DL fine-tune trên dữ liệu mới cần sự kiện host cùng schema với OpTC; tránh hai nhánh làm hai adapter khác nhau.
10. **Khôi phục các báo cáo đã bỏ khỏi zip bản 04/11:** `ML/analyst/optc_theia_atlasv2_field_mapping_2026-10-24.md`, `parent_child_*_2026-10-26.md`, `parent_context_implementation_review_*`, `pipeline.md`, `ML/MENU.md` (nếu còn). *Ý nghĩa:* bản 30/10 có các tài liệu này và Lâm đã trích dẫn; nếu bị bỏ có chủ ý thì chỉ cần xác nhận.

## Việc Lâm cam kết làm
- Giữ nguyên khóa, mask và nhãn của Nguyễn; không chia lại; không dùng nhãn tiến trình cha làm đặc trưng.
- Mọi bảng Nguyễn gửi chỉ đọc; Lâm không sửa.
- Nêu rõ trong báo cáo: split theo sự kiện nên điểm đo nhận ra mẫu đã thấy; F1 của DL (theo cửa sổ) và LightGBM (theo sự kiện) không so trực tiếp.
