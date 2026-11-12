# STEP 45 — Kiểm tra nhánh DL trong `KLTN-main.zip` (bản 370 file) và thí nghiệm IL ATLASv2 của Nguyễn

Ngày: 2026-11-04. Chỉ đọc (giải nén vào thư mục tạm của phiên, không chạy mã của Nguyễn). Thay thế các nhận định về "hợp đồng DL" và "ngưỡng 0.245" ở cuối STEP 44 mục 6.

## 1. Zip hiện tại khác bản đã đọc ở STEP 43
`D:\UIT\KLTNv2\KLTN-main.zip` (56.8 MB, sửa 16:39 ngày 04/11) có **370 file**: `DL/`, `IL/dataset_1-ATLASv2/`, `Openstack/`, `ML/`, `docs/`. Bản ở STEP 43 chỉ 50 file (không có `DL/`, `IL/`, `Openstack/`). Vẫn **không có** các file P0 đã xin (`lgbm_metrics.json`, điểm theo sự kiện, `experiment_identity.json`, mask `*.split.gz`, bảng tiến trình, `DL_INPUT_CONTRACT.md`): gói `optc_host_ml_fusion_package.zip` chưa về máy này.

## 2. `DL/` trong zip là bản của ta
`DL/05_models/{bilstm,mixed}_v2_subsetB/best_model.pt` **trùng từng byte** với `05_models/v2_subsetB/` của ta (so bằng `cmp`); ngưỡng BiLSTM 0.99560546875, Mixed-Type 1.0. Nguyễn không train mô hình DL khác trong thư mục này. "Hợp đồng DL" Nguyễn mô tả (cửa sổ 15 phút, tối đa 512 sự kiện, `[app_family, proto, resp_port_class, image_dir_class]` + `delta_t_log1p`) chính là bản B của ta.

## 3. `proto` và `resp_port_class`
Đúng như Lâm nói: bản B đã bỏ các trường số đo của Bro (byte, packet, thời lượng…), `conn_state`, `service`, `has_missed_bytes`, `principal_class`; chỉ giữ 4 trường category + `delta_t`. README của Nguyễn (dòng 38) cũng nói vậy. Chỉ có `docs/Framework_Selection_Testbed.md` (dòng 76–92) ghi `proto`/`resp_port_class` "vẫn mang thông tin giao thức/port" và yêu cầu bundle triển khai giải quyết điểm lệch này: đó là lập luận của tài liệu testbed, không phải lỗi của bản B. Đính chính nhận định "mâu thuẫn L3/L4" ở STEP 44: chỉ là điểm cần thống nhất với Nguyễn nếu testbed cấm hẳn hai trường này.

## 4. "Ngưỡng 0.245" đến từ đâu
Từ **`IL/dataset_1-ATLASv2/` (Nguyễn tự chạy IL BiLSTM OpTC → ATLASv2, Run 12)**, không phải mô hình của ta. Run 12 báo: TEST ATLASv2 768 cửa sổ (20 dương) TP 17, FP 7, F1 0.7727, ngưỡng 0.2450; "OpTC F1 1.0000, BWT +5.13%".

## 5. Các điểm cần cảnh giác ở thí nghiệm IL của Nguyễn (đọc mã, chưa chạy lại)
1. **Tập OpTC test và replay buffer là dữ liệu tổng hợp, không phải OpTC thật.** `code/DL/preprocess/extract_optc_network_replay.py` dựng bằng hàm `generate_sequence` (mẫu viết tay: ví dụ `powershell_c2_443` với `delta_t` lấy từ `random.gauss(30, 5)`), cho cả 82 cửa sổ dương (chỉ lấy `sample_id`, host, số sự kiện từ `test_positive_samples.csv` của ta) và 250 cửa sổ âm, và cho 300 mẫu replay (60 dương, 240 âm). Test và replay cùng một bộ sinh mẫu nên "F1 1.0000, quên lãng bằng 0, BWT +5.13%" không đo khả năng nhớ OpTC thật và không so được với F1 0.988 của ta (34,413 cửa sổ thật). Chưa chạy mã để xác nhận từng dòng, nhưng cấu trúc mã là rõ.
2. **Nhãn ATLASv2 khác nhãn của ta.** Nguyễn dùng `LabelRefiner` (khớp IP/cổng C2 + mốc thời gian, gồm các điểm `.seeds` như `34.107.221.82:80`), còn **73 sự kiện dương**; ta dùng nhãn REAPr theo tiến trình (7,761 flow dương). STEP 42 cho thấy `34.107.221.82:80` là IP công cộng bị REAPr gán nhầm `root_cause`; Nguyễn coi nó là C2 nên một phần dương của Nguyễn có thể là duyệt web thường.
3. **Chia theo kịch bản** (TRAIN s1,s2,s3,m1,m2,m4; VAL m3,m5; TEST s4,m6), không chia trộn như thầy yêu cầu; ít dương (49/23/20 cửa sổ).
4. **Thiết kế lặp theo kết quả TEST.** Bảng Run 1–12 đánh giá cùng 768 cửa sổ TEST, mỗi lần đổi kiến trúc/pooling/dịch bias (Δb −5.42 rồi 60% = −3.25) sau khi xem lỗi trên S4/M6; checkpoint và ngưỡng của lần cuối có chọn trên VAL (`find_harmonic_domain_threshold`) nhưng việc chọn cấu hình thì đã nhìn TEST → số F1 0.7727 lạc quan, không phải ước lượng độc lập.
5. **Có so sánh "Zero-shot/trước IL"** (ngưỡng cố định 0.9956), trái quyết định của ta (bỏ so sánh trước/sau).
6. Khác kiến trúc: pooling Top-K, SupCon, replay 20%, 3 tầng learning rate; không phải freezing/mở dần thầy yêu cầu; mô hình gốc không đổi số tham số (78,698).

## 6. Hệ quả
- Không cần chờ "hợp đồng DL" nữa: nó là bản B hiện tại.
- Việc còn chờ từ Nguyễn: gói P0/P1 thật sự (zip trên máy Nguyễn).
- Nếu muốn dùng số của Nguyễn trong báo cáo, chỉ dùng phần host LightGBM sau khi kiểm file gốc; phần IL BiLSTM cần dựng lại replay/test OpTC từ dữ liệu thật trước khi trích.
