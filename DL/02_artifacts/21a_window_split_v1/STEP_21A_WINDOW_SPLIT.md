# STEP 21A — Split cấp cửa sổ, phân tầng theo scenario (không host-disjoint)

Ngày: 2026-10-12. Mã: `01_code/pipeline/21a_window_stratified_split.py`. Chỉ tạo bảng ánh xạ và thống kê (vài giây); **chưa** fit preprocessing, chưa build shards, chưa train. Không sửa artifact cũ.

## 1. Yêu cầu và phạm vi
Theo yêu cầu của người dùng (2026-10-12): bỏ các thí nghiệm bỏ `app_family` / beacon chưa từng thấy; cần một bản có **đủ và chia đều các scenario tấn công** ở TRAIN/VAL/TEST, giống cách nhánh Host đang chia (không theo máy). Đây là **ngoại lệ có chủ ý** so với quy tắc "split luôn theo hostname" trong `CLAUDE.md`; các split host-disjoint (seed 1–3) vẫn giữ nguyên để so sánh.

## 2. Thiết kế
- Đơn vị: cửa sổ (hostname, 15 phút), 110,402 cửa sổ của 620 máy (từ manifest seed_1); mọi chunk của một cửa sổ nằm cùng một split.
- Tầng: cửa sổ dương theo scenario của máy; cửa sổ benign theo ngày. Mỗi tầng cắt 70 / 15 / 15 theo thứ tự băm sha256 (`KLTN_OPTC_WINDOW_STRATIFIED_V1|seed=k`, k = 1, 2, 3), tái lập được.
- Ra: `window_split_seed{1,2,3}.csv` (hostname, window_start_epoch, scenario, label, assigned_split), `summary_21a.json`.

## 3. Kết quả: cửa sổ dương theo scenario × split
| Scenario | Split cấp cửa sổ MỚI (train / val / test) | Host-disjoint seed_1 hiện có | Host-disjoint seed_2 | Host-disjoint seed_3 |
|---|---|---|---|---|
| SC1 | 43 / 9 / 9 | 45 / 10 / 6 | 37 / 18 / 6 | 45 / 10 / 6 |
| SC2 | 332 / 71 / 71 | 374 / 29 / 71 | 258 / 144 / 72 | 328 / 74 / 72 |
| SC3 | 4 / 1 / 1 | 2 / 0 / 4 | 2 / 0 / 4 | 2 / 0 / 4 |
Số cửa sổ dương theo scenario giống nhau ở cả 3 seed mới (chỉ khác cửa sổ nào vào split nào). Tổng mỗi split mới: train 77,281 cửa sổ (379 dương), val 16,561 (81), test 16,560 (81); khoảng 160 nghìn sample train, 34 nghìn sample val/test.

Ý nghĩa: ở split host-disjoint, SC3 (chỉ 2 máy) không bao giờ có mặt ở VAL và dồn 4/6 cửa sổ vào TEST; split mới đưa SC3 vào cả ba tập (4 / 1 / 1). Với 1 cửa sổ dương SC3 ở VAL và 1 ở TEST, số liệu riêng của SC3 chỉ có giá trị minh họa từng cửa sổ, không có ý nghĩa thống kê.

## 4. Hệ quả của việc bỏ ràng buộc host-disjoint (số đo được)
- 613 / 620 máy (seed_1) có cửa sổ ở **cả ba** split.
- Trong 81 cửa sổ dương của TEST (seed_1): **80** có cửa sổ dương của **cùng máy** ở TRAIN, **65** cách chưa tới 15 phút và **79** cách chưa tới 60 phút (seed_2: 79 / 69 / 78; seed_3: 81 / 72 / 80). Ở split host-disjoint con số này là 0 / 81.
- Beacon chạy liên tục nhiều cửa sổ liền nhau (SC2: khoảng 72 cửa sổ mỗi máy), nên cửa sổ TEST gần như là bản sao của cửa sổ kề bên trong TRAIN.
- **Kỳ vọng:** điểm TEST ở split này cao hơn hoặc bằng split host-disjoint (hiện F1 0.969–0.988 khi giữ `app_family`, nên chỗ để tăng chỉ khoảng 0.01–0.03); mức tăng thật phải chạy mới biết. Nhánh Host có số tương tự: Nguyễn split theo event đạt F1 0.953, bản retrain host-disjoint của nhóm đạt 0.827 (hai quy trình khác nhau nên không phải so sánh có kiểm soát).
- **Cách phát biểu trong báo cáo:** điểm ở split này đo khả năng nhận ra cửa sổ của máy và mẫu tấn công đã xuất hiện trong dữ liệu huấn luyện, không đo khả năng phát hiện trên máy chưa từng thấy.

## 5. Chưa làm (cần xác nhận trước khi chạy)
1. Fit preprocessing (từ điển category, mean/std, active feature) **chỉ trên TRAIN mới**: preprocess cũ (08b) làm việc theo hồ sơ từng máy nên không dùng trực tiếp được; cần script mới dựng từ joined parquet với bảng ánh xạ cửa sổ.
2. Build shards cùng định nghĩa sample (cửa sổ 15 phút, chunk ≤ 512, nhãn sample = có ≥ 1 flow dương): tham chiếu STEP 10C, ~4.4 GB và ~11–14 phút mỗi seed (3 seed ≈ 13 GB; ổ D: còn khoảng 165 GB). Thời gian fit preprocessing và validation chưa đo.
3. Validation (bảo toàn event/positive event, không rò rỉ preprocessing), rồi train trên Kaggle bằng notebook 06b / 07b với `DROP_APP_FAMILY = False` (bản đầy đủ, không có ablation).
