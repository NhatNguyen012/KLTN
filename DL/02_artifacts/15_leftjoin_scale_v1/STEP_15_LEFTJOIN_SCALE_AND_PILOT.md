# STEP 15 — Biến thể left join: đo quy mô (bước 1) và pilot suy luận (bước 2)

Ngày: 2026-10-07. Script: `01_code/pipeline/15_count_bro_conn_rows.py`, `15_leftjoin_inference_pilot.py`. Không train lại, không sửa shard/artifact cũ.

## Câu hỏi
Bảng flow hiện tại chỉ giữ flow **có bản ghi eCAR-Bro**. Ở SC3, `sysclient0051` có 488 flow độc hại trong Bro nhưng chỉ 163–173 flow có trong bảng (323 flow thiếu không có trong eCAR-Bro thô, phần lớn là `REJ` tới cổng 8080). Nếu giữ cả những flow này (left join, `app_family = <MISSING>`), model có bắt được SC3 tốt hơn không?

## Bước 1 — Quy mô: left join sẽ lớn cỡ nào
Đếm số dòng Bro `conn.log` (313 file, 14.3 GB nén, 492 giây), so với bảng đã ghép (`conn_rows_vs_joined_by_day.csv`):

| Ngày (UTC) | Dòng conn.log | Bảng đã ghép | Gấp |
|---|---:|---:|---:|
| 17/9 | 29,201,419 | 16,965,823 | 1.7 |
| 18/9 | 30,161,280 | 10,198,242 | 3.0 |
| 19/9 | 31,757,451 | 17,806,180 | 1.8 |
| 20/9 | 21,695,847 | 670,704 | 32.3 |
| 21/9 | 41,090,585 | 14,748,316 | 2.8 |
| 22/9 | 40,291,166 | 14,722,876 | 2.7 |
| 23/9 | 38,348,207 | 12,653,852 | 3.0 |
| 24/9 | 34,471,926 | 4,264,024 | 8.1 |
| 25/9 | 23,135,463 | 15,738 | 1,470 |
| **17–25/9** | **290,153,344** | **92,045,755** | **3.15** |
(Các ngày 12–16/9 có thêm 109 triệu dòng nhưng không nằm trong pipeline hiện tại.)

Ước tính: left join toàn bộ 17–25/9 cho **tối đa ~290 triệu dòng, gấp ~3.2 lần** hiện tại (đây là cận trên vì `conn.log` còn gồm cả traffic của máy chủ không thuộc 743 host). Shard hiện tại 4.4 GB mỗi seed (85.6 triệu event) sẽ lên **khoảng 14 GB mỗi seed** (4.4 × 3.15); thời gian train tăng cùng tỉ lệ. Đây là lý do việc này nặng: không phải thêm vài flow mà là đổi quy mô và bản chất dữ liệu benign.

## Bước 2 — Pilot suy luận (model đã train, không train lại)
Model: Mixed-Type bỏ `app_family`, seed_1 (`05_models/10_random_seed1_v1/mixed_v2_noapp_seed1`), ngưỡng chọn trên VAL = 0.00092. Cửa sổ: `sysclient0051` (host SC3 trong TEST) ngày 25/9.

Ba biến thể mỗi cửa sổ: **V0** = flow đã ghép (đúng dữ liệu hiện tại); **V1** = V0 + flow độc hại bị loại; **V2** = mọi flow Bro của host trong cửa sổ (left join thật).

**Kiểm tra harness:** điểm V0 khớp `test_predictions.csv` (ví dụ 7.36×10⁻⁶ so với 7.33×10⁻⁶; 1.433×10⁻⁵ so với 1.431×10⁻⁵; một cửa sổ 15:00 UTC lệch: 7.0×10⁻⁶ so với 1.9×10⁻⁵, nhiều khả năng do cách chọn chunk).

| Cửa sổ (UTC) | Số flow V0 → V1 → V2 | p(V0) | p(V1) | p(V2) |
|---|---|---:|---:|---:|
| 14:15 | 3 → 3 → 3 | 9.6×10⁻⁶ | 9.6×10⁻⁶ | 9.6×10⁻⁶ |
| 14:45 | 60 → 172 → 174 | 7.4×10⁻⁶ | 4.4×10⁻⁶ | 4.5×10⁻⁶ |
| 15:00 | 65 → 203 → 203 | 7.0×10⁻⁶ | 4.2×10⁻⁶ | 4.2×10⁻⁶ |
| 15:15 | 34 → 101 → 103 | 1.4×10⁻⁵ | 4.7×10⁻⁶ | 4.7×10⁻⁶ |
Ngưỡng VAL = 9.2×10⁻⁴. Cả ba biến thể đều **thấp hơn ngưỡng hơn 60 lần**; thêm flow bị loại làm điểm giảm nhẹ, không tăng.

**Phát hiện kèm theo:**
1. Cả ngày 25/9, `sysclient0051` chỉ có **515** flow xuất phát từ nó trong Bro, trong đó **488** là flow độc hại. Các cửa sổ trước tấn công (11:00–12:45 UTC) có **0 flow**. V2 chỉ thêm 0–2 flow so với V1: **cửa sổ SC3 gần như chỉ gồm flow độc hại**, không có "benign nền" bị thiếu.
2. Trong bảng đã ghép, 159/163 flow dương của `0051` đã là loại `REJ` tới :8080. Tức model **đã nhìn thấy** loại flow này trong dữ liệu hiện tại và vẫn chấm điểm ~10⁻⁵. Thêm nhiều flow cùng loại không đổi bản chất.
3. Ngày 25/9, **499 host** có flow nhãn benign tới IP kẻ tấn công SC3 `53.192.68.50` (5,563 flow, chủ yếu cổng 80, `RSTO`/`REJ`, khoảng 13:53–13:59 UTC), trong khi chỉ 2 host có flow nhãn độc hại (188 flow). Rất có thể đây là hành vi kiểm tra cập nhật của notepad++ trên mọi máy (cập nhật bị chiếm); chỉ hai máy thật sự chạy bản cập nhật. Tín hiệu mạng của hai nhóm giống nhau; điểm phân biệt thật nằm ở host (`gup.exe` sinh ra file `.exe` trong Temp, xem STEP 12C).

## Kết luận
- Bằng chứng hiện có **không ủng hộ** việc build left join đầy đủ để cứu SC3: flow bị loại cùng loại với flow model đã thấy và chấm thấp; cửa sổ SC3 không thiếu ngữ cảnh benign; và nhiều host benign tạo traffic gần giống.
- **Giới hạn của pilot:** đây là suy luận trên model chưa từng train với cửa sổ V1/V2, chỉ 1 host, 4 cửa sổ, 1 model; không chứng minh retrain cũng vô ích, nhưng cho thấy kỳ vọng thấp.
- Left join vẫn có giá trị cho một mục đích khác: benign hiện gần như chỉ là flow Firefox (99.7–99.9% các ngày 17–24/9), dữ liệu thực tế hơn cần đưa mọi flow vào. Đó là một thí nghiệm riêng về độ tin cậy của benchmark, tốn ~3 lần tài nguyên, không nên làm trước khi có kết quả host.

## Đề xuất
Không build left join ở thời điểm này. Ưu tiên (1) điểm dự đoán nhánh host của Nguyễn trên split host-disjoint, (2) 4 run Kaggle "beacon chưa từng thấy" (06c/07c).
