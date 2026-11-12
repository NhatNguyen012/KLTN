# STEP 17E — Fusion v2: thêm cách gộp event→cửa sổ "số event vượt ngưỡng" (`count`)

Ngày: 2026-10-08. Mã: `01_code/pipeline/17e_fusion_v2_count_aggregator.py` (chạy bằng `.venv-host`, vài giây, không đọc dữ liệu thô, không cần ổ E:). Dữ liệu vào: `17_host_retrain_v1/window_scores_host.csv` + bảng fusion S9 seed_1. Không sửa artifact cũ.

> **TEST đã được mở lần thứ HAI.** Lần một là STEP 17d. Mọi kết quả dưới đây là thăm dò sau khi đã xem TEST của v1, không phải kết quả chốt. Cách gộp và ngưỡng vẫn chọn trên VAL; phần "quét ngưỡng count" (mục 4) dùng TEST trực tiếp và chỉ là chẩn đoán.

## 1. Thiết lập
- v1 = {`max`, `p99`, `frac` (tỉ lệ event vượt ngưỡng)} đúng như 17d. v2 = v1 + `count` (= `n_above_thr`, số event vượt ngưỡng event-level). Lưu ý: `frac` đã có từ v1 và không được chọn, nên điểm mới thực sự của v2 chỉ là `count`.
- Cách gộp chọn trên VAL theo F1 của host-only cho từng nhãn (`y_net`, `y_host`); ngưỡng/trọng số/stacking chọn trên VAL. Với `count`, average dùng log1p/log1p(max VAL) để đưa về [0,1]; stacking dùng log1p(count) (chỉ thống kê VAL).
- Kiểm tra: phần v1 của 17e khớp từng số với 17d/STEP 17 (ví dụ LightGBM `y_net`: chỉ network 0.962, chỉ host/OR/stacking 0.975).

## 2. Kết quả: VAL không chọn `count`, nên v2 = v1
F1 host-only trên VAL theo cách gộp:
| Model | Nhãn | max | p99 | frac | **count** | Được chọn |
|---|---|---:|---:|---:|---:|---|
| LightGBM | `y_net` | 0.974 | 0.932 | 0.881 | 0.886 | max |
| LightGBM | `y_host` | 0.492 | 0.425 | 0.464 | 0.472 | max |
| XGBoost | `y_net` | 0.951 | 0.932 | 0.872 | 0.867 | max |
| XGBoost | `y_host` | 0.506 | 0.425 | 0.462 | 0.466 | max |

`count` thua `max` trên VAL ở cả bốn trường hợp ⇒ v2 chọn lại `max`, mọi số TEST (chỉ network / chỉ host / OR / average / stacking) **giống hệt v1** (file `fusion_v1_vs_v2_table.csv`, `fusion_results_v1_vs_v2.json`). **SC3 `sysclient0051` vẫn bị bỏ sót 4/4 cửa sổ** (`sc3_sysclient0051_windows.csv`).

## 3. SC3 `sysclient0051`: `count` có tách được không?
Số event vượt ngưỡng của 4 cửa sổ tấn công (`y_net`=1): LightGBM 668 / 360 / 610 / 212; XGBoost cùng giá trị. Nhưng cùng host có cửa sổ **benign** 24/9 10:00 với `count` = 265 (LightGBM) và 310 (XGBoost), cao hơn cửa sổ tấn công 11:15 (212). Vậy ngay trong host này `count` không phân tách sạch bằng một ngưỡng. Cửa sổ 25/9 10:30 có `y_net`=0 nhưng `y_host`=1 (421 event vượt ngưỡng, 5,120 event độc hại theo nhãn host). Các cửa sổ "implant chạy yên" 11:30–14:00 có `count` = 0 (riêng LightGBM 13:30 và 13:45 có 1 và 7) nên không bắt được bằng cách gộp nào.

## 4. Chẩn đoán (dùng TEST, KHÔNG dùng để chọn ngưỡng): quét ngưỡng `count`
File `count_threshold_sweep_DIAGNOSTIC.csv`. Nhãn `y_net`, TEST 509 cửa sổ (81 dương):
| Ngưỡng count ≥ | SC3 0051 bắt (LightGBM / XGBoost) | TEST TP / FP (LightGBM) | F1 (LightGBM / XGBoost) |
|---:|---|---|---|
| 50 | 4/4 / 4/4 | 81 / 22 | 0.880 / 0.876 |
| 100 | 4/4 / 4/4 | 81 / 21 | 0.885 / 0.885 |
| 150 | 4/4 / 4/4 | 81 / 14 | 0.921 / 0.900 |
| 200 | 4/4 / 4/4 | 13 / 10 | 0.250 / 0.250 |
| 250 | 3/4 / 3/4 | 11 / 6 | 0.225 / 0.220 |

Đọc kết quả:
1. Với ngưỡng thấp (≤150), `count` **bắt đủ 4/4 cửa sổ SC3** nhưng đổi lại 14–22 FP trên TEST (so với 0 FP của `max`), F1 tổng 0.88–0.92, thấp hơn 0.975 của `max`. Số FP này còn là cận dưới vì benign trong tập cửa sổ chỉ là mẫu (mục 5).
2. Ở ngưỡng 200 trở lên, recall tụt từ 81 xuống 13 cửa sổ dương. Trung vị `count` của cửa sổ `y_host`=1 trên TEST là 180 (`count_distribution.csv`), tức nhiều cửa sổ dương tập trung quanh ~180 event. Chưa kiểm lý do (có thể là cửa sổ beacon cùng template); không kết luận.
3. Trên VAL, `count` ≥150 chỉ đạt F1 0.83 (`y_net`), nên quy tắc "chọn trên VAL" không chọn nó. Đây là lý do hợp lệ về phương pháp, không phải lỗi ngưỡng.

## 5. Kết luận và giới hạn
- **Kết luận có căn cứ:** thêm `count` vào danh sách chọn trên VAL **không đổi** kết quả fusion; SC3 vẫn 0/4 theo quy trình chuẩn. Giả thuyết trong STEP 17 ("`count` có vẻ phù hợp hơn cho SC3") **chỉ đúng một phần**: về chẩn đoán `count` ≥150 bắt đủ SC3, nhưng phải trả bằng 14–22 FP trên TEST, và không tách sạch ngay trong `0051` (cửa sổ benign 24/9 10:00 có 265).
- **Không kết luận được** `count` là cách gộp tốt hơn: chỉ một host SC3 (4 cửa sổ dương), 1 seed, 1 split; ngưỡng ở mục 4 chọn nhìn TEST nên lạc quan; TEST mở lần hai.
- Benign chỉ là mẫu 2 cửa sổ mỗi host-ngày ⇒ FP thật ở mức cửa sổ cao hơn con số trên (cần việc C).
- `sysclient0351` (SC3) vẫn nằm ở TRAIN ⇒ chưa phải thử nghiệm kịch bản chưa thấy (cần việc B).
- Bước hợp lý tiếp theo (chưa làm): B (giữ cả hai host SC3 ngoài TRAIN) và C (tập benign đầy đủ/trọng số) để đo FP thật; sau đó mới có cơ sở quyết có làm D (fusion mức đặc trưng) hay không. Việc A cho thấy host **có thông tin** ở SC3 (event-level) nhưng chưa có cách gộp event→cửa sổ nào được chọn hợp lệ trên VAL để khai thác nó.

## 6. Tệp
`fusion_v1_vs_v2_table.csv`, `fusion_results_v1_vs_v2.json`, `sc3_sysclient0051_windows.csv`, `count_distribution.csv`, `count_threshold_sweep_DIAGNOSTIC.csv`, `run_log.txt`.
