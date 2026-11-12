# S6 — Nhánh host: đặc trưng hành vi theo cửa sổ 15 phút (từ eCAR thô)

## Mục đích
Cho nhánh host một đơn vị tương ứng với nhánh network: **một dòng mỗi (host, cửa sổ 15 phút)**, để hai nhánh ghép được theo `(hostname, cửa sổ)`.

**Phạm vi:** đây là phần do Võ Ngọc Hoàng Lâm dựng trong STEP 12C để làm baseline và thăm dò SC3. Nó **không phải** mô hình host của Nguyễn Nhật Nguyễn (LightGBM, XGBoost, RF, GraphSAGE). Kết quả và đường dẫn của nhánh đó nhóm chưa cung cấp (xem S9).

## Đầu vào
eCAR thô của từng host-ngày: `E:\host-begnin\2019-09-22\…` (TRAIN, 150 host mẫu) và `E:\host-malicious\2019-09-{23,24,25}\…` (VAL và TEST, 78 và 69 host). Mỗi file là một host một ngày, mỗi dòng một event (S0).

## Cách làm (script `01_code/pipeline/12c_host_window_features.py`)
Đọc từng file một lần, **chỉ đếm** (không lưu nội dung event), theo cửa sổ 15 phút giờ EDT:
- đếm theo loại event (tổng, `FLOW START`, `PROCESS CREATE`, `THREAD REMOTE_CREATE`);
- đếm hành vi đáng chú ý: tiến trình chạy từ thư mục ghi được, tiến trình có cha là `lsass.exe`, ghi registry ở khóa Run/Services/SAM, tạo file thực thi trong thư mục ghi được, dòng lệnh đáng ngờ;
- ghi lại các cặp `cha>con` của tiến trình mới (để tính độ "lạ" so với TRAIN ở bước sau).

Quét 591 file, 2.25 tỷ event, 133.5 GB, 78 phút trên ổ HDD.

## Đầu ra trong thư mục này
| File | Nội dung |
|---|---|
| `host_window_features.csv` | **51,101 dòng**, mỗi dòng một `(host, cửa sổ)`; 15 cột (tên và ý nghĩa ở `fields_host_window.csv`); có `n_host_mal_events` lấy từ nhãn A New Hope |
| `fields_host_window.csv` | Ý nghĩa từng cột |
| `sample_host_window.json` | Hai cửa sổ: cửa sổ tấn công SC3 của `sysclient0051` (10:45 EDT, 25/9) và một cửa sổ bình thường cùng giờ ở host TRAIN khác (22/9) |
| `sample_host_malicious_events.json` | Bốn event eCAR độc hại thật của `sysclient0051` (SC3): process `cKfGW.exe` sinh từ trình cập nhật notepad++, `cmd.exe net user admin /add` có cha là `lsass.exe`, ghi khóa registry Run, `THREAD REMOTE_CREATE` |

Dữ liệu đầy đủ theo từng file nhỏ (591 CSV, kèm `pairs_json`) ở `02_artifacts/12c_host_features_v1/features/`.

## Kết quả đã biết (STEP 12C)
- Luật tay 4 đặc trưng báo nhầm ~540 cửa sổ benign trên TEST, nên **không dùng được một mình** (precision 0.9–1.8%).
- Chỉ `n_cmd_susp` sạch nhưng rất hiếm. Chi tiết: `02_artifacts/12c_host_features_v1/STEP_12C_FUSION_BASELINE_A.md`.

## Hạn chế
- Nhãn `n_host_mal_events > 0` là "có event độc hại bất kỳ", gồm cả cửa sổ implant chạy yên.
- Chỉ 330/434 host TRAIN có file log ngày 22/9; mẫu 150 host chỉ đại diện một phần.
- Chỉ là đặc trưng đếm thô; chưa phải đồ thị provenance hay vector học được.

## Thông tin từ slide báo cáo định kỳ của Nguyễn (`KLTN - Định kỳ.pdf`)
Đây là phần thông tin **đã được Nguyễn công bố** về nhánh host (nhãn ghi theo slide, chưa kiểm chứng độc lập):
| Mục | Nội dung trong slide |
|---|---|
| Đơn vị dự đoán | **Từng event eCAR** (TEST random có 1,249,689 event), không phải cửa sổ |
| Đặc trưng | Vector thưa từ token: object, action, principal, image_path, file_path, command_line, parent_image_path; thêm token provenance (`prov::parent::...`) và token thời gian (`tmp::proc::file_create::10s::bucket...`); `vocab.json` 9,048 token tạo từ TRAIN. Đã bỏ: actorID, hostname, id, objectID, pid, ppid, tid, timestamp, acuity_level, size |
| Cửa sổ lấy mẫu | 30 phút cho ngày benign; toàn bộ cửa sổ bị tấn công của host malicious |
| Split 1 (random) | **Xáo trộn event** (giữ 100% positive), chia 75/10/15, tỉ lệ benign:malicious 30:1; TEST: LightGBM F1 0.95, Recall 0.92, FP 446, FN 3,189; XGBoost F1 0.95, FP 786; RF F1 0.91, FP 1,505, FN 5,334 |
| Split 2 (walk-forward) | Chia theo thời gian trong từng scenario; SC1 → SC2 → SC3 (dữ liệu scenario trước thành TRAIN của scenario sau) |
| Walk-forward, XGBoost | SC1 F1 0.91, Recall 0.865; SC2 F1 0.93, Recall 0.998; **SC3 F1 0.2, Recall 0.24** (TP 5,150, FN 15,686, FP 26,775) |
| Nguyên nhân lỗi (theo Nguyễn) | Nhãn theo provenance (event con của process độc hại cũng nhãn 1) nên có event giống hệt nhau nhưng khác nhãn; ở SC3 event độc hại giống hoạt động phần mềm/dịch vụ bình thường; concept shift (Chrome phần lớn malicious ở TRAIN nhưng toàn benign ở TEST) |

Hệ quả cho khóa luận:
1. **Nhánh host của Nguyễn cũng không bắt được SC3** (F1 0.2) khi đánh giá theo thời gian. Fusion không thể mặc định cứu được SC3 nhờ host; phải đo thật và nói rõ.
2. **Hai cách split của Nguyễn đều không tách theo host** (random trộn event; walk-forward chia theo thời gian). Điểm của nhánh host trên host nằm trong TRAIN là "đã thấy", nên không ghép được với split host-disjoint của nhánh network (xem phân tích chồng lấn ở S3). Nhờ Nguyễn train lại trên split host-disjoint của S3.
3. **Đơn vị khác nhau:** Nguyễn dự đoán theo event. Để ghép phải gộp event theo `(hostname, cửa sổ 15 phút)` (ví dụ max hoặc tỉ lệ event có xác suất vượt ngưỡng). Cần file dự đoán có `hostname`, `timestamp`, `prob`, `label` từng event.
4. Nhận xét về nhãn của Nguyễn khớp với phát hiện ở STEP 12C: nhãn host "có event độc hại bất kỳ" gồm cả event vô hại của process bị chiếm.

## Đầu ra này đi đâu tiếp
Ghép với điểm network ở S9. Khi có điểm dự đoán của nhánh host của Nguyễn, thay `s_host` bằng `p_host` thật.
