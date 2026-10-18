# HANDOFF — bắt đầu nhánh Context-Aware Fusion (2026-10-03)

> Đọc sau `CLAUDE.md` và `HANDOFF_STEP10_11.md`. Chưa có thiết kế fusion nào; file này chỉ gom **sự thật đã kiểm chứng** và **câu hỏi mở** để bắt đầu. Đề tài: *Multi-Source Context-Aware Framework for APT Detection* — Host ML agent + Network DL agent → Context-Aware Fusion.

## 1. Hai nhánh hiện có
| Nhánh | Người | Mô hình | Kết quả đã biết |
|---|---|---|---|
| Network DL | Võ Ngọc Hoàng Lâm | BiLSTM, Mixed-Type Self-Attention (chuỗi flow của host trong 15 phút) | 3 seed split ngẫu nhiên: F1 TEST BiLSTM 0.969 / Mixed-Type 0.988; bỏ `app_family`: 0.959 / 0.957; luật "có powershell" 0.976. Xem `02_artifacts/10e_retrain_analysis_v1/STEP_10E_3SEED_CONCLUSIONS.md` |
| Host ML | Nguyễn Nhật Nguyễn | LightGBM, XGBoost, Random Forest; GraphSAGE 2-hop (theo todolist của nhóm, **chưa kiểm chứng trong repo này**) | F1 LightGBM 0.9533, XGBoost 0.9492, RF 0.9109; sau GraphSAGE 2-hop: 0.98 (XGBoost/LightGBM), 0.96 (RF). Lưu ý: nhãn host bám theo process tree của agent nên metric dễ bị ảnh hưởng tương tự (xem bài *A New Hope* §4) |

## 2. Dữ liệu chung: khóa ghép, thời gian, phạm vi (đã đo)
- **Khóa ghép tự nhiên:** `(hostname, cửa sổ 15 phút)`. Network sample đã dùng đúng đơn vị này (`window_start = floor(ts/900)*900`, UTC epoch). Mốc 15 phút khớp với giờ EDT (UTC − 4 là bội số của 15 phút), nên cùng một cửa sổ ở hai nguồn.
- **Múi giờ:** eCAR dùng `-04:00` (EDT); Bro/joined dùng epoch UTC. Mọi giờ scenario trong báo cáo quy về EDT.
- **Cầu nối host ↔ network:** eCAR-Bro (`properties.bro_uid` = Bro `uid`), 92.1M record, chỉ có `object=FLOW`. Network hiện có `app_family` từ `image_path` của eCAR-Bro.
- **Phạm vi host:** log host có **625 host** (4,695 file host-ngày); dữ liệu mạng có **743 host**. Chung (supervised) **620 host**; **123 host chỉ có log mạng** (ID 26–50, 76–100, 126–150, 176–200, 226–250, 6.42M flow, bị `unmatched_split`); **5 host chỉ có log host** (`0341, 0346, 0389, 0395, 0440`). Fusion cần quy tắc cho host thiếu một nguồn.
- **Nhãn hai cấp khác nhau rất xa:** nhãn host = mọi event của process độc hại và process con (hàng chục nghìn event/host); nhãn mạng = kết nối tới C2 (vài trăm đến vài nghìn flow/host). Ví dụ `sysclient0351` (SC3): 19,378 event nhãn host nhưng 26 flow positive. Nhãn host nằm sẵn trong cột `label` của file `E:\host-malicious\…` và trong file ground truth `E:\a_new_hope_for_darpa_optc\…`.
- **Host bị tấn công:** 29 (SC1 17, SC2 10, SC3 2); bảng đầy đủ và thời gian EDT ở `02_artifacts/11_dataset_overview_v1/scenario_hosts_29.csv`, tổng quan ở `STEP_11_DATASET_OVERVIEW.md`.

## 3. Điều Network DL không làm được (lý do cần fusion)
- **SC3** (`sysclient0051`, 4 window): network-only bắt 0–3/4 window; flow là chuỗi kết nối bị từ chối (`REJ`) tới `53.192.68.50:8080`, giống noise benign; process phát sinh là `biguwcmnsucig.exe` (không có trong từ điển TRAIN, thành `<UNK>`).
- Bro không ghi traffic nội bộ nên **không thấy di chuyển ngang** (pivot WMI/RDP); phần này chỉ host (eCAR) thấy.
- **Đề xuất ngữ cảnh host cần lấy thêm:** process tree (tiến trình cha–con, ai sinh ra process lạ), command line, đường dẫn/hash file thực thi, user.
- Positive của mạng gần như toàn **beacon** (98% window, SC1 mỗi ~5 giây, SC2 mỗi ~30 giây); điểm cao khi bỏ `app_family` chủ yếu do beacon lặp, không chứng minh hiểu hành vi mới.

## 4. Câu hỏi mở cần quyết (chưa ai quyết)
1. **Mức fusion:** gộp ở mức feature (nối embedding host + network trong cùng cửa sổ), mức điểm (kết hợp xác suất của hai nhánh), hay mô hình có chú ý chéo?
2. **Đơn vị dự đoán:** window (host, 15 phút) hay host-level? Nhãn host-level dày hơn nhiều so với nhãn mạng; chọn nhãn nào làm đích?
3. **Host thiếu một nguồn:** 123 host chỉ có mạng, 5 host chỉ có host; mặc định đưa vào hay loại?
4. **Chia split:** phải host-disjoint theo hostname và dùng cùng mapping split cho cả hai nhánh (hiện nhánh Host dùng split gốc STEP 02 với 437/94/94 host; nhánh Network có thêm 3 split ngẫu nhiên 434/93/93).
5. **Tránh shortcut:** `app_family` (powershell) và beacon lặp sẽ lặp lại ở nhánh host; cần ablation tương tự.
6. **Baseline bắt buộc:** từng nhánh riêng, luật 1 dòng, và fusion đơn giản (trung bình/AND/OR) để chứng minh fusion có giá trị, đặc biệt ở SC3.

## 5. Gợi ý bước đầu
1. Đọc: `CLAUDE.md`, `HANDOFF_STEP10_11.md`, file này, `STEP_11_DATASET_OVERVIEW.md`, `STEP_11B_PIPELINE_INPUT_OUTPUT.md`.
2. Khảo sát nhánh Host: artifact host nằm ở `D:\UIT\KLTN\artifacts\` (`step03_host_vocab_*`, `step01b_host_profile`, `step02_label_split_v1_1`) và mã nguồn ở `D:\UIT\KLTN\KLTN_bootstrap_step01\`; hỏi người dùng về thư mục kết quả của Nguyễn (LightGBM/XGBoost/RF/GraphSAGE) vì chưa thấy trong repo này.
3. Đo mức chồng lấn cửa sổ hai nguồn (host nào/cửa sổ nào có cả log host và flow), trước khi thiết kế fusion.
4. Quy tắc CLAUDE.md vẫn áp dụng: output vào thư mục có số step mới (ví dụ `12_fusion_*`), report `STEP_XX_*.md` tiếng Việt, báo dung lượng và thời gian trước job nặng.
