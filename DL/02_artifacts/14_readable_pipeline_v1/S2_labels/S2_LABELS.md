# S2 — Nhãn: nhị phân và đa nhãn (multi-label)

## Mục đích
Gom về một chỗ: nhãn được gán thế nào ở từng mức (flow, event host, cửa sổ), và bảng nhãn đa nhãn theo tactic ATT&CK mà thầy gợi ý thay cho nhãn 0/1.

## Nguồn
- A New Hope (ACSAC 2025 workshop CSET): nhãn host (process) và nhãn network (flow tới C2). Lấy từ `D:\UIT\KLTN\KLTN-main\a_new_hope_for_darpa_optc\labelling\`.
- Nhật ký red team của DARPA (`OpTCRedTeamGroundTruth.pdf`): các bước tấn công có giờ, dùng để dựng nhãn tactic (STEP 12B).

## Bốn mức nhãn
Xem `label_rules.csv`. Tóm tắt:
| Mức | Nhãn | Ai gán | Hạn chế chính |
|---|---|---|---|
| Flow (network) | 0/1 | A New Hope: IP/domain C2 + giờ, kiểm tay | Bro không thấy traffic nội bộ nên thiếu di chuyển ngang |
| Event (host) | 0/1 | A New Hope: process độc hại + process con | Nhãn theo process, event vô hại của process bị chiếm cũng bằng 1 |
| Window (host, 15 phút), nhị phân | 0/1 | pipeline: có ≥ 1 flow độc hại | Đơn vị mà model network thấy |
| Window, đa nhãn | 11 cột 0/1 | STEP 12B (nhóm tự dựng) | Ánh xạ bước → tactic là đề xuất chưa thẩm định |

## File trong thư mục này
| File | Nội dung |
|---|---|
| `label_rules.csv` | Quy tắc, nguồn, đầu ra, hạn chế của bốn mức nhãn |
| `host_malicious_processes.csv` | 640 dòng `(scenario, hostname, pid, start_edt, end_edt)`: process độc hại theo A New Hope (SC1 461, SC2 111, SC3 68; 31 host) |
| `network_malicious_flows_summary.csv` | Flow độc hại theo `(scenario, host, IP đích, cổng đích)`: số flow, giờ đầu, giờ cuối (UTC). Tổng 29,311 flow |
| `stage_steps_red_team.csv` | 138 bước tấn công nhập tay từ nhật ký red team: giờ EDT, tactic, đệm trước/sau, ghi chú |
| `tactic_definitions.csv` | 11 cột tactic: mã, tên, ID ATT&CK (TA00xx), ý nghĩa |
| `window_labels_multilabel.csv` | **Bảng nhãn đa nhãn**: 788 dòng, mỗi dòng một `(scenario, host, cửa sổ 15 phút)` |

## Bảng đa nhãn: cách đọc `window_labels_multilabel.csv`
Mỗi dòng có: `scenario, host, window_start_utc, window_start_edt`, 11 cột 0/1 (`IA, EX, PE, PR, DE, CA, DI, LM, CO, C2, EXF`), `n_tactics`, `n_host_mal_events` (event host độc hại trong cửa sổ), `n_net_pos_flows` (flow mạng độc hại trong cửa sổ), `step_detail` (nhật ký chi tiết, thô hay không có), hai cờ kiểm tra.

Ví dụ `sysclient0051`, cửa sổ 10:45 EDT: `PE=1, PR=1, DE=1, CA=1, C2=1`, 1,052 event host độc hại, 172 flow mạng độc hại.

Cách dựng (STEP 12B): mỗi bước trong `stage_steps_red_team.csv` gán tactic cho mọi cửa sổ giao với `[t−60s, t+300s]`; cửa sổ có flow độc hại thêm `C2`. Script: `01_code/pipeline/12b_stage_labels.py`.

## Số liệu của bảng đa nhãn
| Tactic | Số cửa sổ |
|---|---:|
| C2 | 747 |
| LM | 64 |
| EX | 37 |
| DI | 16 |
| PR, DE | 12 mỗi loại |
| CA | 8 |
| IA | 7 |
| PE, CO | 6 mỗi loại |
| EXF | 3 |
Chỉ **90 cửa sổ** có tactic ngoài C2, rải trên 30 host. Đề xuất gộp 5 nhóm (IA+EX, PE+PR+DE+CA, DI+CO+EXF, LM, C2) để huấn luyện.

## Cần lưu ý trước khi dùng làm nhãn huấn luyện
1. Ánh xạ bước → tactic **chưa được thẩm định** (cần thầy hoặc bạn Nguyễn xem lại).
2. 20/27 cửa sổ host độc hại của SC3 không có bước nhật ký tương ứng; nên **che (mask) khỏi loss** thay vì đoán nhãn.
3. Nhãn mạng của A New Hope (29,311 flow) nhiều hơn số flow dương trong bảng đã ghép (24,721); xem S1.

## Đầu ra này đi đâu tiếp
- Nhãn flow → S4/S5 (nhãn của mẫu cửa sổ).
- Bảng đa nhãn → chưa dùng để train; cần nối với mẫu cửa sổ của nhánh network và đặc trưng host (S6) trước.
