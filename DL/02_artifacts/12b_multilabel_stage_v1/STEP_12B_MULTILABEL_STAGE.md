# STEP 12B — Nhãn đa nhãn (multi-label) theo tactic ATT&CK cho cửa sổ (host, 15 phút)

Ngày: 2026-10-06. Script: `01_code/pipeline/12b_stage_labels.py`. Không cần ổ E:, không job nặng (đọc file local nhỏ, chạy vài giây).

## 1. Làm gì
Dựng bảng nhãn đa nhãn cho từng cửa sổ `(scenario, host, window 15 phút)` từ ba nguồn **local**:
1. `stage_steps_v1.csv`: 138 dòng do tôi nhập tay từ nhật ký red team `OpTCRedTeamGroundTruth.pdf` (mỗi dòng = một bước, giờ EDT, danh sách tactic, đệm trước/sau). **Ánh xạ bước → tactic là đề xuất của tôi, chưa ai thẩm định.**
2. Event eCAR độc hại của A New Hope (bản `corrected`, `*_evts_*.json.gz`): đếm số event độc hại mỗi cửa sổ.
3. Flow Zeek độc hại của A New Hope (`labelling/network/scenario-*/conn-*.log`): đếm flow dương mỗi cửa sổ; cửa sổ có flow dương được thêm nhãn C2.

Quy tắc: cửa sổ theo UTC epoch `floor(ts/900)*900` (giống pipeline network; EDT = UTC−4 là bội 15 phút nên khớp). Một bước tại thời điểm `t` gán tactic cho mọi cửa sổ giao với `[t−60s, t+300s]` (một số dòng có đệm riêng, ghi trong CSV). Bước kéo dài (agent chạy qua đêm) tách thành hai dòng: bước thời điểm (ví dụ LM) và dòng trạng thái chỉ có C2.

11 nhãn: IA, EX, PE, PR, DE, CA, DI, LM, CO, C2, EXF (xem `tactic_counts_v1.csv`).

Đầu ra: `window_labels_v1.csv` (788 cửa sổ), `tactic_counts_v1.csv`, `summary_12b.json`, `run_12b_stdout.txt`.

## 2. Kết quả
Số cửa sổ có nhãn từng tactic (SC1 / SC2 / SC3 / tổng):

| Tactic | SC1 | SC2 | SC3 | Tổng |
|---|---:|---:|---:|---:|
| Initial Access (IA) | 1 | 3 | 3 | 7 |
| Execution (EX) | 29 | 4 | 4 | 37 |
| Persistence (PE) | 1 | 3 | 2 | 6 |
| Privilege Escalation (PR) | 5 | 3 | 4 | 12 |
| Defense Evasion (DE) | 6 | 3 | 3 | 12 |
| Credential Access (CA) | 4 | 2 | 2 | 8 |
| Discovery (DI) | 10 | 5 | 1 | 16 |
| Lateral Movement (LM) | 37 | 25 | 2 | 64 |
| Collection (CO) | 1 | 5 | 0 | 6 |
| Command & Control (C2) | 81 | 657 | 9 | 747 |
| Exfiltration (EXF) | 0 | 3 | 0 | 3 |

- Tổng 788 cửa sổ: SC1 83, SC2 676, SC3 29. Chỉ **90 cửa sổ** có ít nhất một tactic ngoài C2, rải trên 30 host.
- Số nhãn mỗi cửa sổ: 0 nhãn = 31; 1 nhãn = 674 (hầu hết chỉ C2); 2 nhãn = 30; 3 nhãn = 41; 4–6 nhãn = 12. Cặp đồng xuất hiện nhiều nhất: LM+C2 (60), EX+C2 (36), EX+LM (28).
- **Nhãn quá hiếm để huấn luyện từng tactic riêng.** Đề xuất gộp 5 nhóm (số cửa sổ; số host):

| Nhóm | Gồm | SC1 | SC2 | SC3 | Tổng | Số host |
|---|---|---:|---:|---:|---:|---:|
| G1 | IA, EX | 29 | 5 | 4 | 38 | 19 |
| G2 | PE, PR, DE, CA | 8 | 8 | 4 | 20 | 7 |
| G3 | DI, CO, EXF | 10 | 10 | 1 | 21 | 7 |
| G4 | LM | 37 | 25 | 2 | 64 | 28 |
| G5 | C2 | 81 | 657 | 9 | 747 | 29 |

  G2 và G3 chỉ có 20–21 cửa sổ trên 7 host; với split host-disjoint thì dễ có fold không có mẫu của nhóm này. Cần leave-host-out hoặc leave-scenario-out thay vì một split cố định, và chỉ báo cáo kết quả từng nhóm kèm cảnh báo cỡ mẫu.

## 3. Phát hiện cần lưu ý
1. **Độ phủ nhãn giai đoạn thấp ở SC3.** Trong 27 cửa sổ SC3 có event độc hại, 20 cửa sổ **không có bước nhật ký tương ứng** (`host_mal_no_stage`): `sysclient0051` còn tiến trình tồn tại sau 11:15, `sysclient0351` có `lwabeat.exe` bị chiếm sinh ~16,800 event (87% event độc hại của host) trong ~2.5 giờ mà nhật ký chỉ ghi 2 dòng. Toàn bộ 3 scenario: SC1 8, SC2 54, SC3 20 cửa sổ như vậy. **Đề xuất: che (mask) khỏi loss nhãn tactic**, không đoán nhãn.
2. **Nhãn host và nhãn mạng không trùng.** 104 cửa sổ có event độc hại nhưng không có flow dương (SC1 12, SC2 72, SC3 20). Ở SC3, 20/27 cửa sổ host độc hại không có flow dương, trong khi 9 cửa sổ có flow dương nhưng 2 cửa sổ không có event host (host `0351` 09:45, `0051` 14:15). Đây là nơi fusion có thể bổ sung, nhưng cũng cho thấy hai bộ nhãn không đồng bộ theo thời gian.
3. **Số cửa sổ SC3 dương theo nhãn mạng khác con số trước đây.** Từ `conn-*.log` của A New Hope: `0051` có 6, `0351` có 3 cửa sổ có flow dương (tổng 9). Báo cáo STEP 10/11 nêu 6 cửa sổ dương SC3 (2 host). Khác biệt có thể do nhãn mạng trong pipeline (STEP 02, ghép eCAR-Bro) lọc khác, hoặc cửa sổ phải có đủ số flow tối thiểu. **Chưa đối chiếu**; cần kiểm tra trước khi dùng bảng này làm nhãn huấn luyện (đề xuất làm ở 12C).
4. **Sai lệch thời gian giữa nhật ký và eCAR.** Ví dụ `0051`: nhật ký ghi 10:29:42 tải `update.exe` nhưng eCAR tạo `cKfGW.exe` lúc 10:28:11; persistence nhật ký 10:48:43 và eCAR 10:47:14. Đã dùng đệm trước lớn hơn cho các dòng này; vẫn có thể lệch ± một cửa sổ ở biên.
5. Lỗi đã sửa trong lúc làm: lần chạy đầu gán LM cho toàn bộ giai đoạn agent chạy qua đêm (hàng trăm cửa sổ) và sai tên host của log mạng (`sysclient051`); đã sửa (tách bước/trạng thái, zero-pad tên host). Kết quả ở trên là sau sửa.

## 4. Unraveled: danh sách bucket (chỉ liệt kê, chưa tải)
Nguồn: bucket S3 công khai `dapt2021` (xem README `https://dapt2021.s3.amazonaws.com/README.txt`).

| Thư mục | Số file | Dung lượng |
|---|---:|---:|
| `processed/network-flows/` (CSV flow có 4 nhãn: Activity, Stage, DefenderResponse, Signature) | 175 | 3.72 GB |
| `processed/nids/` (Snort) | 2 | 0.013 GB |
| `processed/host-logs/` | **0** | 0 |
| `raw/host-logs/` (log host chưa gắn nhãn) | 131 | 0.36 GB |
| `raw/nids/` | 24 | 0.013 GB |
| `raw/network-captures/` (pcap) | 187 | 476.6 GB |

- `processed/host-logs/` **rỗng**: xác nhận log host của Unraveled chưa có nhãn.
- Tên file dạng `processed/network-flows/Week1_Day1-2_05262021-05272021/net1011x_Flow_labeled.csv` (73.5 MB file lớn nhất mẫu đầu); 31 thư mục ngày, mỗi thư mục có tối đa 5 file `net101{1..5}x`.
- Không đề xuất tải pcap (476.6 GB).

## 5. Bước tiếp theo
1. **12C:** đối chiếu nhãn mạng của bảng này với nhãn trong pipeline (STEP 02 / shards), và đo hồ sơ đặc trưng host trên cửa sổ benign của host TRAIN (cần ổ E:; xem `STEP_12C_SC3_HOST_CONTEXT_PLAN.md`).
2. Thẩm định ánh xạ bước → tactic với giảng viên hoặc bạn Nguyễn (nhánh host) trước khi dùng làm nhãn huấn luyện.
3. Tải Unraveled sau khi bạn xác nhận phạm vi (đề xuất: chỉ `processed/network-flows/`, 3.72 GB).
