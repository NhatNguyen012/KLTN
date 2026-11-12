# STEP 19 — Phân tích 3 dataset đã tải: skrghosh, SAGA, Windows-APT 2025

Ngày: 2026-10-08. Nguồn: `03_datasets/{skrghosh,SAGA,Windows-APT 2025}/` (đã tải về, chưa đụng tới; giải nén bản nhỏ vào thư mục tạm, không ghi vào `03_datasets`). Mã quét SAGA: `01_code/pipeline/19a_saga_label_scan.py` (đọc thẳng từ zip, 513 giây, 0 dòng lỗi). Bảng: `saga_file_summary.csv`, `saga_label_counts.csv`. Mọi con số dưới đây đếm trực tiếp từ file.

## 1. Tóm tắt một dòng cho mỗi dataset
| | Windows-APT 2025 | skrghosh/apt-dataset | SAGA |
|---|---|---|---|
| Có dữ liệu thật trong thư mục chưa? | Có (102,011 dòng) | **Chưa**: 5 file `.json.zip` chỉ là con trỏ Git LFS (134 byte mỗi file) | Có (27.8M event) |
| Có nhãn từng event không? | **Không** có cột nhãn hay mã kịch bản | Không (nhãn theo kịch bản, trong PDF) | **Có**: 1 nhãn mỗi event |
| Nhãn là gì | Tactic/technique do **luật Wazuh** gán (62.4% dòng) | Bảng bước tấn công có giờ + lệnh (PDF) | `benign` hoặc `Txxxx[.yyy]_<ability>` (ground truth) |
| Host + network | Chủ yếu host; 467 dòng có IP đích | Chỉ host (eCAR) | Chỉ host (Procmon); node `Network` chỉ ~0.05–0.4% event |
| Dùng được cho multi-label tactic? | Chỉ như nhãn yếu (xem 2.1) | Sau khi lấy dữ liệu thật và tự dựng nhãn như STEP 12B | **Dùng được**, nhưng có bẫy lặp (xem 2.3) |

## 2. Chi tiết

### 2.1 Windows-APT 2025 (52 MB zip, 459 MB giải nén)
- 16 file CSV theo giai đoạn + `combined.csv` (102,011 dòng = tổng 16 file, khớp). 377 cột, kiểu xuất từ Wazuh/OpenSearch (`_source.*`). Thời gian 2024-10-28 → 2024-12-22 (40 ngày có dữ liệu).
- **Chỉ có 5 agent** (`window-agent3` 56,177 dòng; `wazuh-agent` 23,772; `agent1` 17,665; `DESKTOP-DS4FBF4` 3,435; `Maryam` 962) ⇒ split host-disjoint chỉ còn khoảng 3/1/1 host, quá ít để kết luận.
- **Mọi dòng là một Wazuh alert** (chỉ mục `wazuh-alerts-4.x-*`), không phải log thô: không có nền benign đầy đủ. Mức `rule.level` 3–5 chiếm đa số (nhiễu hệ thống: log rotation, Sysmon error, logon...).
- **Không có cột nhãn, không có cột mã kịch bản.** `scenario_manifest.csv` có 36 kịch bản (nhóm APT Trung Quốc, 230 technique khác nhau) nhưng **không có thời gian chạy** nên không nối được kịch bản với dòng log. README nói script lọc log theo `Scenario_ID` "nếu có cột đó", cột đó không tồn tại trong `combined.csv`.
- Cột `rule.mitre.tactic` có giá trị ở 63,619/102,011 dòng (62.4%): 10 tactic, `Execution` 20,342; `Defense Evasion` 18,776; `Command and Control` 18,365; `Privilege Escalation` 11,948; `Persistence` 9,165; `Discovery` 7,944; `Lateral Movement` 4,884; `Initial Access` 3,626; `Impact` 3,397; **`Credential Access` chỉ 49**. 41,682 dòng có 1 tactic, 13,810 có 2, còn lại 3–5. Đây là **đầu ra của bộ luật phát hiện**, không phải ground truth tấn công: dùng làm nhãn để huấn luyện bộ phát hiện sẽ vòng tròn (model học lại luật Wazuh), ví dụ luật "Executable file dropped in folder commonly used by malware" một mình là 14,714 dòng.
- Kết luận: dùng thử nhanh cho host ML hoặc minh họa ánh xạ ATT&CK được; **không đủ làm benchmark multi-label có ground truth**.

### 2.2 skrghosh/apt-dataset (0.1 MB zip)
- Bản tải "Download ZIP" từ GitHub **không chứa dữ liệu**: `apt29/fin6/oilrig/output_menuPass/wizard_spider.json.zip` đều là con trỏ Git LFS (`size` khai báo 195,824,992 / 124,481,423 / 260,998,942 / 293,773,880 / 202,171,033 byte, tổng ≈ **1.08 GB** nén). Cần `git clone` kèm `git lfs pull` (hoặc tải từ trang GitHub) mới có dữ liệu.
- Có sẵn 5 PDF ground truth và README (bảng 10 chiến dịch + 2 ngày OpTC; bảng tactic/technique/ability cho FIN6 và menuPass). Xem PDF FIN6: đó là "Operations Debrief" của Caldera, liệt kê **từng bước với giờ chính xác và lệnh** (ví dụ 2023-07-25 11:12:18 → 11:13:55 là toàn bộ cuộc tấn công, khoảng 1.5 phút), nên nhãn từng event phải tự dựng bằng cách khớp giờ + lệnh, giống STEP 12B.
- README ghi benign 99.37–99.97% mỗi chiến dịch ⇒ số event độc hại rất nhỏ. Chưa xác minh được schema cột vì chưa có dữ liệu thật; README nói theo mô hình eCAR của FiveDirections, tức cùng họ với OpTC (tokenizer của nhánh Host có thể dùng lại, **chưa kiểm**).

### 2.3 SAGA (3 zip, 676 MB nén, 14.8 GB giải nén; không giải nén, quét trực tiếp từ zip)
- 38 file JSONL (Known C1–C8, Generated G1–G20, Composite M1–M10), tổng **27,805,563 event**, mỗi dòng `{srcNode, dstNode, relation, timestamp, label}`. `srcNode` luôn là Process; `dstNode` là Registry (56–88% ở 4 file mẫu đã đếm), File, Network, Process. Không có trường hostname. Mỗi file là một lát log tối đa 15 phút (một số ngắn hơn, từ 1 đến 14.9 phút; thời gian epoch quanh 2022-06-14).
- **Nhãn: một chuỗi mỗi event**: `benign` hoặc `<technique>_<ability_id>` (58 technique, 98 cặp technique+ability). Không có nhãn tactic: phải ánh xạ technique → tactic bằng bảng ATT&CK bên ngoài (một technique có thể thuộc nhiều tactic). Multi-label xuất hiện ở **mức cửa sổ/file**: cả 38/38 file có ≥ 3 technique khác nhau (trung vị 7.5 ở Known, 9 ở Generated, 17 ở Composite).
- **Tổng event độc hại: 77,090 (0.277%).** Phân bố rất lệch: Known 29,607 / 7.24M; Generated 1,768 / 11.60M (0.015%); Composite 45,715 / 8.97M. Mỗi file có từ 21 đến 15,307 event độc hại.
- **Bẫy lặp (rất quan trọng, giống vấn đề beacon của OpTC):** **70,440 / 77,090 = 91.4% event độc hại thuộc đúng một ability** `T1005_720a3356-...`, xuất hiện **y hệt 14,088 event** ở 5 file (C3, C7, M2, M5, M8). Nếu bỏ ability này còn **6,650 event độc hại, 57 technique, 97 nhãn technique+ability**. Chỉ riêng 5 file chứa T1005 có tỉ lệ độc hại 1.2–9.1%; 33 file còn lại ≤ 0.21%. Trong 98 nhãn có 84 nhãn xuất hiện ở hơn 1 file, 14 nhãn xuất hiện ở cả 3 nhóm. Các file Composite được ghép từ Known/Generated (cùng nhãn và cùng event lặp lại), nên **không được chia ngẫu nhiên theo event hoặc theo file**; nếu dùng phải chia theo chiến dịch gốc và xử lý trùng lặp.
- Hạn chế khác: log là Procmon (schema khác eCAR của OpTC); không có hostname nên split host-disjoint không áp dụng được theo nghĩa của đề tài; network chỉ là node `Network` trong event hệ thống.

## 3. Đánh giá cho khóa luận
1. **Không dataset nào có đủ host + network có ground truth**, nên không thay OpTC cho bài fusion. Chúng chỉ phục vụ phần **multi-label tactic ở nhánh host**.
2. **SAGA là ứng viên duy nhất có nhãn từng event ở quy mô đủ lớn**, đúng như dự đoán ở STEP 18. Nhưng phải xử lý bẫy T1005 (91.4%) trước khi báo bất kỳ metric nào; nếu không sẽ lặp lại lỗi "điểm cao do lặp" như beacon.
3. **skrghosh cần tải lại dữ liệu thật (≈1.08 GB, qua `git lfs`)** mới đánh giá được; về định dạng là gần OpTC nhất, nhưng nhãn phải tự dựng.
4. **Windows-APT 2025 chỉ nên dùng thử nhanh hoặc minh họa**: 5 host, toàn alert, không có nhãn thật.
5. Đây là phân tích mô tả; chưa huấn luyện gì, chưa kết luận mô hình nào tốt hơn.

## 4. Việc có thể làm tiếp (chờ bạn chọn)
- (a) SAGA: dựng bảng ánh xạ technique → tactic (ATT&CK) cho 58 technique, tạo nhãn multi-hot 12 tactic cho từng cửa sổ/file, thống kê độ phủ từng tactic sau khi bỏ T1005 và dedup; nhẹ (chỉ đọc lại bảng đếm đã có, cần thêm quét 513 giây nếu muốn nhãn theo cửa sổ nhỏ hơn 15 phút).
- (b) skrghosh: `git lfs pull` ≈ 1.08 GB để xem schema thật và so với eCAR của OpTC.
- (c) Quay lại hướng chính OpTC (B/C trong danh sách trước).

## 5. Bổ sung 2026-10-10: tài liệu Word và file mẫu
- `PHAN_TICH_SAGA.docx`, `PHAN_TICH_WINDOWS_APT_2025.docx` (3 trang mỗi file, có bảng từ khóa Anh–Việt cho 14 tactic ATT&CK và các thuật ngữ), dựng bởi `01_code/pipeline/19c_build_dataset_docx.py`.
- `saga_samples_per_label.csv` (276 dòng: 98 nhãn × tối đa 3 dòng + 6 dòng benign), `windows_apt_samples_per_tactic.csv` (36 dòng: 10 tactic × 3 + nhóm nhiều tactic + nhóm không nhãn; Collection và Exfiltration không có dòng nào). Sinh bởi `19b_dataset_samples.py` (Windows-APT lấy ngẫu nhiên có seed 0).
- `saga_technique_tactic_map.csv`, `saga_tactic_coverage.csv`: ánh xạ technique → tactic của người viết theo ATT&CK, **chưa thẩm định**.
- skrghosh: chờ bạn `git clone` (xem hướng dẫn trong chat) rồi mới xem schema thật.

## 6. Bổ sung 2026-10-10: mẫu THÔ nguyên bản và phân tích OpTC
- `raw_samples/` (sinh bởi `01_code/pipeline/19e_raw_samples.py`): dòng gốc nguyên văn, không thêm/bớt cột hay sửa giá trị; thông tin chọn dòng nằm ở file `*_index.csv` riêng.
  - `saga_raw_samples.jsonl`: 221 dòng JSONL gốc (98 nhãn technique+ability, mỗi nhãn 1–3 dòng đầu/giữa/cuối trong file đầu tiên chứa nhãn; thêm 4 dòng benign).
  - `windows_apt_raw_samples.csv`: 79 dòng gốc của combined.csv, đủ 377 cột + tiêu đề gốc (27 giá trị nhãn tactic, mỗi giá trị đầu/giữa/cuối; gồm nhóm trống).
  - `skrghosh_raw_samples.jsonl`: 75 dòng gốc (3 dòng ngẫu nhiên seed 0 mỗi chiến dịch × object, thêm 6 dòng PROCESS của FIN6 trong cửa sổ tấn công theo PDF). Dataset này không có cột nhãn.
- Kiểm tra: Windows 79/79 dòng và tiêu đề trùng nguồn; skrghosh 75/75 dòng trùng nguồn; SAGA kiểm 47 dòng của 6 file đều trùng.
- `PHAN_TICH_OPTC_SC3_BEACON_VA_FIELD_HOST.docx` (`19f_build_optc_doc.py`): SC3 ít positive, beacon, bất cập khi nối field host. Số liệu lấy từ artifact đã có; tỉ lệ ánh xạ flow → PROCESS CREATE chưa đo (cần ổ E:).
