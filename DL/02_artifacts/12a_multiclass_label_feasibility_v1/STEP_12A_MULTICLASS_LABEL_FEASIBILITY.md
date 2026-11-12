# STEP 12A — Khả năng dựng nhãn đa lớp (giai đoạn tấn công) cho OpTC và rà soát Unraveled

Ngày: 2026-10-05. Chỉ đọc và tra cứu, không sinh dữ liệu, không tải dataset, không sửa artifact cũ.
Bối cảnh: thầy gợi ý không train nhãn nhị phân 0/1 mà cần nhãn đa lớp.

## 1. Nguồn đã đọc
| Nguồn | Vị trí |
|---|---|
| Red team ground truth gốc của OpTC (`OpTCRedTeamGroundTruth.pdf`, 442.6 KB, nguồn GitHub `FiveDirections/OpTC-data`) | Đọc qua công cụ fetch; bản cache nằm trong thư mục tool-results của phiên (ngoài repo), **không nằm trong repo** |
| Nhãn host (A New Hope): `ground_truth_*.csv`, `ground_truth_corrected_*_updated.csv`, `*_evts_*.json.gz` | `D:\UIT\KLTN\KLTN-main\a_new_hope_for_darpa_optc\labelling\host\ground_truths\` |
| Nhãn network (A New Hope): `conn-*.log` đã lọc | `...\labelling\network\scenario-{1,2,3}\` |
| Bài A New Hope (§4 Labeling) | `...\a_new_hope_for_darpa_optc\A New Hope for DARPA OpTC.pdf` |
| Bài Unraveled (Computer Networks 227, 2023) | `D:\UIT\KLTNv2\papers\Unraveled.pdf` |
| Repo Unraveled: README, `data/README.md`, cây thư mục | https://gitlab.com/asu22/unraveled (đọc qua web) |
| `E:\a_new_hope_for_darpa_optc\…` | **Ổ E chưa gắn**; đã dùng bản sao ở `D:\UIT\KLTN\KLTN-main\` |

## 2. OpTC: nhãn hiện có chỉ là nhị phân, mức process
- **Host:** mỗi dòng ground truth là `(hostname, pid, thời điểm bắt đầu, thời điểm kết thúc)`. Mọi event của process đó và process con bị gán "malicious". Không có cột giai đoạn, kỹ thuật hay tactic.
- Event trong `*_evts_*.json.gz` là eCAR gốc (`action`, `object`, `properties.command_line`, …), không thêm trường nhãn. Ví dụ `sysclient0051`: 11,355 event, chủ yếu `THREAD`, `MODULE`, `PROCESS OPEN`, `FLOW`.
- **Network:** `conn-*.log` chỉ chứa các flow đã được coi là malicious (lọc theo IP/domain C2). Đếm theo đích (resp_h:resp_p):

| Scenario | Tổng flow | Phân bố chính |
|---|---|---|
| SC1 | 9,950 | 132.197.158.98:80 = 9,944; :8000 = 6 |
| SC2 | 18,806 | 202.6.172.98:443 = 16,693; 132.197.158.98:80 = 2,066; :22 = 18; :445 = 11; :81 = 5; :8080 = 5; :8443 = 3; **:9999 = 3** (khớp bước exfil bằng nc.exe); :8000 = 2 |
| SC3 | 555 | 53.192.68.50:8080 = 510; :80 = 34; :8000 = 8; RDP 3389 = 2; ICMP = 1 |

  Hệ quả: nhãn network gần như toàn **C2/beacon**; các bước khác chỉ còn vài flow.

## 3. Tài liệu red team gốc đủ chi tiết để dựng nhãn giai đoạn
PDF red team có nhật ký có timestamp (EDT) từng bước và mô tả tool. Ánh xạ sang ATT&CK tactic như sau (đây là **đề xuất ánh xạ của tôi, chưa được ai thẩm định**):

| Tactic ATT&CK | Ví dụ bước trong nhật ký |
|---|---|
| Initial Access / Execution | SC1: tải `runme.bat` stager Empire (23/9 11:23); SC2: mở `payroll.docx` (24/9 10:36, 10:40); SC3: notepad++ cập nhật tải `update.exe` Meterpreter (25/9 10:29, 11:23) |
| Privilege Escalation | `bypassuac` (SC1 11:26; SC2 11:09–11:25); `getsystem` (SC3 10:31) |
| Credential Access | Mimikatz, `lsadump` (SC1, SC3 10:44), tìm GPP/SYSVOL (SC2 11:10) |
| Persistence | Registry `Debug` (SC1 11:39); WMI subscription (SC2 11:34); Autorun (SC3 10:48) |
| Discovery | ping sweep, ARP scan, `enum_domain`/`enum_shares`, DeathStar (SC1 12:58–13:29; SC2 11:03–11:13; SC3 10:33–10:38) |
| Lateral Movement | `invoke_wmi` (SC1 13:24, 13:35, 14:04, 14:45; SC2 11:33, 15:42); RDP (SC2 13:46, 13:54) |
| Collection / Exfiltration | Chụp màn hình (SC1 12:51); nén `export.zip`, `nc.exe` tới news.com:9999 (SC2 13:31–13:44), 3.5 GB `allgona.zip` (SC2 15:04) |
| Defense Evasion | `timestomp` (SC3 10:53); migrate/inject (SC3 10:40; SC1 thất bại); dọn file (SC2 13:45, 15:22) |
| Command & Control | Beacon liên tục (SC1 5 giây, SC2 30 giây) |

## 4. Giới hạn (phải nói rõ trong báo cáo)
1. **Chi tiết rất không đều.** Chỉ một số host có nhật ký chi tiết: SC1 `0201, 0402, 0660, DC1`; SC2 `0501, 0974, 0005, DC1`; SC3 `0051`. 14 host SC1 bị lây từ DC1 chỉ có 2 dòng nhật ký ("spread", "killed agents"); 5–6 host SC2 chỉ "agents ran overnight"; `sysclient0351` SC3 chỉ 2 dòng.
2. **Nhãn process không tách được giai đoạn.** Nhiều bước (Mimikatz, `ps`, ARP scan) chạy trong **cùng một process** agent (cùng pid), nên phải gán giai đoạn theo **khoảng thời gian trong nhật ký** áp lên event của process độc hại, không theo pid.
3. **Độ chính xác thời gian của nhật ký.** A New Hope §4.2 nêu có sai lệch timestamp trong PDF. Cần cửa sổ đệm khi gán.
4. **Bro không thấy traffic nội bộ** (A New Hope §4.1), nên network không có nhãn cho di chuyển ngang và dò quét nội bộ. Nhánh network chỉ có thể học C2/exfil/tải tool; các giai đoạn còn lại là của nhánh host.
5. **Số mẫu hiếm theo lớp.** 29 host bị tấn công và ~541 window dương (98% beacon); các giai đoạn ngoài C2 chỉ có rất ít window. Cần đếm cụ thể trước khi chọn số lớp (gộp bớt tactic ít mẫu).
6. **Nhãn cuối là nhãn do chúng ta dựng**, không phải nhãn chính thức của DARPA hay của A New Hope. Phải ghi rõ quy trình và lưu ánh xạ để người khác tái lập.

## 5. Unraveled: tra cứu trang tải và schema
- **Bài báo:** *Computer Networks* 227 (2023) 109688 — dữ liệu 6 tuần, 27 máy (Linux Kali/Ubuntu và Windows 10), kịch bản 3 nhóm: Amateur, Skilled Hackers, APT.
- **Kho dữ liệu:** GitLab https://gitlab.com/asu22/unraveled (GPLv3; thư mục `data/`, `tools/`, `benchmarking/`, `images/`); dữ liệu lớn ở S3 bucket công khai `dapt2021` (README tại `dapt2021.s3.amazonaws.com/README.txt`; bucket `unraveled.s3…` trong bài trả 403). Tải bằng AWS CLI (`aws s3 cp s3://dapt2021/processed/...`) hoặc S3 Viewer.
- **Dung lượng:** bài báo nêu ~1 TB raw (pcap + log); README cần 1 TB trống cho toàn bộ. Phần processed (flow CSV) chưa có số liệu dung lượng chính xác, **cần liệt kê bucket để biết** trước khi tải.
- **Network flow (processed):** ~6.8 triệu flow từ NFStream, 81–85 feature (README ghi hai con số khác nhau), chia theo tuần/ngày. **4 cột nhãn:** `Activity` (số TTP MITRE), `Stage` (Reconnaissance, Foothold Establishment, Lateral Movement, Data Exfiltration, Cover-Up), `DefenderResponse` (Benign/Detected/Mitigated), `Signature` (AA/SH/APT). Tỷ lệ tấn công rất thấp: HR 28/1.79M flow, Marketing 29/734K, Gateway 59,043/2.89M.
- **Host log:** thư mục theo IP; Linux (audit, auth, filebeat), Windows (Security/Application/Admin events). `data/README.md` ghi rõ: **host log chưa có nhãn** ("still undergoing the labeling process"). Liên kết host–network chỉ bằng **IP + timestamp**.
- **Hiệu năng tham chiếu của tác giả:** LSTM-SAE/SAE/IF cho ROC-AUC ≈ 0.32–0.67, PR-AUC ≈ 0.01–0.05 — tức tác giả cũng khó phát hiện (bài báo nêu hạn chế này).
- **Đánh giá cho đề tài:** Unraveled có nhãn giai đoạn tốt **cho network**, nhưng host log chưa có nhãn và là log dạng văn bản Linux/Windows event, không phải eCAR/provenance. Không đủ để huấn luyện nhánh host đa lớp.

## 6. Kết luận
- Dựng nhãn đa lớp (tactic/giai đoạn) cho **OpTC là khả thi** nhờ nhật ký red team có timestamp, nhưng chỉ chắc chắn ở nhóm host có nhật ký chi tiết; phần còn lại phải gộp lớp hoặc loại khỏi bài toán đa lớp.
- Unraveled chỉ phù hợp làm **dataset phụ cho nhánh network** (nhãn Stage có sẵn), không thay được OpTC cho fusion.
- Nhánh network của OpTC gần như chỉ học được C2; nhãn đa lớp có ý nghĩa nhất ở nhánh host, và là lý do thuyết phục để fusion.

## 7. Việc cần quyết / bước tiếp theo
1. Chốt là multi-class (một giai đoạn/window) hay multi-label (nhiều tactic/window).
2. Chốt bộ lớp cuối (ví dụ gộp: Benign; C2/Execution; Credential Access + Privilege Escalation; Discovery; Lateral Movement; Persistence + Defense Evasion; Collection + Exfiltration) sau khi đếm số window mỗi lớp.
3. Step 12B (script đọc dữ liệu local, không job nặng): ánh xạ nhật ký → khoảng thời gian → event eCAR của process độc hại; đếm số event/window theo giai đoạn; đo phần chồng lấn với window mạng. Ghi vào thư mục mới.
4. Nếu muốn dùng Unraveled cho nhánh network: liệt kê bucket (không tải) để biết dung lượng thật, rồi báo tên file, nguồn, dung lượng và chờ xác nhận.
