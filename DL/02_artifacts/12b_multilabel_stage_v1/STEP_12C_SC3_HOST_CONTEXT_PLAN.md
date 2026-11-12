# STEP 12C (kế hoạch) — Lấy gì từ nhánh host để bắt SC3, và làm thế nào

Ngày: 2026-10-06. Đây là phân tích và kế hoạch, chưa chạy huấn luyện. Dữ liệu đã đọc: event eCAR độc hại của `sysclient0051` (11,355 event) và `sysclient0351` (19,378 event) trong `labelling/host/ground_truths/` (bản corrected), cộng nhật ký red team.

## 1. Về nhận định "chỉ 0.9x vì network-only không bắt được SC3"
Đúng một phần, theo số liệu STEP 10E (3 seed, TEST):
- Precision gần 1.0; lỗi hầu như là **bỏ sót** (FN), không phải báo nhầm.
- Phần FN do SC3 (cộng 3 seed): BiLSTM full 11/15 (73%), Mixed full 6/6 (100%), BiLSTM noapp 11/20 (55%), Mixed noapp 8/20 (40%).
- Các run bỏ `app_family` còn bỏ sót cả window SC2 (BiLSTM noapp 9, Mixed noapp 12 trên 222). Vì vậy với bản noapp, SC3 chỉ giải thích 40–55% lỗi; phần còn lại do beacon SC2 bị bỏ sót và threshold bão hòa (K6).
- Kết luận an toàn: bắt được SC3 sẽ nâng F1 của bản full lên cao hơn nhưng **không đảm bảo bằng 1**; và SC3 chỉ là 4 window của 1 host trong TEST, nên đây là case study, không phải thống kê.

## 2. Tín hiệu từ host quan sát được ở SC3 (chỉ trên event độc hại; chưa so với benign)
| # | Tín hiệu (eCAR) | Bằng chứng ở SC3 | Network nhìn thấy không |
|---|---|---|---|
| 1 | Chuỗi cha-con bất thường: `explorer → notepad++.exe → gup.exe → %TEMP%\cKfGW.exe` | `0051` 10:28:11; `0351` 11:18:18, 11:20:07, `f.exe` 11:22:16 | Không |
| 2 | Process thực thi từ thư mục ghi được (User Temp, `C:\Windows\Temp\rad*.tmp\`) | `cKfGW.exe`, `biGuWCmNsuCIG.exe` | Không |
| 3 | `cmd.exe`/`cscript.exe` có cha là `lsass.exe` (migrate vào LSASS) | `0051` từ 10:47; lệnh `net user admin ... /add`, `net localgroup Administrators admin /add` (11:06) | Không |
| 4 | ~~`THREAD REMOTE_CREATE` (chèn thread)~~ **bị loại sau pilot** | 48 sự kiện duy nhất ở `0051`, 4 ở `0351` (chỉ xét event độc hại) | Không. Log đầy đủ: ngày benign 22/9 có trung bình ~154–191 REMOTE_CREATE/cửa sổ |
| 5 | Ghi registry persistence và SAM | `HKLM\...\Run\RTqWaEHv` thêm lúc 10:47; sửa `SAM\...\Users` lúc 11:06 | Không |
| 6 | Tạo `.vbs`/`.exe` trong Temp, `cscript` chạy `.vbs` | `C:\Windows\Temp\myHbYXTpViwX.vbs` 10:47 | Không |
| 7 | Respawn đều đặn: `biGuWCmNsuCIG.exe` sinh mới mỗi ~65 giây từ cùng `cscript` | quan sát từ 10:49 trở đi | Gián tiếp: flow REJ tới `53.192.68.50:8080` giống noise |
| 8 | ~~Bùng nổ khối lượng event theo cửa sổ~~ **bị loại sau pilot** | `0051` 10:30 có 5,178 event **độc hại** so với 134–187 ở cửa sổ yên | Không. Log đầy đủ: cửa sổ này có 34,313 event tổng, thấp hơn mức trung bình 46,916 của ngày benign; 5,178 event độc hại chỉ là một phần nhỏ |
| 9 | Process hợp lệ bị chiếm: `lwabeat.exe` sinh 87% event độc hại của `0351` | 16,786/19,378 event | Không |

Các tín hiệu 1–6, 8 đều **theo hành vi** (cha-con, thư mục, loại thao tác), không phụ thuộc tên file; tên như `biGuWCmNsuCIG.exe` thì không thể học được vì ngẫu nhiên.

**Chưa kiểm chứng:** các tín hiệu này có thật sự hiếm trên cửa sổ benign hay không (ví dụ chuỗi `gup.exe → exe trong Temp` có thể xuất hiện ở cập nhật notepad++ hợp lệ). Cần đo tần suất trên cửa sổ benign của host TRAIN, việc này cần log eCAR thô ở ổ E:.

## 3. Cách làm (đề xuất, theo thứ tự rẻ → đắt)
**Mức A — baseline không học (1–2 ngày):** quy tắc/điểm host đơn giản trên cửa sổ `(host, 15 phút)`, rồi kết hợp với xác suất của nhánh network bằng OR / trung bình / stacking (logistic hoặc LightGBM trên 2 điểm). Mục đích: chứng minh "fusion đơn giản" trước khi làm mô hình phức tạp, đúng yêu cầu baseline của đề cương.

**Mức B — vector host theo cửa sổ (đặc trưng hành vi, không dùng tên file làm đặc trưng chính):**
- Đếm theo `(object, action)` (log1p), số `PROCESS CREATE`, số image khác nhau.
- Tỷ lệ process chạy từ thư mục ghi được (Temp/AppData/Windows\Temp).
- Số cặp cha→con **chưa từng thấy trong TRAIN** (từ điển cặp fit trên TRAIN only).
- Số `THREAD REMOTE_CREATE`; số `REGISTRY ADD/EDIT` ở khóa Run/Services/SAM; số `FILE CREATE` đuôi `.exe/.vbs/.dll/.bat` trong Temp.
- Số process có cha là `lsass/winlogon/services`.
- Z-score số event so với nền của **chính host đó** (từ ngày benign 22/9, chỉ dùng dữ liệu trước thời điểm kiểm thử).
- Bản ablation bỏ mọi đặc trưng dựa trên tên image/command line (như ablation `app_family` ở STEP 10).

**Mức C — cầu nối cấp flow (đúng tinh thần context-aware):** mỗi flow trong eCAR-Bro có `actorID` ⇒ tra ra `PROCESS CREATE` của chính tiến trình đó ⇒ gắn thêm vào flow: loại thư mục image, cha là ai, tuổi tiến trình, cha là `lsass`, chưa từng thấy trong TRAIN. Khi đó flow REJ giống noise sẽ mang thêm ngữ cảnh "do tiến trình chạy từ Temp có cha là lsass phát sinh". Cần log eCAR thô (ổ E:).

**Mức D — mô hình fusion học được:** hai nhánh (network BiLSTM/Mixed-Type; host MLP hoặc GraphSAGE), cổng `g = σ(W[h_host; h_net; m_host; m_net])`, `z = g·h_host + (1−g)·h_net`, `m_*` là source mask. Huấn luyện với missing-source dropout 10/20/30% (khớp đề cương). Đầu ra multi-label 5 nhóm tactic của STEP 12B, loss BCE có `pos_weight`, mask các cửa sổ chưa có nhãn giai đoạn.

## 4. Cách đánh giá SC3 một cách trung thực
- Chỉ 2 host SC3 (29 cửa sổ có nhãn, 9 cửa sổ có flow dương). **Không báo F1 kèm khoảng tin cậy**; báo bảng từng cửa sổ: điểm network, điểm host, điểm fusion, nhãn.
- Kịch bản chính: **leave-scenario-out** (train SC1+SC2, kiểm tra SC3). Đây thử khả năng tổng quát sang kỹ thuật chưa thấy (Meterpreter qua cập nhật notepad++, khác Empire/PowerShell), nên đặc trưng bắt buộc theo hành vi.
- Cần cửa sổ benign của chính hai host SC3 để đo dương tính giả (cần ổ E:).
- Mọi preprocessing fit trên TRAIN only; threshold chọn trên VAL; split theo hostname (quy tắc CLAUDE.md).

## 5. Việc cần xác nhận trước khi chạy
1. Cho phép gắn ổ E: để (a) đo tần suất các tín hiệu trên cửa sổ benign của host TRAIN, (b) lấy cửa sổ benign của 2 host SC3. Tôi sẽ báo dung lượng/thời gian ước tính trước khi chạy job quét eCAR thô, vì log host dạng ngày-host có 4,695 file.
2. Chọn đi từ mức A (rẻ, trước) hay làm thẳng B.
3. Thẩm định ánh xạ nhật ký → tactic (STEP 12B) với thầy hoặc bạn Nguyễn.

## 6. Pilot (2026-10-06): đặc trưng trên log eCAR đầy đủ của 2 host SC3
Script `01_code/pipeline/12c_host_window_features.py`, 4 file (`sysclient0051` và `0351` ngày 22/9 benign và 25/9). Tốc độ: 2.5 triệu event ngày 25/9 mất 20–24 s, 4.5–4.8 triệu event ngày 22/9 mất 37–39 s (4 tiến trình song song). Kết quả ở `02_artifacts/12c_host_features_v1/pilot/`.

Ngày benign 22/9 (96 cửa sổ/host; trung bình / lớn nhất trên mỗi cửa sổ), chỉ 2 host nên **chưa đại diện**:

| Đặc trưng | `0051` | `0351` |
|---|---|---|
| `n_parent_lsass` (process con của lsass.exe) | 0 / 0 | 0 / 0 |
| `n_cmd_susp` (net user, /add, wmic, encodedcommand...) | 0 / 0 | 0 / 0 |
| `n_proc_writable` (process chạy từ Temp/AppData) | 0.1 / 1 | 0.1 / 1 |
| `n_remote_thread` | 154 / 470 | 191 / 803 |
| `n_exec_drop` (tạo/ghi file thực thi trong thư mục ghi được) | 22.5 / 713 | 26.7 / 495 |
| `n_reg_persist` | 1.8 / 22 | 1.6 / 22 |

Ngày 25/9, cửa sổ tấn công của `sysclient0051` (EDT):

| Cửa sổ | `n_parent_lsass` | `n_cmd_susp` | `n_proc_writable` | cặp cha→con lạ so với ngày benign |
|---|---:|---:|---:|---:|
| 10:15 (dropper `cKfGW.exe`) | 0 | 0 | 1 | 4 |
| 10:30 (getsystem, Mimikatz) | 0 | 0 | 0 | 3 |
| 10:45 (persistence) | 2 | 0 | 12 | 4 |
| 11:00 (`net user ... /add`) | 4 | 12 | 14 | 5 |
| 11:15 | 0 | 0 | 6 | 1 |

Kết luận pilot (chỉ 2 host, chưa tổng quát hóa):
- **Phân tách được ở `0051` bằng 3 tín hiệu hành vi**: process con của `lsass.exe`, lệnh `net user/localgroup`, process chạy từ Temp. Cả ba đều bằng 0 hoặc rất thấp trong ngày benign của hai host.
- **Không phân tách bằng**: số `REMOTE_CREATE`, tổng số event, số file thực thi bị tạo (`n_exec_drop` benign tối đa 713, cao hơn cả cửa sổ tấn công), `n_reg_persist` (cửa sổ 13:30–14:15 tăng ở cả hai host mà không có liên quan tới bước tấn công trong nhật ký).
- **`sysclient0351` yếu**: chỉ cửa sổ 11:15 có dấu hiệu (`n_proc_writable` = 3, 7 cặp cha→con lạ); các cửa sổ `lwabeat.exe` bị chiếm (11:30–13:45) không hiện ra ở các đặc trưng này. Với host này cần đặc trưng khác (ví dụ tần suất file `RENAME/WRITE` bất thường theo process), chưa thử.
- Cửa sổ 10:30 của `0051` (getsystem/Mimikatz/migrate) **không có tín hiệu nào** trong 3 đặc trưng trên: giai đoạn này chỉ phát hiện được bằng ngữ cảnh khác (ví dụ chuỗi cha-con `cKfGW.exe → cmd.exe`, các cặp lạ ở cột cuối = 3).

## 7. Job lớn đề xuất (chờ xác nhận) — chạy script trên nhiều host
Cần cho baseline mức A vì phải (a) thống kê "bình thường" chỉ từ TRAIN, (b) chọn ngưỡng/trọng số trên VAL, (c) đo TEST đúng một lần (CLAUDE.md).

| Phần | Số file | Dung lượng đọc | Ước tính thời gian (6 tiến trình) |
|---|---:|---:|---:|
| TRAIN: ngày benign 22/9, mẫu ngẫu nhiên 150 host có log host | 150 | ~37 GB | ~15 phút |
| VAL: 23, 24, 25/9, các host VAL có log host (≤93 host) | ≤279 | ≤ 40 GB | ~15 phút |
| TEST: 23, 24, 25/9, các host TEST có log host (≤93 host, seed_1) | ≤279 | ≤ 40 GB | ~15 phút |
| Tổng | ≤708 | ≤ ~117 GB | ~45–60 phút (giới hạn bởi tốc độ đọc ổ HDD E:) |

Đầu ra nhỏ (vài chục MB CSV). Không ghi đè dữ liệu cũ; ghi vào `02_artifacts/12c_host_features_v1/`.
