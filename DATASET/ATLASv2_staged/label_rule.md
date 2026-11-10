# Quy chuẩn Gán Nhãn & Phân loại Giai đoạn Tấn công (Labeling & Stage Taxonomy Rules) trên Bộ Dữ liệu ATLASv2_staged

Tài liệu này trình bày chi tiết và toàn diện phương pháp luận, cơ sở lý thuyết trích xuất từ các công trình nghiên cứu khoa học hàng đầu, và các quy tắc kỹ thuật cụ thể được áp dụng để gán nhãn nhị phân (Binary Anomaly) và phân loại giai đoạn tấn công đa bước (Multi-Stage Cyber Kill-Chain) trên bộ dữ liệu **ATLASv2_staged**.

---

## Mục Lục
1. [Tổng quan & Mục tiêu Chuẩn hóa Nhãn](#1-tổng-quan--mục-tiêu-chuẩn-hóa-nhãn)
2. [Cơ sở Lý thuyết & Các Công trình Nghiên cứu Nền tảng](#2-cơ-sở-lý-thuyết--các-công-trình-nghiên-cứu-nền-tảng)
3. [Hệ Thống 5 Giai đoạn Tấn công Chuẩn hóa (MITRE ATT&CK Mapping)](#3-hệ-thống-5-giai-đoạn-tấn-công-chuẩn-hóa-mitre-attck-mapping)
4. [Quy tắc Gán Nhãn Nhị phân 2 Tầng & Khắc phục "Nghịch lý Firefox"](#4-quy-tắc-gán-nhãn-nhị-phân-2-tầng--khắc-phục-nghịch-lý-firefox)
5. [Quy tắc Ánh xạ Chi tiết Từng Giai đoạn Tấn công (Stage Assignment Rules)](#5-quy-tắc-ánh-xạ-chi-tiết-từng-giai-đoạn-tấn-công-stage-assignment-rules)
6. [Hiện thực Hóa Mã Nguồn & Luồng Xử lý Dữ liệu](#6-hiện-thực-hóa-mã-nguồn--luồng-xử-lý-dữ-liệu)
7. [Thống kê Thực nghiệm Phân bố Nhãn trên Toàn bộ Tập Dữ liệu](#7-thống-kê-thực-nghiệm-phân-bố-nhãn-trên-toàn-bộ-tập-dữ-liệu)
8. [Quy trình Kiểm chứng & Đảm bảo Tính Toàn vẹn Dữ liệu](#8-quy-trình-kiểm-chứng--đảm-bảo-tính-toàn-vẹn-dữ-liệu)

---

## 1. Tổng quan & Mục tiêu Chuẩn hóa Nhãn

Trong các hệ thống giám sát và bảo mật EDR/SIEM truyền thống, bài toán phát hiện tấn công thường chỉ dừng lại ở mức **phân loại nhị phân (Binary Classification: Benign vs Attack)**. Tuy nhiên, đối với các cuộc tấn công có chủ đích nâng cao (APT - Advanced Persistent Threats), các chiến dịch thường kéo dài qua nhiều ngày với hành vi lén lút, sử dụng công cụ có sẵn của hệ điều hành (Living-off-the-Land - LotL), xen kẽ giữa hàng triệu sự kiện nền bình thường của người dùng.

Để giải quyết triệt để bài toán này cho cả hai nhánh **Host ML (LightGBM)** và **Network DL (BiLSTM)**, bộ dữ liệu **ATLASv2** (thu thập từ testbed kéo dài 5 ngày của UIUC với 154 GB dữ liệu thực tế) được nâng cấp thành **ATLASv2_staged** nhằm đạt được hai mục tiêu chuẩn mực:
1. **Lọc sạch nhãn nhị phân ở mức sự kiện (Event-level Refinement):** Loại bỏ hoàn toàn báo động giả do gán nhãn thô theo tiến trình (đặc biệt là tiến trình trình duyệt duyệt web nền), đảm bảo dữ liệu lành tính Ngày 1–4 đạt chính xác 0.00% False Positive.
2. **Gán nhãn giai đoạn tiến triển tấn công (Multi-Stage Kill-Chain Labeling):** Ánh xạ từng tiến trình và chuỗi sự kiện EDR vào 5 giai đoạn chiến thuật chuẩn hóa của MITRE ATT&CK và Lockheed Martin Cyber Kill-Chain, cho phép mô hình Deep Learning không chỉ phát hiện bất thường mà còn định danh chính xác kẻ tấn công đang ở pha nào của chiến dịch.

---

## 2. Cơ sở Lý thuyết & Các Công trình Nghiên cứu Nền tảng

Hệ thống quy chuẩn gán nhãn trong `ATLASv2_staged` được xây dựng dựa trên sự tổng hợp và kế thừa có chọn lọc từ 4 công trình khoa học quốc tế uy tín:

### 2.1. Paper 1: USENIX Security 2021 — ATLAS (Adil Inam et al., UIUC & Purdue)
* **Tên bài báo:** *ATLAS: A Sequence-based Learning Approach for Attack Investigation* (USENIX Security 2021).
* **Đóng góp lý thuyết kế thừa:**
  - **Mô hình Chuỗi Nhân quả Thực thể (Causal Sequence Graph):** Biểu diễn các bước tấn công dưới dạng đồ thị nguồn gốc phụ thuộc nhân quả giữa các thực thể `Subject (Process) -> Operation -> Object (File / Socket / Registry)`.
  - **Vòng đời Tấn công 8 Bước Chuẩn hóa (8-Step Attack Chain):**
    - *Bước 1 (Phishing):* Gửi email đính kèm hoặc chứa link độc hại tới nạn nhân.
    - *Bước 2 (Exploitation):* Nạn nhân mở email/link, kích hoạt khai thác lỗ hổng trình duyệt hoặc Office.
    - *Bước 3 (Meterpreter Shell):* Khai thác thành công, tiêm mã độc vào bộ nhớ và thiết lập kết nối điều khiển từ xa về máy tấn công Kali Linux.
    - *Bước 4 (Drop Payload):* Kẻ tấn công thực thi các lệnh thăm dò và tải xuống backdoor `payload.exe`.
    - *Bước 5 (Exfiltration trên Host 1):* `payload.exe` quét và gom các tài liệu nhạy cảm (`.pdf`), truyền ra máy chủ C&C qua giao thức HTTPS.
    - *Bước 6 (Sabotage Web Portal):* Kẻ tấn công can thiệp vào máy chủ web nội bộ (`python.exe` SimpleHTTP server) trên máy `h1`, sửa đổi tệp `index.html` thành trang web lừa đảo cập nhật phần mềm.
    - *Bước 7 (Lateral Movement sang Host 2):* Người dùng trên máy trạm thứ hai (`h2`) truy cập vào cổng web nội bộ, bị đánh lừa tải và thực thi bản cập nhật mã độc.
    - *Bước 8 (Exfiltration trên Host 2):* `payload.exe` thực thi trên máy `h2`, tiếp tục gom tài liệu và tuồn về máy chủ C&C.
  - **Định lý Cạnh Nhân quả (Causal Edge Principle - Figure 1a):** Khi một tiến trình độc hại được nạp vào bộ nhớ, bản thân các hành vi nạp thư viện hệ điều hành tiêu chuẩn (`ntdll.dll`, `kernel32.dll`, `user32.dll`) hoặc các truy vấn registry giao diện vô hại (`shell folders`, `muicache`) là hành vi thiết yếu của OS Loader Windows, không mang bản chất tấn công. Chỉ các hành vi can thiệp sâu, tạo tiến trình con (`PROCESS_START`), ghi file payload (`FILE_WRITE/CREATE`), hoặc mở luồng mạng C&C (`FLOW_START`) mới được coi là cạnh tấn công nhân quả.

### 2.2. Paper 2: UIUC STS-Lab Technical Report 2022 — ATLASv2 (STS-Lab, UIUC)
* **Tên tài liệu:** *ATLAS Attack Engagements, Version 2* (Technical Documentation & Dataset Release).
* **Đóng góp lý thuyết kế thừa:**
  - **Thời gian biểu Khởi động & Mốc Bắt đầu Tấn công Thực sự (`INITIAL_ATTACK_TIMESTAMPS`):** Chỉ ra rằng trong 10 kịch bản tấn công của Ngày thứ 5, mỗi kịch bản bắt đầu bằng việc khôi phục một bản snapshot máy ảo (VM snapshot). Dấu vết khởi động máy ảo (VM startup footprint) diễn ra trong 10–20 phút đầu hoàn toàn là hoạt động lành tính của Windows. Mốc tấn công thực sự (`Initial Attack Step`) được xác định chính xác theo giây cho từng kịch bản (`s1` đến `m6`).
  - **Bộ Nhận diện Chỉ số Xâm phạm (Known IOCs & Seed Endpoints):** Định danh các IP/Port máy chủ C&C (`10.193.66.115:9999`, `10.193.66.115:8443`), tên miền độc hại (`ortrta.net`), tên mã độc (`payload.exe`), và các tệp nén chứa vũ khí tấn công (`s3take2.zip`, `s4-at-night.zip`, `m4.zip`, `m5-2.zip`, `m6.zip`).

### 2.3. Paper 3: UIUC REAPr Project — Ground Truth Labeling for Provenance IDS
* **Tên dự án:** *REAPr: Repeatable Evaluation and Automated Labeling for Provenance Graphs*.
* **Đóng góp lý thuyết kế thừa:**
  - Cung cấp tệp nhãn mức tiến trình `*.labels` ánh xạ trực tiếp `process_uuid` (GUID) sang nhãn `attack` hoặc `benign`.
  - Nhận diện **"Nghịch lý Firefox" (Firefox Paradox):** Tiến trình trình duyệt `firefox.exe` được người dùng sử dụng liên tục để duyệt tin tức, xem video, họp trực tuyến trong 4 ngày bình thường và cả trong ngày tấn công (phát sinh hơn 27,000 kết nối mạng). Nếu áp dụng trực tiếp nhãn REAPr theo GUID tiến trình, toàn bộ hoạt động duyệt web bình thường sẽ bị gán nhầm là độc hại, gây sụp đổ tỷ lệ báo động giả của mô hình học máy.

### 2.4. Paper 4: APT-LMSPS (Information 2026 / 2024 MDPI) & CL-APT / DeepDist (IEEE TrustCom 2023)
* **Tên bài báo:**
  - *APT-LMSPS: An Efficient APT Detection System via Long-Range Meta-Path Progressive Sampling Search* (MDPI Information 2024/2026).
  - *Representation-enhanced APT Detection Using Contrastive Learning* (IEEE TrustCom 2023).
* **Đóng góp lý thuyết kế thừa:**
  - **Phân đoạn Đa Giai đoạn (Multi-Stage Semantic Partitioning):** Chứng minh rằng các cuộc tấn công APT có tính chất "Low-and-Slow", phân tán qua các giai đoạn khác biệt về mặt cấu trúc và tần suất sự kiện. Việc gộp chung toàn bộ cuộc tấn công thành một nhãn nhị phân duy nhất làm mất đi tính đặc trưng hành vi và gây khó khăn cho việc truy vết căn nguyên (Root Cause Analysis).
  - **Quy chuẩn 4 Pha Tấn công Cốt lõi của MITRE ATT&CK:** Đề xuất phân rã vòng đời tấn công của APT thành 4 pha chiến thuật chính: (1) Thâm nhập ban đầu, (2) Khảo sát và thực thi, (3) Lan truyền nội bộ, và (4) Thu thập & tuồn dữ liệu ra ngoài.

---

## 3. Hệ Thống 5 Giai đoạn Tấn công Chuẩn hóa (MITRE ATT&CK Mapping)

Từ việc hợp nhất 8 bước tấn công của ATLAS với cấu trúc 4 pha chiến thuật của APT-LMSPS và MITRE ATT&CK, toàn bộ dữ liệu trong `ATLASv2_staged` được quy chuẩn thành **5 giai đoạn rời rạc**:

| Stage ID | Tên Nhãn Giai đoạn | Chiến thuật MITRE ATT&CK Tương ứng | Mã vạch Thực thể & Tiến trình Tiêu biểu | Hành vi Kỹ thuật Đặc trưng |
| :---: | :--- | :--- | :--- | :--- |
| **0** | `Benign` | Normal Operations / Background | Dịch vụ Windows chuẩn (`svchost.exe`, `lsass.exe`, `explorer.exe`), lưu lượng ngày thường | Lưu lượng người dùng duyệt web thông thường, họp Zoom, cập nhật hệ thống, log trước mốc tấn công. |
| **1** | `Initial_Compromise` | Initial Access (TA0001), Execution (TA0002) | `plugin-container.exe`, `firefox.exe`, `winword.exe`, `excel.exe`, `eqnedt32.exe`, `mshta.exe` | Nạn nhân mở email phishing, kích hoạt lỗ hổng bộ nhớ Adobe Flash (CVE-2015-5122/5119/3105) hoặc Office (CVE-2017-11882/0199, CVE-2018-8174). |
| **2** | `Execution_Discovery` | Persistence (TA0003), Discovery (TA0007), Command & Control (TA0011) | `cmd.exe`, `powershell.exe`, `conhost.exe`, `regsvr32.exe`, `schtasks.exe`, `taskhost.exe` | Kẻ tấn công điều khiển Meterpreter shell, thực thi các lệnh trinh sát hệ thống (`whoami`, `netstat`, `ipconfig`), kiểm tra tiến trình, tiêm mã độc vào tiến trình hệ thống. |
| **3** | `Lateral_Movement` | Lateral Movement (TA0008), Defense Evasion (TA0005) | `python.exe` (SimpleHTTP), `explorer.exe` (ghi đè portal), toàn bộ tiến trình trên `h2` (`win-32-h2`) | Can thiệp làm sai lệch cổng thông tin web nội bộ trên `h1`, lừa máy trạm `h2` kết nối tới cổng web bị nhiễm và kích hoạt bản cập nhật giả mạo sang máy `h2`. |
| **4** | `Exfiltration` | Collection (TA0009), Exfiltration (TA0010) | `payload.exe`, kết nối HTTPS tới `10.193.66.115:8443` / `9999` | Tiến trình backdoor quét hệ thống tìm kiếm tài liệu nhạy cảm (`.pdf`), đóng gói và tuồn dữ liệu dồn dập ra máy chủ C&C qua kênh mạng mã hóa. |

---

## 4. Quy tắc Gán Nhãn Nhị phân 2 Tầng & Khắc phục "Nghịch lý Firefox"

Quy trình gán nhãn nhị phân cho từng sự kiện EDR được thực thi nghiêm ngặt thông qua lớp `LabelRefiner` ([label_refiner.py](file:///mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/preprocess/label_refiner.py)) theo cơ chế **Hai Tầng (Two-Tier Ground Truth Policy)**:

```
                  Sự kiện EDR Đầu vào (Canonical Event)
                                   │
                                   ▼
        [Kiểm tra 1: Sự kiện có thuộc Ngày 1–4 hay Kịch bản Benign?]
               ├── Có ──► Gán nhãn Benign (0) (100% Sạch!)
               └── Không (Thuộc Ngày 5 Attack Scenarios)
                                   │
                                   ▼
        [Kiểm tra 2: Timestamp < INITIAL_ATTACK_TIMESTAMPS?]
               ├── Có ──► Gán nhãn Benign (0) (Lọc bỏ VM Snapshot Startup!)
               └── Không (Sau mốc bắt đầu tấn công)
                                   │
                                   ▼
        [Kiểm tra 3: Process GUID có nằm trong REAPr Attack GUIDs?]
               ├── Không ──► Gán nhãn Benign (0)
               └── Có (Tiến trình bị nghi ngờ kiểm soát bởi Attacker)
                                   │
                                   ▼
        [Kiểm tra 4: Tiến trình có thuộc nhóm Dùng kép (Dual-Use) không?]
               ├── Có (Firefox / Office / Explorer / System Services)
               │      └── Phải thỏa mãn Quy tắc Hành vi Sâu (Deep Semantic Filter)
               │             ├── Khớp IOCs C2 IP / Domain / Seed? ──► Attack (1)
               │             ├── Tạo tiến trình con độc hại (cmd, payload)? ──► Attack (1)
               │             ├── Ghi file payload / script độc hại? ──► Attack (1)
               │             └── Ngược lại (Duyệt web bình thường, lưu tạm) ──► Benign (0)
               └── Không (Tiến trình thuần tấn công: payload.exe, cmd, powershell)
                      └── Áp dụng Định lý Cạnh Nhân quả (Causal Edge Principle)
                             ├── Nạp DLL hệ điều hành chuẩn / Đọc registry giao diện ──► Benign (0)
                             └── Thực thi lệnh, tiêm luồng, ghi payload, mạng C2 ──► Attack (1)
```

### 4.1. Cổng Thời gian Nghiêm ngặt (Temporal Gating)
Mọi sự kiện xảy ra trước mốc `INITIAL_ATTACK_TIMESTAMPS` của từng kịch bản đều bị ép nhãn `0` (Benign):
- `s1`: `2022-07-19 13:26:00 UTC`
- `s2`: `2022-07-19 14:07:00 UTC`
- `s3`: `2022-07-19 15:36:00 UTC` (lần chạy `s3take2`)
- `s4`: `2022-07-20 00:52:00 UTC`
- `m1`: `2022-07-19 17:20:00 UTC`
- `m2`: `2022-07-19 19:44:00 UTC`
- `m3`: `2022-07-19 20:28:00 UTC`
- `m4`: `2022-07-19 22:49:00 UTC`
- `m5`: `2022-07-19 23:38:00 UTC`
- `m6`: `2022-07-20 00:10:00 UTC`

### 4.2. Bộ lọc Ngữ cảnh Hành vi Sâu Cho Tiến trình Trình duyệt & Văn phòng
1. **Tiến trình Firefox (`firefox.exe`):**
   - Sự kiện mạng (`FLOW_START`): Chỉ gán `1` khi kết nối trực tiếp tới IP C2 (`10.193.66.115`), domain C2 (`ortrta.net`), hoặc các seed endpoint được chỉ định trong `.seeds` (ví dụ `34.107.221.82:80`). Mọi luồng truy cập Google, Cloudflare, Zoom, YouTube đều gán `0`.
   - Sự kiện File (`FILE_WRITE`, `FILE_CREATE`): Chỉ gán `1` khi ghi tệp thực thi (`.exe`, `.zip`) hoặc các tệp trong danh sách mã độc đã biết.
   - Sự kiện Tạo tiến trình (`PROCESS_START`): Chỉ gán `1` khi gọi `plugin-container.exe`, `cmd.exe`, `powershell.exe`, hoặc `payload.exe`.
2. **Tiến trình Microsoft Office (`winword.exe`, `excel.exe`):**
   - Sự kiện Tạo tiến trình (`PROCESS_START`): Chỉ gán `1` khi sinh ra các tiến trình khai thác (`cmd.exe`, `powershell.exe`, `eqnedt32.exe`, `mshta.exe`, `cscript.exe`, `payload.exe`).
   - Sự kiện File: Ghi tệp font (`.ttf`), tệp tạm Office autosave (`~*.tmp`, `.asd`, `.wbk`) được gán `0`. Chỉ gán `1` khi ghi các file thực thi/script (`.exe`, `.zip`, `.sct`, `.vbs`, `.hta`, `.ps1`).
   - Sự kiện Nạp module (`MODULE_LOAD`): Nạp các DLL chuẩn của Windows hoặc Office (`mso.dll`, `wwlib.dll`, `kernel32.dll`) được gán `0`. Chỉ gán `1` khi nạp các module thực thi mã lệnh nguy hiểm (`urlmon.dll`, `vbscript.dll`, `jscript.dll`, `scrobj.dll`).

---

## 5. Quy tắc Ánh xạ Chi tiết Từng Giai đoạn Tấn công (Stage Assignment Rules)

Hàm phân loại giai đoạn `classify_process_stage` ([add_stage_column.py](file:///mnt/SSD_Data/optc/DATASET/ATLASv2_staged/add_stage_column.py#L33-L92)) và phương thức `get_event_stage` ([label_refiner.py](file:///mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/preprocess/label_refiner.py#L306-L329)) tuân thủ các quy tắc logic xác định sau:

### Quy tắc 1: Stage 0 — `Benign`
- Nếu nhãn nhị phân của tiến trình hoặc sự kiện là `benign` (không chứa chuỗi `attack`).
- Hoặc sự kiện xảy ra trên các ngày nền (Ngày 1 đến Ngày 4).
- Hoặc sự kiện xảy ra trước mốc `INITIAL_ATTACK_TIMESTAMPS` của kịch bản.

### Quy tắc 2: Stage 4 — `Exfiltration`
- Áp dụng khi tiến trình thực thi có tên chứa **`payload.exe`**.
- Đây là tiến trình mã độc duy nhất được thiết kế để quét thư mục, thu gom các file tài liệu định dạng `.pdf` và mở luồng mạng HTTPS đẩy dữ liệu về C&C server. Bất kể tiến trình này chạy trên máy `h1` hay máy `h2`, toàn bộ hành vi của `payload.exe` đều đại diện cho giai đoạn tuồn dữ liệu cuối cùng của chiến dịch.

### Quy tắc 3: Stage 3 — `Lateral_Movement`
- **Thành phần trên Host 1 (`h1`):** 
  - Tiến trình **`python.exe`**: Đóng vai trò máy chủ SimpleHTTP nội bộ. Việc duy trì và bị can thiệp vào máy chủ này là cầu nối trực tiếp để lan truyền mã độc sang máy trạm thứ hai.
  - Tiến trình **`explorer.exe` trên `h1` trong các kịch bản đa máy chủ (`m1` đến `m6`)**: Được kẻ tấn công sử dụng để điều hướng, ghi đè tệp `index.html` của máy chủ SimpleHTTP thành trang phishing cập nhật hệ thống giả mạo.
- **Toàn bộ Thành phần trên Host 2 (`win-32-h2`):**
  - Mọi tiến trình bị kiểm soát bởi kẻ tấn công trên máy `h2` (ngoại trừ `payload.exe` thuộc Stage 4) đều được xếp vào giai đoạn **Lateral Movement**. Điều này phản ánh chính xác bản chất: toàn bộ sự hiện diện của kẻ tấn công trên máy trạm thứ hai bắt nguồn từ sự lan truyền thành công từ máy trạm thứ nhất.

### Quy tắc 4: Stage 1 — `Initial_Compromise`
- Áp dụng cho các vector thâm nhập và khai thác ban đầu trên máy `h1`:
  - **Khai thác Trình duyệt / Flash:** Tiến trình `firefox.exe` (khi thỏa mãn điều kiện tấn công) và tiến trình chứa container Flash `plugin-container.exe` (nơi trực tiếp kích hoạt các lỗ hổng heap overflow CVE-2015-5122, CVE-2015-5119, CVE-2015-3105).
  - **Khai thác Tài liệu Văn phòng (Office Exploits):** Các tiến trình `winword.exe`, `excel.exe`, trình xử lý công thức toán học cổ điển `eqnedt32.exe` (CVE-2017-11882), trình xử lý HTML Application `mshta.exe` (CVE-2017-0199, CVE-2018-8174), và dịch vụ cấp phép Office `osppsvc.exe`.

### Quy tắc 5: Stage 2 — `Execution_Discovery`
- Áp dụng cho các công cụ dòng lệnh, phiên điều khiển Meterpreter shell, và các kỹ thuật Living-off-the-Land sau khi đã khai thác thành công trên máy `h1`:
  - Các công cụ thực thi shell: `cmd.exe`, `powershell.exe`, `conhost.exe`.
  - Các công cụ quản trị hệ thống bị lạm dụng: `regsvr32.exe`, `schtasks.exe`.
  - Các tiến trình hệ thống bị tiêm mã hoặc giả mạo: `dllhost.exe`, `taskhost.exe`, `lsass.exe`, `audiodg.exe`.
  - Tiến trình `explorer.exe` trên máy `h1` trong các kịch bản đơn máy chủ (`s1` đến `s4`).

---

## 6. Hiện thực Hóa Mã Nguồn & Luồng Xử lý Dữ liệu

Quy trình gán nhãn và phân loại giai đoạn được tích hợp khép kín qua 3 tệp mã nguồn chính:

```
[reapr-ground-truth/*.labels] (Gốc: 5 cột)
             │
             ▼  Chạy: add_stage_column.py
[reapr-ground-truth/*.labels] (Nâng cấp: Thêm cột thứ 6 'stage')
             │
             ├──────────────────────────────────────────────┐
             ▼                                              ▼
[stage_mapper.py: AtlasStageRefiner]         [label_refiner.py: LabelRefiner]
(Ánh xạ GUID -> Stage Name & ID)             (Kiểm tra 2 tầng nhị phân + Gán Stage)
             │                                              │
             └──────────────────────┬───────────────────────┘
                                    │
                                    ▼
                 [build_network_shards.py / dataset.py]
    (Tạo cửa sổ trượt EDR 180s, gán nhãn đa tầng cho Shards nhị phân)
                                    │
                                    ▼
                [train_local.py: Dual-Head BiLSTM Training]
           (Huấn luyện đồng thời Anomaly Detection & Stage Classification)
```

1. **[add_stage_column.py](file:///mnt/SSD_Data/optc/DATASET/ATLASv2_staged/add_stage_column.py):**
   - Đọc từng tệp nhãn `*.labels` trong `reapr-ground-truth/atlasv2/`.
   - Phân tích cú pháp cột `process_name`, `process_uuid`, `label`, kết hợp với định danh `host` và `scenario`.
   - Gọi hàm `classify_process_stage` và ghi trực tiếp cột `stage` vào tệp nhãn.
2. **[stage_mapper.py](file:///mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/preprocess/stage_mapper.py):**
   - Cung cấp lớp đối tượng `AtlasStageRefiner`. Nạp toàn bộ ánh xạ `process_guid -> (stage_name, stage_id)` vào bộ nhớ RAM, phục vụ việc tra cứu với độ phức tạp $O(1)$ trong quá trình xử lý stream log.
3. **[label_refiner.py](file:///mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/preprocess/label_refiner.py):**
   - Quản lý logic gán nhãn nhị phân sự kiện (`is_event_malicious`) và định danh giai đoạn sự kiện (`get_event_stage`). Tự động tích hợp bộ lọc thời gian và danh mục IOCs.

---

## 7. Thống kê Thực nghiệm Phân bố Nhãn trên Toàn bộ Tập Dữ liệu

### 7.1. Phân bố Mức Tiến trình (Process-Level Distribution trong REAPr)
Sau khi thực thi `add_stage_column.py` trên toàn bộ 16 tệp `.labels` của REAPr, tổng cộng **191 tiến trình độc hại** được phân loại chính xác vào 4 giai đoạn tấn công:

| Giai đoạn Tấn công (Stage) | Tên Nhãn Phân loại | Số lượng Tiến trình Độc hại | Tỷ lệ Phần trăm (%) |
| :---: | :--- | :---: | :---: |
| **Stage 1** | `Initial_Compromise` | 49 | 25.65% |
| **Stage 2** | `Execution_Discovery` | 84 | 43.98% |
| **Stage 3** | `Lateral_Movement` | 26 | 13.61% |
| **Stage 4** | `Exfiltration` | 32 | 16.75% |
| **Tổng cộng**| **Toàn bộ Tiến trình Tấn công** | **191** | **100.00%** |

### 7.2. Phân bố Mức Cửa sổ Thời gian (Window-Level Distribution - Cửa sổ 180s, Trượt 60s)
Khi chuyển đổi dữ liệu EDR thành các chuỗi sự kiện được đóng khung theo cửa sổ trượt 180 giây phục vụ mô hình BiLSTM:

| Phân vùng (Split) | Tổng Mẫu Cửa sổ | Mẫu Lành tính (Stage 0) | Stage 1 (InitComp) | Stage 2 (ExecDisc) | Stage 3 (LatMov) | Stage 4 (Exfil) | Tổng Mẫu Dương | Tỷ lệ Lành tính : Dương |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **TRAIN** | 4,642 | 4,562 | 10 | 12 | 18 | 40 | 80 | **57.0 : 1** |
| **VAL** | 1,960 | 1,920 | 2 | 5 | 12 | 21 | 40 | **48.0 : 1** |
| **TEST** | 2,369 | 2,331 | 8 | 4 | 8 | 18 | 38 | **61.3 : 1** |
| **Tổng ATLASv2** | **8,971** | **8,813** | **20** | **21** | **38** | **79** | **158** | **55.8 : 1** |
| **OpTC Test** | 332 | 250 | — | — | — | — | 82 | **3.0 : 1** |

---

## 8. Quy trình Kiểm chứng & Đảm bảo Tính Toàn vẹn Dữ liệu

Để đảm bảo tính nhất quán khoa học và không bị rò rỉ dữ liệu (Data Leakage):
1. **Bảo tồn Phân vùng Độc lập (Scenario Split Isolation):**
   - Tập huấn luyện (TRAIN), kiểm định (VAL) và kiểm thử (TEST) được chia cắt hoàn toàn theo kịch bản (Scenario-level split):
     - `TRAIN`: Kịch bản `s1`, `s2`, `s3`, `m1`, `m2`, `m4` cùng dữ liệu nền Ngày 1–2.
     - `VAL`: Kịch bản `m3`, `m5` cùng dữ liệu nền Ngày 3.
     - `TEST`: Kịch bản `s4`, `m6` cùng dữ liệu nền Ngày 4–5.
   - Không có sự chồng chéo kịch bản giữa tập huấn luyện và tập kiểm thử.
2. **Quy tắc Bất biến Tập Dữ liệu Gốc:**
   - Thư mục dữ liệu gốc `DATASET/ATLASv2/` và các thư mục đọc-chỉ (`host-begnin/`, `host-malicious/`, `ecar-bro/`, `bro/`) được giữ nguyên trạng thái Read-Only tuyệt đối. Mọi can thiệp thêm cột `stage` chỉ được thực hiện trên bản sao phân nhánh độc lập `DATASET/ATLASv2_staged/`.
3. **Kiểm tra Tính Nhất quán Phân tầng (Hierarchical Consistency Check):**
   - Trong quá trình suy luận của mô hình, nhãn giai đoạn $\hat{Y}_{\text{stage}}$ luôn luôn nhất quán với nhãn nhị phân: một mẫu chỉ có thể mang nhãn giai đoạn $1, 2, 3, 4$ khi xác suất phát hiện bất thường $P(\text{Anomaly}) \ge \tau$. Nếu $P(\text{Anomaly}) < \tau$, nhãn giai đoạn bắt buộc phải là $0$ (`Benign`).
