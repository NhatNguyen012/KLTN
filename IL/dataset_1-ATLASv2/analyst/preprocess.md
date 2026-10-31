# BÁO CÁO KỸ THUẬT: ĐẶC TẢ QUY TRÌNH TIỀN XỬ LÝ DATASET ATLASv2 CHO INCREMENTAL LEARNING (OpTC → ATLASv2)

> **Mục tiêu tài liệu:** Đặc tả chi tiết, chính xác 100% về mặt toán học, ngữ nghĩa an ninh mạng và mã nguồn thực thi để chuyển đổi dữ liệu thô từ bộ dữ liệu **ATLASv2** thành định dạng đầu vào chuẩn tắc (canonical representation) phục vụ huấn luyện tăng tiến (**Domain-Incremental Learning**) cho hai mô hình: **Host ML (LightGBM)** và **Network DL (BiLSTM)** vốn đã được huấn luyện trên **DARPA OpTC**.

---

## 1. TỔNG QUAN KIẾN TRÚC TIỀN XỬ LÝ (PIPELINE CONTRACT)

Hệ thống tiền xử lý được thiết kế theo mô hình phân tầng độc lập (modular architecture) nhằm đảm bảo dữ liệu thô được chuẩn hóa về cùng một hợp đồng không gian đặc trưng (Feature Contract) với DARPA OpTC mà không làm phá vỡ các checkpoint mô hình đã huấn luyện:

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 ATLASv2 RAW TELEMETRY                   │
                  │   /data/benign|attack/h1|h2/cbc-edr/*.jsonl (Primary)   │
                  │   reapr-ground-truth/atlasv2/*.labels & *.seeds         │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ GIAI ĐOẠN 1: TINH LỌC NHÃN & KHỬ NHIỄU (LABEL REFINEMENT & DE-NOISING)                       │
│ • Áp dụng mốc thời gian Initial Attack Step (Temporal Gate Filtering)                      │
│ • Giao tập với danh mục Known Attack Entities / IOCs (Entity-level Filtering)              │
│ • Triệt tiêu 99.16% flow dương giả của Firefox (Giải quyết triệt để "Nghịch lý Firefox")   │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ GIAI ĐOẠN 2: TẦNG INGESTION ADAPTER & CANONICAL MAPPING                                     │
│ • Streaming nạp JSONL từ CBC-EDR (procstart, netconn, filemod, regmod, modload, crossproc)  │
│ • Chuẩn hóa trường về Common Event Schema tương thích eCAR                                  │
│ • Sắp xếp nhân quả nghiêm ngặt theo UTC epoch microsecond (Strict Causal Ordering)          │
└───────────────────────┬─────────────────────────────────────────────┬───────────────────────┘
                        │                                             │
                        ▼                                             ▼
┌───────────────────────────────────────────────┐ ┌───────────────────────────────────────────┐
│ GIAI ĐOẠN 3: ĐẶC TRƯNG HOST ML (LIGHTGBM)     │ │ GIAI ĐOẠN 4: ĐẶC TRƯNG NETWORK DL (BILSTM)│
│ • Token hóa cú pháp lệnh an toàn (Syntax AST) │ │ • Cắt cửa sổ trượt 15 phút (900s)         │
│ • Theo dõi phả hệ & ngữ cảnh cha (Lineage)   │ │ • Trích xuất 5 features (Phương án B):    │
│ • Phân nhóm tài khoản (Principal buckets)     │ │   app_family, image_dir_class, proto,    │
│ • Hành vi can thiệp chéo (crossproc incoming) │ │   resp_port_class, delta_t_log1p          │
│ • CHÍNH SÁCH ĐÓNG BĂNG & MỞ RỘNG VOCAB.JSON   │ │ • Khớp ID với network_category_maps.json  │
│   (Frozen OpTC Vocab + Monotonic Extension)   │ │ • Gán nhãn cửa sổ dựa trên Event sạch     │
└───────────────────────┬───────────────────────┘ └───────────────────────────┬───────────────┘
                        │                                             │
                        └───────────────────────┬─────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ GIAI ĐOẠN 5: CHIA TẬP DỮ LIỆU SUPERVISED CHUẨN MỰC & BỘ ĐỆM REPLAY CHO DOMAIN-IL            │
│ • Phân chia theo Kịch bản kết hợp Ngày lành tính: 60% Train - 20% Val - 20% Test            │
│ • Đảm bảo cả Train, Val, Test đều có đầy đủ nhãn Benign (0) và Attack (1)                   │
│ • Undersampling phần Benign nền Ngày 1-2 để kiểm soát mất cân bằng lớp (Class Imbalance)    │
│ • Kẹp Experience Replay Buffer (chứa cả Benign + Attack từ OpTC) vào mỗi mini-batch         │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. GIAI ĐOẠN 1: TINH LỌC VÀ CHUẨN HÓA NHÃN GROUND TRUTH

### 2.1. Bản chất vấn đề và Cơ sở học thuật
Trong tập nhãn `reapr-ground-truth`, nhóm STS-Lab gán nhãn ở **cấp độ Tiến trình bị kiểm soát (Process-level)** phục vụ bài toán đồ thị truy vết nguyên nhân gốc rễ (Root Cause Analysis). Khi một người dùng mở email lừa đảo hoặc click link khai thác trên Firefox, toàn bộ tiến trình `firefox.exe` bị đánh dấu là "attack". 

Hệ quả là trong tổng số 7,761 kết nối mạng (`netconn`) bị gán nhãn dương, có tới **7,696 flow (chiếm 99.16%) phát sinh từ `firefox.exe`**, mặc dù phần lớn các kết nối này là hoạt động duyệt web bình thường (Google, Zoom, Discord, YouTube) của hai nhà nghiên cứu trong quá trình làm việc. Nếu đưa thẳng vào mô hình, BiLSTM và LightGBM sẽ bị hiện tượng **học đường tắt giả mạo (Spurious Shortcut Learning)**: cứ thấy `firefox.exe` là kết luận tấn công, dẫn tới bùng nổ tỷ lệ báo động giả (FPR).

Cơ sở khoa học để xử lý vấn đề này được khẳng định đồng nhất qua hai công trình nghiên cứu trên cùng bộ dữ liệu:
1. **DEEPDIST (IEEE TrustCom 2023):** Khẳng định trong *Challenge 1* và *Motivation*: Tiến trình Firefox bị thỏa hiệp chỉ thực sự kết nối tới hạ tầng độc hại và fork ra tiến trình con độc hại (`plugin-container` $\rightarrow$ `cmd` $\rightarrow$ `payload.exe`), còn vô số kết nối mạng và tệp tin khác là hoàn toàn lành tính. Nhóm tác giả áp dụng nén đồ thị và nhiễu loạn tương phản (Contrastive Perturbation) để ép mô hình bỏ qua các tương tác web lành tính của Firefox.
2. **APT-LMSPS (MDPI Information 2026):** Chứng minh trạng thái ngữ nghĩa của tiến trình chỉ chuyển dịch từ lành tính sang độc hại sau thời điểm bị kích hoạt khai thác. Họ sử dụng phân đoạn lành tính trước tấn công (*pre-attack benign segments*) và loại bỏ các sự kiện lặp lại không làm đổi trạng thái ngữ nghĩa.

### 2.2. Danh mục Thực thể Độc hại Đã biết (Known Attack Entities / IOCs)
Dựa trên tài liệu công bố của ATLASv2, các tệp mầm mống `reapr-ground-truth/atlasv2/*.seeds` và cấu hình tấn công từ máy Kali Linux (`10.193.66.115`), danh mục IOCs chuẩn bao gồm:

* **Địa chỉ IP và Cổng C&C (Network Endpoints):**
  * `10.193.66.115:9999` (Meterpreter Reverse TCP Shell).
  * `10.193.66.115:8443` (HTTPS Exfiltration Channel).
  * `ortrta.net` (Tên miền độc hại).
  * `192.168.223.129:8000` hoặc cổng HTTP trên `h1` nơi lưu trang web nội bộ giả mạo phục vụ di chuyển ngang (Lateral Movement).
  * Các địa chỉ IP / URL chứa payload ban đầu ghi trong các tệp `.seeds`.
* **Tệp tin độc hại (Malicious Files & Payloads):**
  * `payload.exe` (Backdoor thu thập và tuồn dữ liệu).
  * Các gói khai thác: `s3take2.zip`, `s4-at-night.zip`, `m4.zip`, `m5-2.zip`, `m6.zip`, `msf.doc`.
* **Tiến trình độc hại thuần túy (Pure Attack Processes - 100% Malicious):**
  * Mọi thể hiện của `payload.exe`.
  * Các tiến trình con sinh ra từ lỗ hổng tài liệu Office hoặc Flash: `cmd.exe`, `powershell.exe`, `audiodg.exe` (bị lợi dụng inject), `RepWmiUtils.exe` (khi bị lạm dụng).
* **Mốc thời gian bắt đầu tấn công (Initial Attack Timestamps - UTC):**
  * `s1`: `2022-07-19 13:26:00`
  * `s2`: `2022-07-19 14:07:00`
  * `s3`: `2022-07-19 15:36:00`
  * `s4`: `2022-07-20 00:52:00`
  * `m1`: `2022-07-19 17:20:00`
  * `m2`: `2022-07-19 19:44:00`
  * `m3`: `2022-07-19 20:28:00`
  * `m4`: `2022-07-19 22:49:00`
  * `m5`: `2022-07-19 23:38:00`
  * `m6`: `2022-07-20 00:10:00`

### 2.3. Quy tắc Gán nhãn Sự kiện Hai tầng (Two-Tier Event Labeling Rule)

Mỗi sự kiện thô $e$ trong ATLASv2 được gán nhãn nhị phân $y(e) \in \{0, 1\}$ theo thuật toán sau:

```python
def assign_event_label(event, scenario_name, scenario_attack_time, reapr_attack_guids, ioc_endpoints, ioc_files):
    # Quy tắc 1: Lọc theo trục thời gian tuyệt đối
    if event.timestamp < scenario_attack_time:
        return 0  # Toàn bộ sự kiện trước mốc tấn công là 100% Benign
    
    # Quy tắc 2: Tiến trình không nằm trong danh sách nghi ngờ của REAPr
    if event.process_guid not in reapr_attack_guids:
        return 0  # Các tiến trình hệ thống sạch độc lập là 0
        
    proc_name = extract_basename(event.process_path).lower()
    
    # Quy tắc 3: Xử lý riêng biệt cho tiến trình lưỡng dụng (Firefox.exe)
    if proc_name == "firefox.exe":
        # Sự kiện mạng của Firefox
        if event.type == "endpoint.event.netconn":
            is_c2 = (event.remote_ip in ioc_endpoints["ips"] or 
                     event.remote_port in ioc_endpoints["ports"] or 
                     ioc_endpoints["domain"] in (event.netconn_domain or ""))
            return 1 if is_c2 else 0
        # Sự kiện ghi file của Firefox
        elif event.type == "endpoint.event.filemod":
            is_mal_file = any(mal_f in (event.filemod_name or "").lower() for mal_f in ioc_files)
            return 1 if is_mal_file else 0
        # Sự kiện tạo tiến trình con từ Firefox
        elif event.type == "endpoint.event.procstart":
            child_name = extract_basename(event.childproc_name or "").lower()
            return 1 if child_name in ["cmd.exe", "powershell.exe", "payload.exe", "plugin-container.exe"] else 0
        return 0
        
    # Quy tắc 4: Các tiến trình hậu khai thác độc hại thuần túy
    if proc_name == "payload.exe" or "meterpreter" in proc_name:
        return 1
        
    # Quy tắc 5: Các tiến trình con nằm trong chuỗi tấn công của REAPr
    return 1
```

---

## 3. GIAI ĐOẠN 2: TẦNG INGESTION ADAPTER & CANONICAL MAPPING

### 3.1. Lý do lựa chọn Carbon Black Cloud EDR (`cbc-edr/*.jsonl`) làm nguồn nạp chính
1. **Khớp nối nhãn 100%:** File nhãn `reapr-ground-truth` lưu mã định danh tiến trình dưới dạng CBC GUID (ví dụ: `7DMF69PK-05e5f750-00000218-00000000-1d89b87dbe5b471`). Chỉ có `cbc-edr` chứa trường `process_guid` và `parent_guid` trùng khớp hoàn toàn, loại bỏ việc join mờ theo PID/thời gian.
2. **Hiệu năng xử lý:** Dữ liệu dạng JSONL cho phép xử lý dòng (streaming line-by-line), tránh nghẽn bộ nhớ so với việc parse các file XML khổng lồ của Sysmon.
3. **Bao phủ toàn diện:** `cbc-edr` chứa đầy đủ 7 loại sự kiện tương ứng với eCAR: tiến trình, luồng mạng, tệp tin, registry, nạp module và can thiệp chéo.

### 3.2. Bảng ánh xạ từ CBC-EDR sang Lược đồ Sự kiện Chuẩn tắc (Canonical Schema)

Mỗi dòng JSON trong `cbc-edr/*.jsonl` được chuyển đổi thành cấu trúc đối tượng `CanonicalEvent`:

| Trường Chuẩn tắc (Canonical Field) | Kiểu dữ liệu | Nguồn trường từ CBC-EDR | Ghi chú & Chuẩn hóa |
| :--- | :--- | :--- | :--- |
| `event_id` | `str` | Sinh mã UUID ngẫu nhiên hoặc hash `(device_id, process_guid, device_timestamp)` | Khóa duy nhất xác định sự kiện |
| `timestamp` | `int` | `device_timestamp` | **Bắt buộc dùng `device_timestamp` (local sensor), không dùng `backend_timestamp`.** Parse sang UTC epoch microsecond |
| `hostname` | `str` | `device_name` | Chuyển thành chữ thường: `win-32-h1` hoặc `win-32-h2` |
| `event_type` | `str` | `type` | Ánh xạ: `procstart` $\rightarrow$ `PROCESS_START`, `netconn` $\rightarrow$ `FLOW_START`, `filemod` $\rightarrow$ `FILE_WRITE`, v.v. |
| `process_guid` | `str` | `process_guid` | Chuẩn hóa lowercase |
| `parent_guid` | `str` | `parent_guid` | Chuẩn hóa lowercase |
| `process_path` | `str` | `process_path` | Chuẩn hóa đường dẫn Windows (lowercase, normalize backslash) |
| `process_cmdline`| `str` | `process_cmdline` | Giữ nguyên văn bản gốc phục vụ phân tích cú pháp lệnh |
| `parent_path` | `str` | `parent_path` | Đường dẫn file thực thi của tiến trình cha |
| `parent_cmdline` | `str` | `parent_cmdline` | Dòng lệnh của tiến trình cha |
| `username` | `str` | `process_username` | Ví dụ: `NT AUTHORITY\SYSTEM` hoặc `WIN-32-H2\aalsahee` |
| `target_path` | `str` | Tùy loại sự kiện:<br>- `filemod`: `filemod_name`<br>- `regmod`: `regmod_name`<br>- `moduleload`: `modload_name`<br>- `crossproc`: `crossproc_name` | Đường dẫn file/registry/module mục tiêu |
| `target_guid` | `str` | `crossproc_guid` (trong sự kiện `crossproc`) | GUID của tiến trình mục tiêu bị mở handle hoặc tiêm thread |
| `proto` | `str` | `netconn_protocol` | Ánh xạ: `"PROTO_TCP"` $\rightarrow$ `"tcp"`, `"PROTO_UDP"` $\rightarrow$ `"udp"` |
| `remote_ip` | `str` | `remote_ip` | Địa chỉ IP máy đích |
| `remote_port` | `int` | `remote_port` | Cổng dịch vụ từ xa (chuyển float sang int) |
| `local_port` | `int` | `local_port` | Cổng nội bộ |
| `inbound` | `bool` | `netconn_inbound == 1.0` | Cờ xác định chiều kết nối (Inbound/Outbound) |

---

## 4. GIAI ĐOẠN 3: TRÍCH XUẤT ĐẶC TRƯNG CHO HOST ML (LIGHTGBM)

Mô hình LightGBM yêu cầu đầu vào là các vector thưa biểu diễn token ngữ nghĩa nhị phân. Các đặc trưng phải khớp 100% với hợp đồng của [ecar_tokenizer.py](file:///mnt/SSD_Data/optc/ML/code/preprocess/ecar_tokenizer.py) và [process_context_tracker.py](file:///mnt/SSD_Data/optc/ML/code/preprocess/process_context_tracker.py).

### 4.1. Trích xuất Token Tiến trình & Cú pháp Dòng lệnh
Từ `process_path` và `process_cmdline`, bộ chuyển đổi thực hiện:
1. **Basename & Thư mục:**
   * Trích xuất tên tệp thực thi: `basename = ntpath.basename(process_path).lower()` $\rightarrow$ Tạo token: `anchor::launcher=<basename>`.
   * Phân loại thư mục lưu trữ: Ánh xạ đường dẫn thành các nhóm cố định: `SYSTEM32`, `PROGRAM_FILES`, `TEMP_OR_APPDATA`, `WINDOWS_OTHER`, `USERS_OTHER`, `OTHER`.
2. **Họ lệnh & Tham số (Command Family & Switches):**
   * Xác định họ lệnh thông qua `command_syntax.py`: `cmd`, `powershell`, `python`, `wscript`, `cscript`, `rundll32`, `native`.
   * Quét và trích xuất các tham số dòng lệnh (switches): `/c`, `/v`, `-enc`, `-executionpolicy`, `-w hidden` $\rightarrow$ Tạo token: `cmd::switch=<switch_name>`.
3. **Giải mã Base64 an toàn (Safe Base64 Decoding):**
   * Nếu dòng lệnh chứa cờ `-enc` hoặc chuỗi base64 dài $\ge 40$ ký tự: thực hiện giải mã nhị phân mà không thực thi, giải nén UTF-16LE, đưa qua parser đệ quy để bắt thêm các token lệnh ngầm (ví dụ: `IEX`, `DownloadString`).
4. **Chuẩn hóa đối tượng động (Dynamic Operand Normalization):**
   * Toàn bộ UUID, SID, địa chỉ IP, địa chỉ bộ nhớ Hex, số nguyên dài được thay thế bằng các nhãn vị trí (placeholder): `<UUID>`, `<SID>`, `<IPV4>`, `<HEX_ADDR>`, `<NUM>`. Tuyệt đối không sinh token cho giá trị cụ thể.

### 4.2. Xây dựng Ngữ cảnh Tiến trình Cha (Parent Context & Lineage Tracking)
Sử dụng bộ nhớ trạng thái nhân quả LRU (`ProcessContextTracker`) với ràng buộc thời gian nghiêm ngặt ($t_{parent} < t_{event}$):
1. **Liên kết Phả hệ (Process Lineage):**
   * Khi bắt gặp tiến trình, tra cứu `parent_guid` trong bộ đệm.
   * Tạo token quan hệ phả hệ: `ctx::relation::lineage=<parent_family>-><child_family>` (ví dụ: `ctx::relation::lineage=firefox->cmd` hoặc `ctx::relation::lineage=explorer->firefox`).
2. **Độ trễ khởi tạo (Spawn Recency Bucket):**
   * Tính $\Delta t = t_{child} - t_{parent}$. Ánh xạ vào các khoảng thời gian hữu hạn: `lt_1s`, `lt_10s`, `lt_1m`, `lt_5m`, `lt_15m`, `gt_1h` $\rightarrow$ Tạo token: `ctx::relation::spawn_recency=<bucket>`.
3. **Trạng thái tài khoản cha-con (Principal Equality):**
   * Kiểm tra quyền của cha và con: `ctx::relation::same_principal_class=true` hoặc `false` (nhận diện hành vi leo thang đặc quyền).

### 4.3. Phân nhóm Quyền Tài khoản (Principal Bucketing)
Chuỗi `process_username` được ánh xạ thành các nhóm ngữ nghĩa cố định:
* Nếu chứa `nt authority\system`, `nt service`, `font driver host` $\rightarrow$ `principal::system_account`.
* Nếu chứa `administrator` $\rightarrow$ `principal::administrator`.
* Nếu là tài khoản domain/local thông thường (`aalsahee`) $\rightarrow$ `principal::domain_user` hoặc `local_user`.
* Rỗng $\rightarrow$ `principal::none`.

### 4.4. Thao tác Đối tượng và Can thiệp Chéo (Object Actions & Incoming Events)
* **File Operations (`endpoint.event.filemod`):**
  * Hành động: map sang `action::create`, `action::write`, `action::delete`, `action::open`.
  * Đường dẫn file: trích xuất extension (`.exe`, `.zip`, `.pdf`, `.doc`) và category thư mục.
* **Registry Operations (`endpoint.event.regmod`):**
  * Nhận diện các khóa nhạy cảm: `Run`, `RunOnce`, `Services`, `Explorer\UserAssist` $\rightarrow$ Tạo token ngữ nghĩa khóa Registry, không lưu key literal.
* **Module Loads (`endpoint.event.moduleload`):**
  * Tạo token: `module::basename=<dll_name>`.
* **Cross-Process Interactions (`endpoint.event.crossproc`):**
  * Hành động `ACTION_OPEN_PROCESS_HANDLE` $\rightarrow$ Ghi nhận vào hàng đợi `incoming` của tiến trình đích với nhãn `ctx::incoming::process_open`.
  * Hành động `ACTION_OPEN_THREAD_HANDLE` hoặc inject $\rightarrow$ Ghi nhận `ctx::incoming::thread_remote_create`.

### 4.5. Chính sách Đóng băng & Mở rộng Từ điển `vocab.json` (Strict Vocab Freeze & Monotonic Extension)

> [!IMPORTANT]
> **Nguyên tắc đóng băng tuyệt đối (Frozen Vocab Contract):** 
> File [vocab.json](file:///mnt/SSD_Data/optc/ML/code/output/host_ml_seed02/vocab.json) của OpTC ($N$ tokens với index từ $0$ đến $N-1$) là **BẤT BIẾN (IMMUTABLE / READ-ONLY)**. Mọi thứ tự cột, định danh chỉ số và trọng số đã học của mô hình LightGBM trên OpTC bắt buộc phải được bảo toàn nguyên trạng. Tuyệt đối không được fit lại từ đầu, không sắp xếp lại (re-sort) hay xóa bớt token cũ.

Khi xử lý tập dữ liệu mới ATLASv2, các token mới xuất hiện sẽ được xử lý theo **Quy tắc Mở rộng Đơn điệu (Monotonic Extension)**:

```
OpTC Frozen Vocab:  [Token_0: 0,  Token_1: 1,  ... , Token_{N-1}: N-1]  <-- KHÔNG ĐỔI
                                                              │
ATLASv2 New Tokens:                                           ▼ Append mới
Extended Vocab:     [ ... , Token_{N-1}: N-1, Token_N: N, Token_{N+1}: N+1, ... ]
```

1. **Khởi tạo:** Nạp toàn bộ $N$ tokens từ `vocab.json` của OpTC làm gốc.
2. **Ghi nhận Token mới:** Quét toàn bộ tập **TRAIN của ATLASv2** (theo phân chia kịch bản ở Mục 6). Với mỗi token mới $t \notin \text{Vocab}_{OpTC}$:
   * Gán index mới: $\text{Index}(t) = N + k$ ($k = 0, 1, 2, \dots$).
   * Xuất ra file riêng: `vocab_extended.json` và `vocab_extension_metadata.json` (ghi rõ token nào thuộc OpTC, token nào mới sinh từ ATLASv2).
3. **Cơ chế Thích ứng trên LightGBM:**
   * **Chế độ 1 (Baseline Zero-shot & Direct IL):** Chỉ bật các cột nằm trong khoảng $[0, N-1]$. Các token mới $> N-1$ bị coi là Out-of-Distribution (OOD / Unknown), đảm bảo ma trận đầu vào khớp 100% shape $N$ cột để nạp vào `lgb.Booster(model_file=optc_checkpoint)` tiếp tục boosting bằng `init_model`.
   * **Chế độ 2 (Elastic GBDT / Residual Boosting):** Mở rộng ma trận lên $N+M$ cột. Giữ nguyên mô hình cơ sở $f_{old}(x_{0:N-1})$ từ OpTC, huấn luyện thêm cây phần dư $g(x_{0:N+M-1})$ trên không gian mở rộng với giá trị khởi tạo `init_score = f_{old}(x)`.

---

## 5. GIAI ĐOẠN 4: TRÍCH XUẤT ĐẶC TRƯNG CHO NETWORK DL (BILSTM)

Theo đúng kiến trúc [06d_BiLSTM_Kaggle_v2_final.ipynb](file:///mnt/SSD_Data/optc/DL/04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb) (Phương án B), mô hình chỉ sử dụng đúng **5 đặc trưng** trên từng sự kiện mạng trong chuỗi.

### 5.1. Phân chia Cửa sổ Trượt (Windowing)
* Dữ liệu luồng mạng (`endpoint.event.netconn`) được gom nhóm theo cặp: `(hostname, floor(timestamp / 900_000_000))` (cửa sổ cố định 15 phút = 900 giây theo chuẩn UTC).
* Trong mỗi cửa sổ, các flow được sắp xếp tăng dần theo `timestamp`.
* Cắt chuỗi thành các chunk có độ dài tối đa $T = 512$ sự kiện.

### 5.2. Công thức và Mã hóa 5 Đặc trưng Đầu vào

```
                        ┌────────────────────────────────────────────────────────┐
                        │             5 INPUT FEATURES FOR BILSTM                │
                        └────────────────────────────────────────────────────────┘
                                 │                                       │
                  ┌──────────────┴──────────────┐                 ┌──────┴──────┐
                  ▼ Categorical (Embedding)     ▼                 ▼ Continuous  ▼
            [app_family]                  [proto]                 [delta_t_log1p]
          [image_dir_class]          [resp_port_class]
```

1. **Đặc trưng 1: `app_family` (Categorical ID)**
   * Lấy `basename` chữ thường của `process_path`: `firefox.exe`, `cmd.exe`, `payload.exe`.
   * Tra cứu ID trong `network_category_maps.json` của OpTC. Nếu là tiến trình mới chưa từng thấy ở OpTC $\rightarrow$ Gán ID reserved `<UNK> = 0`. Nếu thiếu giá trị $\rightarrow$ `<MISSING> = 1`.
2. **Đặc trưng 2: `image_dir_class` (Categorical ID)**
   * Đánh giá theo thứ tự ưu tiên:
     * Chứa `\temp\` hoặc `\appdata\` $\rightarrow$ `TEMP_OR_APPDATA`
     * Chứa `\windows\system32\` hoặc `\syswow64\` $\rightarrow$ `SYSTEM32`
     * Chứa `\program files\` hoặc `\program files (x86)\` $\rightarrow$ `PROGRAM_FILES`
     * Chứa `\windows\` $\rightarrow$ `WINDOWS_OTHER`
     * Chứa `\users\` $\rightarrow$ `USERS_OTHER`
     * Còn lại $\rightarrow$ `OTHER`
   * Ánh xạ chuỗi danh mục sang integer ID theo từ điển OpTC.
3. **Đặc trưng 3: `proto` (Categorical ID)**
   * Chuẩn hóa chuỗi `netconn_protocol`: `"PROTO_TCP"` $\rightarrow$ `"tcp"`, `"PROTO_UDP"` $\rightarrow$ `"udp"`, còn lại $\rightarrow$ `<UNK>`.
   * Ánh xạ sang ID theo bảng từ điển giao thức OpTC.
4. **Đặc trưng 4: `resp_port_class` (Categorical ID)**
   * Xác định cổng responder:
     $$\text{resp\_port} = \begin{cases} \text{remote\_port}, & \text{nếu } \text{inbound} == \text{False (Outbound)} \\ \text{local\_port}, & \text{nếu } \text{inbound} == \text{True (Inbound)} \end{cases}$$
   * Phân loại cổng vào các nhóm cố định:
     * $80 \rightarrow \text{HTTP\_80}$
     * $443 \rightarrow \text{HTTPS\_443}$
     * $53 \rightarrow \text{DNS\_53}$
     * $445 \rightarrow \text{SMB\_445}$
     * $9999, 8443 \rightarrow \text{EPHEMERAL\_HIGH}$ (do $\ge 1024$)
     * $\ge 1024 \rightarrow \text{EPHEMERAL\_HIGH}$
     * Còn lại $\rightarrow \text{WELL\_KNOWN\_OTHER}$
5. **Đặc trưng 5: `delta_t_log1p` (Continuous 1D Float)**
   * Với sự kiện đầu tiên trong chunk: $\Delta t = 0.0$.
   * Với các sự kiện tiếp theo $i \ge 1$: $\Delta t = \max(0.0, (t_i - t_{i-1}) / 10^6)$ (khoảng cách thời gian tính bằng giây).
   * Giá trị đặc trưng:
     $$x_{delta} = \ln(1.0 + \Delta t)$$

### 5.3. Căn chỉnh Kích thước Tensor (Tensor Alignment)
Để tương thích với kiến trúc mạng `BiLSTMBaseline` đã lưu trong checkpoint:
* Tensor Categorical `x_cat`: Shape `(B, T, 4)` chứa 4 cột theo đúng thứ tự: `[app_family, proto, resp_port_class, image_dir_class]`.
* Tensor Số `x_num` và `x_num_missing`: Shape `(B, T, 0)` (0 cột, do Phương án B đã bỏ các trường số của Bro).
* Tensor Nhị phân `x_bin`: Shape `(B, T, 1)` đặt giá trị hằng số $0.0$.
* Tensor Thời gian `delta_t_log1p`: Shape `(B, T, 1)`.

### 5.4. Quy tắc Gán nhãn Cửa sổ Chuỗi (Window-level Target Label)
* Một cửa sổ 15 phút được gán nhãn $Y = 1$ (Positive/Malicious) khi và chỉ khi: **Tồn tại ít nhất một sự kiện mạng bên trong cửa sổ đó có nhãn $y(e) = 1$** (đã được tinh lọc qua Giai đoạn 1).
* Nếu toàn bộ các sự kiện trong cửa sổ đều có $y(e) = 0$ $\rightarrow$ Gán nhãn $Y = 0$ (Negative/Benign).

---

## 6. GIAI ĐOẠN 5: CHIẾN LƯỢC CHIA TẬP DỮ LIỆU SUPERVISED CHUẨN MỰC & BỘ ĐỆM REPLAY

### 6.1. Bắt buộc Cân bằng Hai Lớp (Supervised Binary Constraint)
Vì cả LightGBM và BiLSTM đều là **mô hình phân loại nhị phân có giám sát (Supervised Binary Classification)**:
* **Hạn chế của việc chia ngây thơ:** Nếu lấy toàn bộ 4 ngày đầu thuần Benign làm tập Train và Ngày 5 (Attack Day) làm Test, tập Train sẽ hoàn toàn không có nhãn `1`. Mô hình học tăng cường sẽ bị "sốc phân phối" (Gradient Collapse), quên sạch khái niệm lớp tấn công.
* **Hạn chế của Random Split:** Nếu chia ngẫu nhiên trên toàn bộ sự kiện/cửa sổ, các chuỗi tấn công của cùng một kịch bản và cùng backdoor `payload.exe` sẽ rải đều ở cả Train và Test, dẫn tới rò rỉ dữ liệu nghiêm trọng (**Data Leakage**).

### 6.2. Phương án Chia Chuẩn tắc: Phân chia theo Kịch bản kết hợp Ngày Lành tính (Scenario-based + Chronological Split)

Áp dụng tỷ lệ phân chia chuẩn **60% TRAIN – 20% VAL – 20% TEST** dựa trên đơn vị độc lập là **Kịch bản tấn công (Scenarios) + Ngày làm việc lành tính (Benign Days)**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│               PHÂN CHIA 60% TRAIN - 20% VAL - 20% TEST TRÊN ATLASv2                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
  • TRAIN (60%):
      - Benign nền: Toàn bộ Ngày 1 và Ngày 2 (Undersampled)
      - Attack (kèm Benign song song): 6 Kịch bản (s1, s2, s3, m1, m2, m4)
        [Cân bằng: 4 Flash (s1, s2, m1, m2) + 2 Word (s3, m4)]
  • VALIDATION (20%):
      - Benign nền: Toàn bộ Ngày 3
      - Attack (kèm Benign song song): 2 Kịch bản (m3, m5)
        [Cân bằng: 1 Flash (m3) + 1 Word (m5)]
  • TEST (20%):
      - Benign nền: Toàn bộ Ngày 4
      - Attack (kèm Benign song song): 2 Kịch bản (s4, m6)
        [Cân bằng: 1 Single-host (s4) + 1 Multi-host (m6)]
```

| Phân vùng (Split) | Tỷ lệ | Thành phần Benign Nền (Background) | Thành phần Kịch bản Tấn công (Attack Scenarios) | Tính chất đa dạng (Diversity) |
| :--- | :---: | :--- | :--- | :--- |
| **TRAIN** | **60%** | **Days 1 & 2** (Đã qua bước Undersampling) | **`s1`, `s2`** (Flash), **`s3`** (Word),<br>**`m1`, `m2`** (Flash), **`m4`** (Word) | 6 kịch bản: Gồm cả Single-host & Multi-host; bao phủ cả 2 vector khai thác Flash và Word. |
| **VAL** | **20%** | **Day 3** | **`m3`** (Flash), **`m5`** (Word)** | 2 kịch bản: Dùng để căn chỉnh ngưỡng cắt xác suất (F1 Threshold Tuning) và Early Stopping. |
| **TEST** | **20%** | **Day 4** | **`s4`** (Word Single-host), **`m6`** (Word Multi-host) | 2 kịch bản hoàn toàn mới: Kiểm tra khả năng phát hiện trên biến thể tấn công chưa từng học. |

### 6.3. Hai Lưu ý Sống còn khi Huấn luyện Tăng tiến

#### 1. Kiểm soát Mất cân bằng Lớp bằng Lấy mẫu (Benign Undersampling):
* Trong 2 ngày làm việc đầu (Days 1–2), toàn bộ 100% sự kiện là Benign. Trong khi đó, các sự kiện Attack trong 6 kịch bản huấn luyện chỉ xuất hiện tập trung trong vài phút. Nếu đổ toàn bộ 100% Benign của Ngày 1–2 vào, tỷ lệ mất cân bằng sẽ vọt lên hàng chục nghìn Benign trên 1 Attack, làm tê liệt hàm mất mát.
* **Chiến lược lấy mẫu:**
  * Giữ lại **100%** các sự kiện diễn ra trong khung thời gian của 6 kịch bản tấn công.
  * Với các sự kiện nền của Ngày 1 và Ngày 2, tiến hành **lấy mẫu ngẫu nhiên có kiểm soát theo cửa sổ (Window Undersampling)** để đưa tỷ lệ Benign : Attack về mức thực tế tương đương OpTC (ví dụ tỷ lệ âm/dương khoảng **$30:1$** hoặc **$10:1$** như kỹ thuật Undersampling trong Mục 4.2.3 của bài báo ATLAS gốc).

#### 2. Kẹp Bộ đệm Lưu hồi từ OpTC (Experience Replay - ER):
* Để chống hiện tượng quên tri thức trên OpTC, trong mỗi mini-batch huấn luyện trên tập Train của ATLASv2, bắt buộc phải kẹp kèm một tỷ lệ mẫu từ bộ đệm Replay:
  $$\text{Mini-Batch} = 80\% \text{ (Mẫu mới từ ATLASv2 TRAIN)} + 20\% \text{ (Mẫu cũ từ OpTC TRAIN Buffer)}$$
* **Thành phần Buffer:** Chứa cả mẫu Benign và mẫu Attack được trích xuất từ tập TRAIN của OpTC seed02.
* **Hiệu quả:** Cơ chế "mỏ neo" này đảm bảo sau khi huấn luyện xong trên ATLASv2, khi đánh giá chéo lại trên tập TEST của OpTC, chỉ số F1 và FPR trên môi trường cũ vẫn giữ vững độ chính xác cao ($BWT \approx 0$).

---

## 7. CHECKLIST KIỂM THỬ VÀ NGHIỆM THU DỮ LIỆU (VALIDATION CHECKS)

Trước khi kích hoạt luồng huấn luyện, bộ dữ liệu tiền xử lý của ATLASv2 phải vượt qua các bài kiểm tra tự động sau:

1. **Kiểm tra rò rỉ nhãn Firefox:**
   * Tỷ lệ flow `firefox.exe` mang nhãn dương trên tập Days 1–4 phải bằng chính xác **0.00%**.
   * Số lượng flow `firefox.exe` mang nhãn dương trên Ngày 5 phải giảm từ 7,696 xuống dưới 100 flow (chỉ còn các kết nối thực sự tới C2/IOC).
2. **Kiểm tra tính đơn điệu của thời gian:**
   * Kiểm tra điều kiện $\Delta t \ge 0$ cho mọi chuỗi sự kiện trong từng chunk. Không chấp nhận sự kiện đảo lộn thời gian do bất đồng bộ sensor.
3. **Kiểm tra tính bất biến của `vocab.json` OpTC:**
   * Đối chiếu mã SHA256 của file `vocab.json` OpTC gốc trước và sau khi chạy script: **Bắt buộc trùng khớp 100%**. Mọi token mới chỉ được phép ghi vào `vocab_extended.json`.
4. **Kiểm tra tương thích Shape ma trận:**
   * Ma trận thưa đầu ra cho LightGBM ở chế độ cơ sở phải có đúng $N$ cột khớp với `len(vocab.json)` OpTC.
   * Tensor đầu ra cho BiLSTM phải có đúng 4 chiều categorical, 0 chiều numerical và 1 chiều continuous delta-t.
5. **Kiểm tra tính cân bằng phân vùng Split:**
   * Cả 3 phân vùng TRAIN, VAL, TEST đều phải có sự hiện diện của cả nhãn `0` và nhãn `1` với tỷ lệ dương $> 0$.
