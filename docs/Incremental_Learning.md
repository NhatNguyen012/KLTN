# Kế hoạch Triển khai Học tăng dần (Incremental Learning) cho Hệ thống Phát hiện APT

Tài liệu này đặc tả chi tiết quy trình, cơ chế dữ liệu và các bước kỹ thuật để thực hiện **Học tăng dần / Chuyển giao miền (Incremental Learning / Domain Adaptation)** từ mô hình cơ sở **DARPA OpTC (Windows Baseline)** sang hai tập dữ liệu mới:
1. **ATLASv2** (Môi trường Windows Endpoint: Sysmon & Carbon Black EDR).
2. **DARPA-TC-E3-THEIA** (Môi trường Ubuntu Linux Endpoint: Kernel Provenance CDM / Audit).

Kiến trúc áp dụng thống nhất cho 3 mô hình thành phần: **LightGBM (Host ML)**, **2-hop GraphSAGE (Provenance Graph)** và **BiLSTM (Host Event Sequence)**.

---

## 1. Bản chất phương pháp: Fine-tune kết hợp Replay Buffer

Theo các phân tích tại [Temp/10.md](file:///mnt/SSD_Data/optc/Temp/10.md) và [Temp/11.md](file:///mnt/SSD_Data/optc/Temp/11.md), việc áp dụng Học tăng dần trong đề tài được định nghĩa như sau:

* **Mục tiêu:** Cho phép 3 mô hình hấp thụ các kỹ thuật tấn công và hành vi hệ điều hành mới (từ Windows hiện đại của ATLASv2 và Linux của THEIA) mà **không làm mất đi tri thức đã học trên OpTC (chống Catastrophic Forgetting)** và **không cần huấn luyện lại từ đầu (Retrain from scratch)**.
* **Cơ chế kỹ thuật chính:** **Fine-tune + Replay Buffer**:
  * Trích xuất một tỷ lệ đại diện (ví dụ: $10\% - 20\%$) từ tập OpTC TRAIN (đã đóng băng trong 358 shards của `host_ml_seed02`) lưu vào bộ nhớ đệm (Replay Buffer).
  * Khi huấn luyện trên dataset mới, mỗi batch cập nhật gồm: **$80\%$ mẫu mới + $20\%$ mẫu cũ từ Replay Buffer**.
* **Chỉ số đánh giá học thuật:**
  * **BWT (Backward Transfer):** Đo mức độ suy giảm F1/Recall trên tập OpTC TEST sau khi đã học xong dataset mới ($BWT \ge -0.05$ là đạt chuẩn ổn định tri thức).
  * **FWT (Forward Transfer):** Đo tốc độ hội tụ và hiệu năng ban đầu trên dataset mới nhờ đã có nền tảng tri thức từ OpTC.

---

## 2. Cơ chế gán nhãn (Ground Truth) của ATLASv2 & THEIA

### Câu hỏi: "ATLASv2 được label như thế nào? Có phải là binary label 0/1 không?"

👉 **CÂU TRẢ LỜI: ĐÍCH ĐẾN CUỐI CÙNG LÀ PHÂN LOẠI NHỊ PHÂN (BINARY LABEL: 0 = Benign, 1 = Attack/Malicious).**

Tuy nhiên, trong dữ liệu thực tế của ATLASv2 và THEIA, **nhãn không nằm sẵn thành một cột `0/1` trong từng dòng log thô**, mà được cung cấp dưới dạng **danh mục thực thể độc hại (Entity-level / Event-level Ground Truth)** thông qua bộ nhãn REAPr (`reapr-ground-truth/`):

### 2.1. Cấu trúc nhãn của ATLASv2 (`DATASET/ATLASv2/`)
ATLASv2 cung cấp nhãn theo 2 cấp độ:

1. **Cấp độ Tiến trình (`*.labels` trong `reapr-ground-truth/atlasv2/`):**
   * Mỗi kịch bản (ví dụ `h2-m1.labels`, `h1-s1.labels`) chứa danh sách các tiến trình nằm trong chuỗi tấn công (attack chain):
     ```csv
     attack, process_name, process_id, process_uuid, label
     h2-m1,  c:\windows\explorer.exe, 1118, 7DMF69PK-05e61374-0000063c-00000000-1d89b6984b85de4, attack
     h2-m1,  c:\users\aalsahee\downloads\payload.exe, 640.0, 7DMF69PK-05e61374-00000280-00000000-1d89b94f8fff420, attack
     ```
   * **Quy tắc gán nhãn:** Mọi sự kiện do `process_uuid` này sinh ra $\rightarrow$ gán nhãn **`1` (Attack)**. Các tiến trình nền còn lại trong hệ thống $\rightarrow$ gán nhãn **`0` (Benign)**.
2. **Cấp độ Bản ghi Sự kiện (`EventRecordID` trong `msft-security/groundtruth/`):**
   * Chứa danh sách trực tiếp các số định danh bản ghi `EventRecordID` (ví dụ `2830846`, `2831086`...) thuộc về hành vi độc hại trong Windows Security XML.
   * **Quy tắc gán nhãn:** Sự kiện nào có `EventRecordID` nằm trong danh sách $\rightarrow$ gán nhãn **`1`**; các sự kiện khác trong cùng file $\rightarrow$ gán nhãn **`0`**.
3. **Cấp độ Hạt giống đồ thị (`*.seeds`):**
   * Định danh đỉnh gốc (`root_cause`) và đỉnh tác động (`impact`) phục vụ kiểm thử khả năng truy vết phả hệ của **2-hop GraphSAGE**.

### 2.2. Cấu trúc nhãn của DARPA-TC-E3-THEIA (`darpa-tc-engagement3/`)
* **File nhãn tiến trình:** `theia_labels.csv` định danh trực tiếp `uuid` và `process_name` của các tiến trình độc hại:
  ```csv
  attack_chain, uuid, process_name, label
  theia_3.3_fail_allstate, 8B161C29-0000-0000-0000-000000000020, /usr/bin/firefox, attack
  theia_3.3_fail_gatech_clean, 5418F32A-0000-0000-0000-000000000020, /home/admin/Downloads/firefox/firefox, attack
  ```
* **Nhãn cạnh đồ thị:** `theia_edge_labels.tar.gz` chứa các cạnh nhân quả độc hại trong đồ thị provenance.
* **Quy tắc gán nhãn:** Ghép (join) `uuid` của sự kiện/node với `theia_labels.csv`. Nếu khớp $\rightarrow$ gán **`1`**, ngược lại $\rightarrow$ gán **`0`**.

---

## 3. Bảng Ánh xạ Thuộc tính (Field Mapping Matrix): OpTC $\leftrightarrow$ ATLASv2 $\leftrightarrow$ THEIA

Bảng này xác định rõ các trường đang được 3 mô hình trích xuất từ OpTC sẽ được lấy từ đâu trong ATLASv2 và THEIA:

| Thực thể / Ý nghĩa nghiệp vụ | OpTC eCAR (Đang dùng) | ATLASv2 (Windows - CBC EDR / Sysmon) | DARPA-TC-E3-THEIA (Linux CDM Provenance) | Mô hình sử dụng & Vai trò |
| :--- | :--- | :--- | :--- | :--- |
| **Hành động & Kiểu đối tượng** | `action`, `object` (vd: `CREATE/PROCESS`, `WRITE/FILE`) | • CBC: `action` (`ACTION_LOAD_MODULE`, `ACTION_FILE_MOD`)<br>• Sysmon: `EventID` (1=ProcessCreate, 11=FileCreate, 12=Reg) | • CDM: `Event.type` (`EVENT_EXECUTE`, `EVENT_WRITE`, `EVENT_MODIFY_FILE_ATTRIBUTES`) | **Cả 3 mô hình:** Xác định loại hành vi và đối tượng tương tác. |
| **Đường dẫn tiến trình** | `image_path` | • CBC: `process_path`<br>• Sysmon: `Image` | • CDM: `Event.subject.properties.image_path` hoặc `execve.filename` | • **LightGBM:** Token phân loại thư mục/tên file.<br>• **GraphSAGE:** Thuộc tính semantic role của node.<br>• **BiLSTM:** Nhận diện `app_family`. |
| **Tiến trình cha** | `parent_image_path` | • CBC: `parent_path`<br>• Sysmon: `ParentImage` | • CDM: Truy vết qua `Event.subject.parentSubject` $\rightarrow$ `image_path` | • **LightGBM:** Token quan hệ `parent_exe->child_exe`.<br>• **GraphSAGE:** Cạnh phả hệ `PROCESS/CREATE`. |
| **Toàn văn Dòng lệnh** | `command_line` | • CBC: `process_cmdline`<br>• Sysmon: `CommandLine` | • CDM: `Event.subject.cmdLine` | • **LightGBM:** Tokenizer bóc tách launcher, switches, operators, AST tokens, typed placeholders. |
| **Định danh liên kết phả hệ (Graph keys)** | `hostname`, `pid`, `ppid`, `process_uuid`, `parent_uuid` | • CBC: `device_name`, `process_pid`, `parent_pid`, `process_guid`, `parent_guid`<br>• Sysmon: `Computer`, `ProcessId`, `ParentProcessId`, `ProcessGuid`, `ParentProcessGuid` | • CDM: `hostId`, `Event.subject.uuid`, `Event.subject.parentSubject.uuid` | • **GraphSAGE:** Khóa liên kết dựng cạnh 2-hop (Chỉ làm khóa, **không** làm feature). |
| **Mốc thời gian sự kiện** | `timestamp` ($\mu s$) | • CBC: `device_timestamp`<br>• Sysmon: `UtcTime` / `TimeCreated` | • CDM: `Event.timestamp` (nanoseconds $\rightarrow$ quy đổi $\mu s$) | • **GraphSAGE:** Bắt buộc strictly past time cutoff.<br>• **BiLSTM:** Sắp xếp chuỗi và tính $\Delta t$ (`delta_t_log1p`). |
| **Thao tác Tệp** | `file_path`, `new_path` | • CBC: `filemod_name`<br>• Sysmon: `TargetFilename` | • CDM: `FileObject.predicateObjectPath` | • **LightGBM:** Token đường dẫn nhạy cảm (`/etc/`, `AppData`, `Temp`). |
| **Thư viện nạp động (DLL/SO)** | `module_path` | • CBC: `modload_name`<br>• Sysmon: `ImageLoaded` (EventID 7) | • CDM: `SharedLibraryObject` / nạp `.so` qua `dlopen`/`mmap` | • **LightGBM:** Token phát hiện nạp DLL/SO bất thường. |
| **Cơ chế Duy trì (Persistence)** | Registry: `key`, `registry_key`, `registry_path` | • CBC: `regmod_name`<br>• Sysmon: `TargetObject` (EventID 12/13/14) | *(Linux không có Registry)*<br>$\rightarrow$ Ánh xạ sang sửa file cấu hình: `/etc/cron*`, `/etc/systemd/system/` | • **LightGBM:** Token persistence.<br>*(Adapter Linux gán cờ `persist_cron` / `persist_systemd`)*. |
| **Ngữ cảnh Tài khoản** | `principal` | • CBC: `process_username`<br>• Sysmon: `User` | • CDM: `Principal.userId` / `uid` / `euid` (ánh xạ: root, system, user) | • **LightGBM & BiLSTM:** Phân loại vai trò tài khoản (`principal_class`). |
| **Hành vi Socket Mạng** | `START/FLOW`, `direction` | • CBC: `netconn_*`<br>• Sysmon: EventID 3 (`NetworkConnect`) | • CDM: `NetFlowObject` (`EVENT_CONNECT`, `EVENT_ACCEPT`) | • **BiLSTM:** Bắt sự kiện tiến trình tạo socket kết nối.<br>*(Lưu ý: Bỏ toàn bộ IP/Port/Proto L3/L4)*. |

---

## 4. Chiến lược Mở rộng Từ điển (Vocabulary Expansion) cho LightGBM

Đối với mô hình cây LightGBM, việc giữ vững không gian đặc trưng là yếu tố sống còn để chống quên thảm khốc:

```
┌────────────────────────────────────────────────────────────────────────┐
│  vocab_v1.json (OpTC Baseline, Seed02)                                  │
│  Chỉ số: 0 ───> N-1  (HOÀN TOÀN ĐÓNG BĂNG / IMMUTABLE)                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ EXPAND (Append-only)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  vocab_v2.json (OpTC + ATLASv2 Windows Tokens)                         │
│  Chỉ số 0 ───> N-1: Giữ nguyên tuyệt đối                              │
│  Chỉ số N ───> N + M - 1: Token Windows mới xuất hiện ở ATLASv2        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ EXPAND (Append-only)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  vocab_v3.json (OpTC + ATLASv2 + THEIA Linux Tokens)                   │
│  Chỉ số 0 ───> N + M - 1: Giữ nguyên tuyệt đối                        │
│  Chỉ số N + M ───> Hết: Token Linux mới (/bin/bash, sudo, /etc/...)    │
└────────────────────────────────────────────────────────────────────────┘
```

### 4.1. Quy tắc mở rộng (Append-only Policy)
1. **Không tái lập chỉ mục (No Re-indexing):** Các token cũ từ OpTC (từ index `0` đến `N-1`) giữ nguyên vị trí cột. Cột `powershell.exe` hay `-encodedcommand` tuyệt đối không bị dời chỉ số.
2. **Nối tiếp đuôi (Append-only):** Khi quét tập TRAIN của ATLASv2/THEIA, những token mới vượt qua ngưỡng tần suất tối thiểu (`min_df >= 5`) sẽ được cấp chỉ số mới bắt đầu từ `N`.
3. **Phân tách không gian đặc trưng Windows và Linux:**
   * Token Linux từ THEIA (ví dụ: `path::/bin/bash`, `cmd::sudo`, `path::/etc/passwd`) sẽ chiếm các cột mới ở phía sau.
   * Khi đánh giá mẫu OpTC/ATLASv2 trên từ điển mở rộng, các cột đặc thù của Linux đơn giản mang giá trị `0` (vắng mặt); ngược lại, mẫu THEIA sẽ có giá trị `0` ở các cột Registry của Windows.

### 4.2. Huấn luyện tăng dần bằng `init_model` trong LightGBM
* Trong LightGBM, không khởi tạo lại cây từ đầu (`from scratch`).
* Sử dụng tham số `init_model = 'lgbm_optc_seed02.txt'`:
  ```python
  import lightgbm as lgb
  
  # Giữ nguyên cây cũ của OpTC, chỉ trồng thêm n_estimators mới trên tập kết hợp
  # Dữ liệu train gồm: 80% ATLASv2/THEIA TRAIN + 20% OpTC Replay Samples
  gbm = lgb.train(
      params,
      train_set=new_train_data,
      num_boost_round=50,             # Trồng thêm 50 cây thích nghi mới
      init_model='lgbm_optc_seed02.txt', # Kế thừa nguyên vẹn cây OpTC
      valid_sets=[val_data],
      keep_training_booster=True
  )
  ```

---

## 5. Kế hoạch Triển khai cho 2-hop GraphSAGE

Mô hình 2-hop GraphSAGE (`code/provenace_graph/`) đã được thiết kế sẵn theo dạng **Relational Mean-Message Passing** trên cấu trúc đỉnh Process và Host:

1. **Dựng Ego-graph 2-hop cho dataset mới:**
   * **Với ATLASv2:** Dùng `process_guid` và `parent_guid` trong Sysmon/CBC-EDR để dựng cạnh `PROCESS/CREATE`. Liên kết `host_name` qua sự kiện mở kết nối để tạo cạnh Host $\leftrightarrow$ Host.
   * **Với THEIA:** Dùng `subject.uuid` và `parentSubject.uuid` trong CDM provenance để dựng cạnh cha $\rightarrow$ con.
2. **Khớp nối 40 thuộc tính Node hữu hạn:**
   * Các thuộc tính của đỉnh Process là **finite categories** (loại tiến trình: shell, system daemon, user application, script engine, v.v.).
   * Adapter của THEIA sẽ phân loại các tiến trình Linux (ví dụ `/bin/sh`, `/usr/bin/python`, `/usr/sbin/cron`) vào đúng các nhóm thuộc tính ngữ nghĩa tương đương với Windows (`cmd.exe`, `python.exe`, `taskhost.exe`).
3. **Chiến lược Fine-tuning:**
   * **Đóng băng (Freeze) 2 tầng RelationalSAGE encoder** (weights 32 $\rightarrow$ 16 đã học được mẫu cấu trúc đồ thị tổng quát từ OpTC).
   * **Chỉ Fine-tune tầng Readout / Risk head** với tốc độ học nhỏ ($\text{lr} = 10^{-5}$) trên tập dữ liệu mới kết hợp mẫu Replay từ OpTC.

---

## 6. Kế hoạch Triển khai cho BiLSTM

1. **Khắc phục điểm yếu "học vẹt" (Shortcut Learning):**
   * Theo [Temp/10.md](file:///mnt/SSD_Data/optc/Temp/10.md) và phân tích ở [Monitoring_Logging_Architecture.md](file:///mnt/SSD_Data/optc/docs/Monitoring_Logging_Architecture.md), BiLSTM không dùng các thuộc tính gói tin mạng L3/L4 (`orig_bytes`, `resp_bytes`, `port`) của Zeek Bro nữa.
   * Đầu vào chuyển dịch thành **chuỗi vết hành vi tiến trình (Process Event Sequence Trace)**:
     $$\text{Event} = [ \text{Action\_Type}, \text{Object\_Type}, \text{Process\_Family}, \text{User\_Role}, \Delta t ]$$
2. **Ánh xạ về Canonical Event Actions:**
   * Cả Windows (OpTC, ATLASv2) và Linux (THEIA) đều quy đổi về 6 nhóm hành động thời gian chuẩn:
     1. `ACTION_SPAWN`: Khởi tạo tiến trình con.
     2. `ACTION_MODULE`: Nạp thư viện (DLL/SO).
     3. `ACTION_FILE_IO`: Thao tác ghi/sửa tệp.
     4. `ACTION_PERSIST`: Can thiệp registry hoặc sửa crontab/systemd.
     5. `ACTION_SOCKET`: Tiến trình mở socket kết nối ra ngoài.
     6. `ACTION_TERMINATE`: Kết thúc tiến trình.
3. **Fine-tuning:**
   * BiLSTM học nhịp điệu tấn công theo chuỗi thời gian (Kill-chain Rhythm). Huấn luyện bằng AdamW ($\text{lr} = 5 \times 10^{-5}$) trên các cửa sổ trượt (sliding windows) thời gian kết hợp Replay Buffer.

---

## 7. Lộ trình Thực hiện Từng bước (Step-by-Step Roadmap)

```
[Bước 1: Trích xuất & Lọc dữ liệu]
  ├── Giải nén telemetry ATLASv2 (cbc-edr, sysmon) và THEIA (raw json/CDM).
  └── Kiểm tra tính hợp lệ của mốc thời gian và định danh (UUID/GUID validation).
                    │
                    ▼
[Bước 2: Viết Log Adapter & Chuẩn hóa Entity]
  ├── atlasv2_adapter.py: Chuyển Sysmon/CBC sang chuẩn trung gian eCAR.
  ├── theia_adapter.py: Chuyển CDM Provenance sang chuẩn trung gian eCAR.
  └── Gán nhãn nhị phân (0/1) bằng cách khớp với file nhãn REAPr.
                    │
                    ▼
[Bước 3: Mở rộng Không gian Đặc trưng & Chuẩn bị Đầu vào]
  ├── Chạy build_vocab.py --append để sinh vocab_v2.json (ATLASv2) & vocab_v3.json (THEIA).
  ├── Sinh Shards nhị phân cho LightGBM (Lưu dưới dạng shards riêng, không ghi đè OpTC).
  ├── Dựng Ego-graph Cache cho 2-hop GraphSAGE với exact-time cutoffs.
  └── Trích xuất chuỗi sự kiện thời gian chuẩn hóa cho BiLSTM.
                    │
                    ▼
[Bước 4: Huấn luyện Tăng dần (Incremental Training with Replay)]
  ├── Nạp 10% - 20% mẫu OpTC TRAIN vào Replay Buffer.
  ├── LightGBM: init_model='lgbm_optc.txt' + Replay Buffer.
  ├── GraphSAGE: Freeze encoder, fine-tune Readout head + Replay Buffer.
  └── BiLSTM: Fine-tune LSTM weights trên Canonical Event Traces + Replay Buffer.
                    │
                    ▼
[Bước 5: Đánh giá Toàn diện Đa miền (Comprehensive Cross-Domain Evaluation)]
  ├── Đánh giá trên tập TEST của dataset mới (Khả năng thích ứng / FWT).
  ├── Đánh giá lại trên tập TEST của OpTC cũ (Đo độ suy giảm tri thức / BWT).
  └── Báo cáo các chỉ số: Precision, Recall, F1-Score, PR-AUC, BWT.
