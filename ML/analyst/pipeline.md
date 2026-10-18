# OpTC Host ML — Full Pipeline Reference

> **Scope:** Local preprocessing (eCAR → sparse shards) → Kaggle training (XGBoost) → evaluation → error analysis → tracing wrong predictions back to raw log lines.
> **Data source:** Real error examples from `mission4_audit_results_final/code/output/audits/mission4/`.

---

## Tổng quan kiến trúc pipeline

```
Raw eCAR JSON Logs
  (host-begnin/ & host-malicious/)
          │
          ▼
[STEP 1] build_host_index.py     → host_ml/index/
          │
          ▼
[STEP 2] build_split.py          → host_ml/split/manifest.json
          │   75% TRAIN / 10% VAL / 15% TEST  (seed=1, event-level stratified)
          ▼
[STEP 3] build_vocab.py --split  → host_ml/vocab.json + vocab_metadata.json
          │   Fit từ TRAIN only; VAL/TEST chỉ transform
          ▼
[STEP 4] build_model_input.py    → host_ml/model_input/  (compressed .npz shards)
          │   Binary sparse presence vectors, mỗi row = 1 eCAR event
          ▼
[STEP 5] package_kaggle_input.py → kaggle_upload_ustar/  (ustar tarball)
          │   Copy vocab + shards + notebooks vào bundle
          ▼
[KAGGLE] host_xgb_shards.ipynb
          ├── Đọc manifest → load shards (HostShardDataset)
          ├── prepare_sample()  → TRAIN subsample (neg_per_pos=30)
          ├── fit_sample_model() → XGBoost 300 rounds, max_depth=8
          ├── evaluate_resumable() → Val (tìm threshold), Test (frozen threshold)
          └── Diagnostics → fn_examples, fp_examples, score_distribution, PR curve
          │
          ▼
[ANALYST] Tải diagnostics về local → Phân tích FN/FP → Trace về raw log
```

---

## STEP 1 — Build Host Index

**Script:** [`code/preprocess/build_host_index.py`](file:///mnt/SSD_Data/optc/code/preprocess/build_host_index.py)

**Input:** Các file JSON/JSONL trong `host-begnin/` và `host-malicious/` (date range 16–25/09).

**Output:** `code/output/host_ml/index/` — file `.json` mô tả identity (path, size, mtime) mỗi nguồn telemetry.

**Điều cần biết:**
- Đây là bước **scan-only**, không đọc nội dung event.
- Kết quả được dùng làm "source-of-truth" cho các bước sau để verify integrity.
- Chạy với `--dry-run` để kiểm tra cấu hình mà không ghi file.

---

## STEP 2 — Build Split

**Script:** [`code/preprocess/build_split.py`](file:///mnt/SSD_Data/optc/code/preprocess/build_split.py)  
**Core logic:** [`stratified_pipeline.py`](file:///mnt/SSD_Data/optc/code/preprocess/stratified_pipeline.py)

**Output:** `code/output/host_ml/split/manifest.json` + per-source `*.split.gz`

### Chiến lược split

| Partition | Tỉ lệ | Seed | Ghi chú |
|-----------|-------|------|---------|
| TRAIN | 75% | 1 (= seed 01) | Dùng fit vocab + train model |
| VAL | 10% | — | Dùng tìm threshold tối ưu |
| TEST | 15% | — | Frozen; chỉ đánh giá sau khi lock threshold |

- Split là **event-level stratified random** — mỗi event (row) được assign vào một partition độc lập.
- Mỗi source file sinh ra file `<source_sha256>.split.gz` (1 byte/line: 0=exclude, 1=train, 2=val, 3=test).
- Split **không bao giờ được fit lại**; tất cả model (RF/XGB/LGBM) dùng cùng 1 split.

### Số liệu thực tế (từ `package_report.json`)

| Split | Tổng events | Positives (malicious) | Tỉ lệ imbalance |
|-------|------------|----------------------|----------------|
| TRAIN | 3 476 277 622 | 201 551 | **17 245 : 1** |
| VAL | 463 503 683 | 26 873 | 17 249 : 1 |
| TEST | 695 255 524 | 40 310 | 17 243 : 1 |

> [!WARNING]
> Imbalance 17 000:1 ở full corpus là nguyên nhân cốt lõi ảnh hưởng recall. Model được train trên mẫu 30:1 nhưng phải predict trên 17 000:1 thực tế.

---

## STEP 3 — Build Vocabulary & Tokenizer

**Script:** [`code/preprocess/build_vocab.py`](file:///mnt/SSD_Data/optc/code/preprocess/build_vocab.py)  
**Tokenizer:** [`ecar_tokenizer.py`](file:///mnt/SSD_Data/optc/code/preprocess/ecar_tokenizer.py)

**Output:** `code/output/host_ml/vocab.json` + `vocab_metadata.json`

### 3.1 Tokenizer — Nguyên lý hoạt động

Tokenizer xử lý mỗi raw eCAR event qua các bước sau:

```
Raw eCAR JSON event (từ host-begnin/ hoặc host-malicious/)
     │
     ▼ tokenize_record(record)
  Kiểm tra tính hợp lệ (eligible = True/False)
  • FLOW events → eligible=False → không vào Host ML (→ Network DL branch)
  • Exclude label → eligible=False
     │ eligible=True
     ▼
  Bóc tách theo object type + properties:
  - PROCESS: action, object, image_path, parent_image_path, command_line
  - FILE:    action, object, image_path, file_path, new_path
  - MODULE:  action, object, image_path, module_path
  - REGISTRY: action, object, image_path, key
  - SHELL:   action, object, image_path, payload (context_info)
     │
     ▼
  Group tokens theo layer:
  - STRUCTURE  : action::open, object::process, structure::action_object=open->process
  - ANCHOR     : command_line::anchor::launcher=ping.exe, image_path::basename=...
  - SYNTAX     : command_line::syntax::switch=-w, command_line::syntax::quoted_argument
  - SEMANTIC   : command_line::semantic::category=command, ::role=switch, ::subtype=ipv4
  - LEXICAL    : image_path::category=system, file_path::extension=.dll
     │
     ▼ flatten_tokens(grouped)
  Set[str] — danh sách token strings cho event này
```

### 3.2 Các fields được tokenize và fields bị DROP

**Fields được đọc (tokenized):**

| Object | Fields được xử lý | Cách xử lý |
|--------|------------------|-----------|
| PROCESS | `image_path`, `parent_image_path`, `command_line`, `acuity_level` | basename, category, AST parse command_line |
| FILE | `image_path`, `file_path`, `new_path`, `size` | basename, extension, category |
| MODULE | `image_path`, `module_path` | basename, category |
| SHELL | `image_path`, `payload`, `context_info` | invocation, parameter, parameter_role |
| REGISTRY | `image_path`, `key` | key depth, basename |

**Fields bị DROP hoàn toàn (không vào vocab):**

| Field | Lý do drop |
|-------|-----------|
| `actorID`, `objectID`, `id` | UUIDs — pure high-cardinality identifiers |
| `pid`, `ppid`, `tid` | Process IDs — ephemeral, không ổn định |
| `hostname` | Host name — không mang behavioral semantics |
| `principal` (raw) | User name — high-cardinality, variable |
| `timestamp` | Không tokenize thời gian ở event level |
| `base_address` | Memory addresses — random |
| IP addresses trong command_line | High-cardinality numeric (loại khi parse native) |
| Raw file path (full path) | Drop full path, chỉ giữ basename/extension/category |
| `size` (raw number) | Số nguyên raw — không semantics |
| `context_info` (đầy đủ) | Chỉ lấy invocation/parameter từ payload; context_info quá dài |

> [!IMPORTANT]
> **Đây chính là nguồn gốc của nhiều FN và FP.** Khi drop `file_path` → chỉ còn `file_path::category=system` + `file_path::extension=.dll`. Hai events khác nhau (benign và malicious) có thể có cùng category+extension → **Representation Collision**.

### 3.3 Xử lý 7 Command-Line Families (với ví dụ THỰC từ audit data)

#### Family 1: Native (PING — thực từ FN case)

**Raw event thực tế (từ `host-malicious/`, label=1):**
```json
{
  "action": "OPEN",
  "actorID": "61d47ba4-51cc-4277-ae0c-f9d864187606",
  "hostname": "SysClient0201.systemia.com",
  "id": "da7c1879-aa1f-4daa-aefb-305308002e99",
  "object": "PROCESS",
  "objectID": "61d47ba4-51cc-4277-ae0c-f9d864187606",
  "pid": 5076,
  "ppid": 5088,
  "principal": "SYSTEMIACOM\\zleazer",
  "properties": {
    "acuity_level": "5",
    "command_line": "ping -w 2000 -n 2 127.0.0.1",
    "image_path": "PING.EXE",
    "parent_image_path": "\\Device\\HarddiskVolume1\\Python27\\python.exe"
  },
  "tid": 6088,
  "timestamp": "2019-09-23T13:14:00.787-04:00",
  "label": 1
}
```

**Các fields bị DROP:**
- `actorID`, `objectID`, `id` → UUIDs, dropped
- `pid=5076`, `ppid=5088`, `tid=6088` → PIDs, dropped
- `hostname` → dropped
- `principal="SYSTEMIACOM\\zleazer"` → dropped
- `timestamp` → dropped
- `127.0.0.1` trong command_line → IP address, dropped (→ `command_line::native::ip_loopback`)
- `2000`, `2` trong command_line → integers, dropped (→ `command_line::native::number_value`)

**Tokens được sinh ra (thực tế, chạy tokenizer):**
```
action::open
command_line::anchor::command=ping.exe
command_line::anchor::launcher=ping.exe
command_line::family=native
command_line::launcher=ping.exe
command_line::native::executable=ping.exe
command_line::native::ip_loopback          ← IP được type-abstract thành "ip_loopback"
command_line::native::number_value          ← số được type-abstract thành "number_value"
command_line::native::ping
command_line::relation::command_switch=ping.exe->-n
command_line::relation::command_switch=ping.exe->-w
command_line::relation::role_transition=launcher->switch
command_line::relation::role_transition=number->ip_address
command_line::relation::role_transition=switch->number
command_line::semantic::category=command
command_line::semantic::category=location
command_line::semantic::category=object_amount
command_line::semantic::role=ip_address
command_line::semantic::role=launcher
command_line::semantic::role=number
command_line::semantic::role=switch
command_line::semantic::subtype=integer
command_line::semantic::subtype=ipv4
command_line::structure::argument_count=5-8
command_line::structure::switch=-n
command_line::structure::switch=-w
command_line::syntax::switch=-n
command_line::syntax::switch=-w
image_path::basename=ping.exe
image_path::category=relative
object::process
parent_image_path::basename=python.exe
parent_image_path::category=other_path
structure::action_object=open->process
structure::process_lineage=python.exe->ping.exe
```

**Benign train match (label=0) có cùng sparse vector:**
```json
{
  "action": "OPEN",
  "hostname": "SysClient0154.systemia.com",
  "object": "PROCESS",
  "principal": "SYSTEMIACOM\\mpietraccone",
  "properties": {
    "acuity_level": "5",
    "command_line": "ping -w 2000 -n 2 127.0.0.1",
    "image_path": "PING.EXE",
    "parent_image_path": "\\Device\\HarddiskVolume1\\Python27\\python.exe"
  },
  "label": 0
}
```

**Kết quả:** Sparse vector của malicious và benign **hoàn toàn giống nhau** (28 695 benign vs 2 malicious trong train). Score = 0.011271 < threshold 0.99968 → **FN**.

---

#### Family 2: CMD (thực từ FN Category D)

**Raw event thực tế (label=1, 0 benign match trong train):**
```json
{
  "action": "OPEN",
  "actorID": "de18c363-2320-45a1-9cd8-ed07ca742bbe",
  "hostname": "SysClient0005.systemia.com",
  "id": "bfdac009-7d00-4493-9edd-f3ba6ad3153e",
  "object": "PROCESS",
  "objectID": "de18c363-2320-45a1-9cd8-ed07ca742bbe",
  "pid": 9008,
  "ppid": 4908,
  "principal": "SYSTEMIACOM\\sysadmin",
  "properties": {
    "acuity_level": "5",
    "command_line": "\"C:\\Windows\\system32\\cmd.exe\" ",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\cmd.exe",
    "parent_image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\cmd.exe"
  },
  "tid": 6708,
  "timestamp": "2019-09-24T15:23:30.106-04:00",
  "label": 1
}
```

**Fields bị DROP:** `actorID`, `objectID`, `id`, `pid`, `ppid`, `tid`, `hostname`, `principal`, `timestamp`

**Tokens thực tế:**
```
action::open
command_line::anchor::command=cmd.exe
command_line::anchor::launcher=cmd.exe
command_line::cmd::cmd
command_line::cmd::exe
command_line::cmd::system32
command_line::cmd::windows
command_line::family=cmd
command_line::launcher=cmd.exe
command_line::semantic::category=command
command_line::semantic::role=launcher
command_line::semantic::subtype=.exe
command_line::structure::argument_count=1
command_line::syntax::quoted_argument
image_path::basename=cmd.exe
image_path::category=system
object::process
parent_image_path::basename=cmd.exe
parent_image_path::category=system
structure::action_object=open->process
structure::process_lineage=cmd.exe->cmd.exe
```

**Kết quả:** benign=0, malicious=17 trong train. Score = 0.040031 < threshold → **FN (Category D)**. Logical contradiction: token vector này chỉ có malicious label nhưng XGBoost vẫn predict < threshold do leaf node averaging.

---

#### Family 3: PowerShell SHELL (thực từ FP case — payload field)

**Raw event thực tế (label=0 benign, nhưng bị FP):**
```json
{
  "action": "COMMAND",
  "actorID": "c66fbad1-ac53-4fac-98be-f8422088d76a",
  "hostname": "SysClient0110.systemia.com",
  "id": "6db8c21b-b142-4ddd-8a30-2cb55650bd98",
  "object": "SHELL",
  "objectID": "84122c30-3e1c-4dc8-b894-60d09c253ea6",
  "pid": 5336,
  "ppid": -1,
  "principal": "",
  "properties": {
    "acuity_level": "0",
    "context_info": "... Host Name = ConsoleHost ... Command Name = New-Object ...",
    "image_path": "POWERSHELL.EXE",
    "payload": "CommandInvocation(New-Object): \"New-Object\"\nParameterBinding(New-Object): name=\"TypeName\"; value=\"System.CodeDom.Compiler.CompilerParameters\""
  },
  "tid": 5684,
  "timestamp": "2019-09-16T19:35:02.456-04:00",
  "label": 0
}
```

**Fields bị DROP:** `actorID`, `objectID`, `id`, `pid`, `ppid`, `tid`, `hostname`, `principal`, `timestamp`  
**Field bị DROP một phần:** `context_info` (dài, chỉ lấy invocation/parameters); full `payload` text bị lọc, chỉ giữ invocation name và parameter names.

**Tokens thực tế:**
```
action::command
image_path::basename=powershell.exe
image_path::category=relative
object::shell
shell::invocation=new-object
shell::parameter=typename
shell::parameter_role=typename->file       ← "CompilerParameters" được type-abstract
structure::action_object=command->shell
```

**Malicious train event có cùng sparse vector (15 242 sự kiện!):**
```
action::command + object::shell + image_path::basename=powershell.exe
+ shell::invocation=new-object + shell::parameter=typename
```
Ví dụ: malicious event dùng `New-Object System.Net.WebClient` để download malware — cùng `shell::invocation=new-object`, cùng `shell::parameter=typename`.

**Tại sao FP?** Benign trong train chỉ có 2 events nhưng malicious có 15 242. Token `shell::invocation=new-object` mang quá nhiều malicious signal (P(malicious|feature) = 10.3%). Model predict Malicious với score 0.9998 > threshold → **FP**.

**Root cause từ audit:** `payload` field chứa object class name (`System.CodeDom.Compiler.CompilerParameters` vs `System.Net.WebClient`) nhưng tokenizer chỉ lấy `shell::parameter_role=typename->file` — không phân biệt được namespace. **Field loss: `payload` value bị abstract mất thông tin discriminating class name.**

---

### 3.4 Xử lý MODULE events (thực từ FN case)

**Raw event thực tế (label=1, FN — 694 benign, 0 malicious trong train):**
```json
{
  "action": "LOAD",
  "actorID": "a30c75f1-17da-4a03-bc09-22703ffb232d",
  "hostname": "SysClient0402.systemia.com",
  "id": "f0ec0e4a-14ac-4f7c-9b95-b07546af11e3",
  "object": "MODULE",
  "objectID": "359e5d19-c9fc-4f17-bbe9-c50f421339ec",
  "pid": 3440,
  "ppid": 560,
  "principal": "NT AUTHORITY\\SYSTEM",
  "properties": {
    "acuity_level": "2",
    "base_address": "0x7ffe3ca60000",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe",
    "module_path": "\\Windows\\System32\\wldp.dll"
  },
  "tid": 2660,
  "timestamp": "2019-09-23T13:30:16.819-04:00",
  "label": 1
}
```

**Fields bị DROP:**
- `actorID`, `objectID`, `id` → UUIDs, dropped
- `pid=3440`, `ppid=560`, `tid=2660` → dropped
- `hostname` → dropped  
- `principal="NT AUTHORITY\\SYSTEM"` → dropped (nhưng mất thông tin!)
- `base_address="0x7ffe3ca60000"` → **memory address, dropped hoàn toàn**
- Full path `module_path` → chỉ lấy `basename=wldp.dll` và `category=system`

**Tokens thực tế:**
```
action::load
image_path::basename=svchost.exe
image_path::category=system
module_path::basename=wldp.dll
module_path::category=system
object::module
structure::action_object=load->module
```

**Benign train match (694 benign, 0 malicious):**
```json
{
  "action": "LOAD",
  "object": "MODULE",
  "properties": {
    "acuity_level": "2",
    "base_address": "0x7ffa11260000",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe",
    "module_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\wldp.dll"
  },
  "label": 0
}
```

**Kết quả:** Sparse vector giống hệt (svchost.exe + wldp.dll). Score = 0.013 < threshold → **FN (Category B)**.

**Root cause:** `module_path` chỉ được tokenize thành `basename=wldp.dll` + `category=system`. Malicious svchost load wldp.dll và benign svchost load wldp.dll có **cùng token set**. Full path drop bỏ mất thông tin về phiên bản file, location variant, hay parent process chain. **Field loss: `module_path` full path.**

---

### 3.5 Xử lý FILE events (thực từ FN case)

**Raw event thực tế (label=1, FN — 8 907 benign, 1 malicious):**
```json
{
  "action": "READ",
  "actorID": "53580bd1-d838-4ddf-95cc-76f310dda788",
  "hostname": "SysClient0402.systemia.com",
  "id": "b62d2f1c-3fa4-401d-8608-4754e45bbe8c",
  "object": "FILE",
  "objectID": "98ec6c99-cff1-4947-ab16-786e351b5d32",
  "pid": 1476,
  "ppid": 664,
  "principal": "SYSTEMIACOM\\tjanet",
  "properties": {
    "acuity_level": "5",
    "file_path": "\\Device\\HarddiskVolume1\\WINDOWS\\SYSTEM32\\IPHLPAPI.DLL",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\backgroundTaskHost.exe",
    "size": "206336"
  },
  "tid": 6576,
  "timestamp": "2019-09-23T13:29:25.766-04:00",
  "label": 1
}
```

**Fields bị DROP:**
- `actorID`, `objectID`, `id` → dropped
- `pid`, `ppid`, `tid` → dropped
- `hostname` → dropped
- `principal="SYSTEMIACOM\\tjanet"` → dropped
- `timestamp` → dropped
- Full `file_path` → **chỉ lấy `category=system` và `extension=.dll`** — mất tên file cụ thể
- `size="206336"` → **dropped hoàn toàn** (raw number)

**Tokens thực tế:**
```
action::read
file_path::category=system
file_path::extension=.dll
image_path::basename=backgroundtaskhost.exe
image_path::category=system
object::file
structure::action_object=read->file
```

**Benign train match:**
```json
{
  "action": "READ",
  "object": "FILE",
  "properties": {
    "acuity_level": "5",
    "file_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\sspicli.dll",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\backgroundTaskHost.exe",
    "size": "171520"
  },
  "label": 0
}
```

**Kết quả:** `IPHLPAPI.DLL` và `sspicli.dll` khác nhau hoàn toàn, nhưng sau khi tokenize → cùng `file_path::category=system` + `file_path::extension=.dll`. 8 907 benign vs 1 malicious → score = 0.037 < threshold → **FN (Category A — field_path field loss)**.

---

### 3.6 Token Layers & Policy Summary

| Layer | Ví dụ thực | Mục đích |
|-------|-----------|---------|
| `structure` | `action::open`, `object::process`, `structure::action_object=open->process` | Hành động & đối tượng |
| `anchor` | `command_line::anchor::launcher=ping.exe`, `command_line::anchor::command=ping.exe` | Launcher/entrypoint identity |
| `syntax` | `command_line::syntax::switch=-n`, `command_line::syntax::quoted_argument` | Switch/operator |
| `semantic` | `command_line::semantic::role=ip_address`, `::subtype=ipv4`, `::category=location` | Typed dynamic value |
| `lexical` | `image_path::category=system`, `file_path::extension=.dll` | Normalized path component |
| `relation` | `command_line::relation::command_switch=ping.exe->-n`, `structure::process_lineage=python.exe->ping.exe` | Structural relationships |

**Giá trị bị loại bỏ (abstracted):**
- IPs → `ip_loopback` / `ip_private` / `ip_public` (type abstracted)
- Numbers → `number_value` (type abstracted)
- Full paths → `basename` + `category` (normalized)
- UUIDs, PIDs, memory addresses → **dropped hoàn toàn**

### 3.7 Tạo vocab.json

1. Chạy tokenizer trên **100% TRAIN events** (cả benign + malicious).
2. Đếm tần suất mỗi token string.
3. Lọc token có `term_freq >= min_tf` (mặc định = 2).
4. Gán integer index: `token_string → integer_index`.

**Kết quả thực tế:** `vocab.json` hiện tại có **204 969 tokens**.

**VAL/TEST chỉ transform:** Token không có trong vocab → OOV, bị bỏ qua.

---

## STEP 4 — Build Model Input (Sparse Shards)

**Script:** [`code/preprocess/build_model_input.py`](file:///mnt/SSD_Data/optc/code/preprocess/build_model_input.py)

**Output:** `code/output/host_ml/model_input/` — các file `.npz` compressed per-source-per-split.

### Quy trình per-event

```python
for code, line, record in split_rows(entry, split_dir):
    split = SPLITS[code - 1]                    # 'train'/'val'/'test'
    grouped, audit = tokenize_record(record)
    tokens = set(flatten_tokens(grouped))
    columns = [vocab[t] for t in tokens if t in vocab]  # vocab lookup
    buffers[split].append(columns, record['label'], line)  # binary row
```

### Shard format

Mỗi `.npz` shard chứa:
- `indices`: cột có giá trị 1 (CSR delta encoding)
- `indptr`: row pointer array
- `label`: nhãn 0/1 per row
- `source_rows`: **line numbers trong source file** (dùng để trace về raw log!)

**Row identity:** `source_id + source_line` — có thể đọc chính xác dòng JSON raw gốc.

### Resume & Integrity

- Mỗi source file có 1 checkpoint JSON riêng.
- Checkpoint so khớp `run_id` (hash của vocab + split + builder code) và SHA256 của từng shard.
- Nếu checkpoint hợp lệ → resume, không xử lý lại.

---

## STEP 5 — Package Kaggle Input

**Script:** [`code/preprocess/package_kaggle_input.py`](file:///mnt/SSD_Data/optc/code/preprocess/package_kaggle_input.py)

**Output:** `code/output/host_ml/kaggle_upload_ustar/` — ustar tarball tương thích Kaggle.

Bundle bao gồm: `vocab.json`, `vocab_metadata.json`, tất cả `.npz` shards, reader code, notebooks, `manifest.json`, `package_report.json`.

---

## KAGGLE — Notebook Training (`host_xgb_shards.ipynb`)

**File:** [`code/kaggle/notebooks/host_xgb_shards.ipynb`](file:///mnt/SSD_Data/optc/code/kaggle/notebooks/host_xgb_shards.ipynb)

### Cấu hình chính (Cell 1)

```python
MODEL_NAME        = 'xgb'
NEG_PER_POS       = 30       # subsample negatives: 30 benign / 1 malicious
TRAIN_TARGET_ROWS = None     # None = giữ toàn bộ positives + neg*pos negatives
SEED              = 1
BOOST_ROUNDS      = 300
MAX_MATRIX_GIB    = 4
DEDUPE_PREDICTION = True     # dedup identical binary rows ở inference
RANKING_BINS      = 100_000
```

### Cell 2: TRAIN Sample Preparation (`prepare_sample`)

```
Input: HostShardDataset (đọc từ manifest.json)
        │
        ▼ sample_plan(data, target_rows, neg_per_pos, seed)
  Giữ 100% positives + random sample negatives (30:1)
  → plan.json (deterministic, hash-verified)
        │
        ▼ Với mỗi shard:
  decode_shard() → X (sparse matrix), y (labels)
  selected_rows() → lọc theo plan
  Ghi ra parts/XXXXXX.npz (atomic write + SHA256 verify)
        │
        ▼
  Sample stats thực tế:
  - 6 244 365 rows total  (0.18% của 3.48B training events)
  - 201 551 positives (100% kept)
  - ~6 042 814 negatives (30 × positives)
  - scale_pos_weight ≈ 29.98
```

> [!IMPORTANT]
> **Sampling chỉ áp dụng cho TRAIN.** VAL và TEST được evaluate trên **toàn bộ** events (không sample). Đây là lý do phải đối mặt với imbalance 17 000:1 thực tế ở inference.

### Cell 3: Fit Model (`fit_sample_model`)

```python
params = {
    'max_depth': 8,
    'eta': 0.05,
    'n_estimators': 300,
    'scale_pos_weight': 29.98,  # neg_per_pos
    'tree_method': 'hist',
}
```

Model: `/kaggle/working/xgb-kaggle/model-slot-1.ubj`

### Cell 4: Full Evaluation (`evaluate_resumable`)

```
VAL pass (threshold = None):
  ├── Stream toàn bộ 463M val events qua model
  ├── Tích lũy score histogram (100 000 bins)
  ├── Tìm threshold tối ưu: max F1 trên val score grid
  └── Output: validation_metrics.json, threshold = 0.99968

TEST pass (threshold = frozen = 0.99968):
  ├── Stream toàn bộ 695M test events qua model
  ├── Đếm TP/FP/FN/TN tại frozen threshold
  └── Output: test_metrics.json
```

**DEDUPE_PREDICTION:** 94.6% rows bị dedup → chỉ 62M unique rows được score.

---

## Kết quả thực tế (XGBoost v3)

| Metric | Validation | Test |
|--------|-----------|------|
| Precision | 0.849 | 0.852 |
| **Recall** | **0.624** | **0.626** |
| **F1** | **0.720** | **0.722** |
| FPR | 6.4 × 10⁻⁶ | 6.3 × 10⁻⁶ |
| PR-AUC | 0.637 | 0.638 |
| ROC-AUC | 0.984 | 0.984 |
| TP | 16 778 | 25 252 |
| **FN** | **10 095** | **15 058** |
| FP | 2 975 | 4 375 |
| **Threshold** | **0.99968** | ← frozen from val |

---

## Phân tích nguồn gốc FN và FP (từ Mission 4 audit)

### Tổng kết field loss (từ `verified_field_loss_breakdown.csv`)

| Object | Field bị mất thông tin | Loại lỗi | Số errors |
|--------|----------------------|---------|----------|
| FILE | `file_path` (full path) | FN | 8 |
| MODULE | `module_path` (full path) | FN | 11 |
| PROCESS | `command_line` (detail) | FN | 1 |
| SHELL | `payload` (object class name) | FP | 24 |

### Nguồn gốc thực sự của FN

**FN chủ yếu là Category B (Semantic Ambiguity):** Token vector của malicious event trùng với nhiều benign events trong train do các fields mang thông tin phân biệt đã bị abstract hoặc drop.

| Category | Số lượng | Ví dụ |
|----------|---------|-------|
| B — Semantic Ambiguity | **Đa số** | ping malicious vs ping benign (27 000 benign : 2 malicious) |
| A — Representation Collision (field loss) | ~19 errors | FILE file_path loss, MODULE module_path loss |
| D — Logical Contradiction | 2 errors | cmd.exe->cmd.exe (0 benign, 17 malicious nhưng score < threshold) |

### Nguồn gốc thực sự của FP

**FP là 100% Category A (SHELL object, payload field loss):** SHELL events (action=COMMAND, object=SHELL) của PowerShell benign bị misclassify là malicious vì tokenizer chỉ lấy `shell::invocation=new-object` mà không phân biệt class name trong `payload`.

**Feature importance của FP (từ SHAP values thực tế):**
```
image_path::basename=powershell.exe  → +6.21  (push về malicious mạnh nhất)
action::command                       → +2.60  (push về malicious)
image_path::category=relative         → -0.37  (hơi push về benign)
```

**Vấn đề:** Token `action::command` + `image_path::basename=powershell.exe` + `shell::invocation=new-object` → combo này xuất hiện với 15 242 malicious events trong train. Benign event cùng combo chỉ có 2 sự kiện. Model learn: combo này = malicious, ngay cả khi benign.

**Tại sao benign events lại có combo này?** Vì Windows system automation scripts (antivirus, deployment tools) cũng dùng `New-Object` trong PowerShell. Tokenizer không lấy đủ thông tin từ `payload` (object class name) để phân biệt `System.Net.WebClient` (malicious) vs `System.CodeDom.Compiler.CompilerParameters` (benign).

---

## Phân tích 5 Mẫu Model Đoán Sai (THỰC từ audit)

### Mẫu 1 — Category B: Semantic Ambiguity (FN — PROCESS)

**Raw event (malicious, label=1, từ SysClient0201):**
```json
{
  "action": "OPEN",
  "object": "PROCESS",
  "properties": {
    "acuity_level": "5",
    "command_line": "ping -w 2000 -n 2 127.0.0.1",
    "image_path": "PING.EXE",
    "parent_image_path": "\\Device\\HarddiskVolume1\\Python27\\python.exe"
  },
  "label": 1
}
```

**Sparse vector sau tokenize:** 32 tokens (action::open, command_line::family=native, command_line::syntax::switch=-n, command_line::syntax::switch=-w, parent_image_path::basename=python.exe, structure::process_lineage=python.exe->ping.exe, ...)

**Vì sao FN?** 28 695 benign events có cùng sparse vector; malicious chỉ có 2. Score = 0.011 < 0.99968 → **FN**.

**Field nào có thể giúp phân biệt?** `principal="SYSTEMIACOM\\zleazer"` (user tài khoản compromised), `timestamp` (thời điểm ngoài giờ làm việc), `actorID` (process chain context). Tất cả bị drop.

---

### Mẫu 2 — Category B: Semantic Ambiguity (FN — MODULE)

**Raw event (malicious, label=1, từ SysClient0402):**
```json
{
  "action": "LOAD",
  "object": "MODULE",
  "properties": {
    "acuity_level": "2",
    "base_address": "0x7ffe3ca60000",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\svchost.exe",
    "module_path": "\\Windows\\System32\\wldp.dll"
  },
  "label": 1
}
```

**Sparse vector sau tokenize:** 7 tokens (action::load, image_path::basename=svchost.exe, image_path::category=system, module_path::basename=wldp.dll, module_path::category=system, object::module, structure::action_object=load->module)

**Vì sao FN?** 694 benign events load `wldp.dll` vào `svchost.exe`. Score = 0.013 < 0.99968 → **FN**.

**Field nào có thể giúp phân biệt?** `base_address` (memory location của DLL injection), full `module_path` (variant path), `principal` (SYSTEM vs user). Tất cả bị drop.

---

### Mẫu 3 — Category A: Representation Collision (FN — FILE)

**Raw event (malicious, label=1, từ SysClient0402):**
```json
{
  "action": "READ",
  "object": "FILE",
  "properties": {
    "acuity_level": "5",
    "file_path": "\\Device\\HarddiskVolume1\\WINDOWS\\SYSTEM32\\IPHLPAPI.DLL",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\backgroundTaskHost.exe",
    "size": "206336"
  },
  "label": 1
}
```

**Sparse vector:** 7 tokens (action::read, file_path::category=system, file_path::extension=.dll, image_path::basename=backgroundtaskhost.exe, image_path::category=system, object::file, structure::action_object=read->file)

**Vì sao FN?** `file_path` được abstract thành `category=system` + `extension=.dll`. `IPHLPAPI.DLL` và `sspicli.dll` có cùng token. 8 907 benign events đọc `.dll` từ system32 bằng backgroundTaskHost.exe. Score = 0.037 < 0.99968 → **FN**.

**Root cause (verified field loss):** `file_path` full path bị drop. Nếu giữ `file_path::stem=iphlpapi` hoặc `file_path::basename=IPHLPAPI.DLL`, model có thể phân biệt.

---

### Mẫu 4 — Category A: Representation Collision (FP — SHELL)

**Raw event (benign, label=0, từ SysClient0110, nhưng bị FP):**
```json
{
  "action": "COMMAND",
  "object": "SHELL",
  "properties": {
    "image_path": "POWERSHELL.EXE",
    "payload": "CommandInvocation(New-Module): \"New-Module\"\nParameterBinding(New-Module): name=\"Name\"; value=\"Ansible.ModuleUtils.AddType\"\nParameterBinding(New-Module): name=\"ScriptBlock\"; value=\"# Copyright (c) 2018 Ansible Project\nFunction Add-CSharpType {\n    ...\n}\"\n"
  },
  "label": 0
}
```
* **Bị drop (Top-level):** `actorID`, `hostname`, `id`, `objectID`, `pid`, `ppid`, `principal`, `tid`, `timestamp`
* **Bị drop (Properties):** `acuity_level`, `context_info`
* **Được giữ lại:** `action`, `object`, `image_path`, `payload`

**Sparse vector:** 8 tokens (action::command, image_path::basename=powershell.exe, image_path::category=relative, object::shell, shell::invocation=new-object, shell::parameter=typename, shell::parameter_role=typename->file, structure::action_object=command->shell)

**SHAP top features:** `image_path::basename=powershell.exe` (+6.21) + `action::command` (+2.60) → score = 0.9998 > 0.99968 → **FP**.

**Vì sao FP?** 15 242 malicious SHELL events dùng `New-Object` trong train. Tokenizer không extract class name từ `payload`. `System.CodeDom.Compiler.CompilerParameters` (benign) vs `System.Net.WebClient` (malicious) đều bị abstract thành cùng `shell::parameter_role=typename->file`.

**Root cause:** `payload` field chứa thông tin discriminating (class namespace) nhưng tokenizer chỉ lấy invocation name và parameter role, bỏ mất class name. **Field loss: payload value.**

---

### Mẫu 5 — Category D: Logical Contradiction (FN — PROCESS)

**Raw event (malicious, label=1, từ SysClient0005):**
```json
{
  "action": "OPEN",
  "object": "PROCESS",
  "properties": {
    "acuity_level": "5",
    "command_line": "\"C:\\Windows\\system32\\cmd.exe\" ",
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\cmd.exe",
    "parent_image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\cmd.exe"
  },
  "label": 1
}
```

**Sparse vector:** 21 tokens (action::open, command_line::family=cmd, command_line::cmd::system32, command_line::syntax::quoted_argument, image_path::basename=cmd.exe, parent_image_path::basename=cmd.exe, structure::process_lineage=cmd.exe->cmd.exe, ...)

**Vì sao FN?** benign=0, malicious=17 trong train. Về mặt logic, model **phải** predict malicious. Nhưng: XGBoost tree-based — sparse vector này rất hiếm, có thể nằm trong Leaf node chung với pattern Benign khác. Leaf averaging → probability = 0.040 < threshold 0.99968 → **FN (Category D)**.

---

## Tổng hợp: Field Loss → Error Type Mapping

```
DROP field         →  Loại Error  →  Mechanism
─────────────────────────────────────────────────────────────────
file_path (full)   →  FN (Cat A)  →  Collision: mọi .dll trong system32 = cùng vector
module_path (full) →  FN (Cat B)  →  Collision: mọi svchost+wldp.dll = cùng vector
payload class name →  FP (Cat A)  →  Collision: New-Object benign = New-Object malicious
actorID/pid/chain  →  FN (Cat B)  →  Mất context: không biết process chain
principal (user)   →  FN (Cat B)  →  Mất context: không biết user account bị compromise
timestamp          →  FN (Cat B)  →  Mất context: không biết thời điểm bất thường
base_address       →  FN (Cat B)  →  Mất memory injection evidence
```

---

## Cách Trace Kết Quả Sai Về Raw Log (7 Bước)

### Bước 1: Tải diagnostics từ Kaggle

```bash
unzip xgb_kaggle_results.zip -d /tmp/xgb_results/
```

### Bước 2: Tìm FN events trong diagnostics

```python
import json

with open('/tmp/xgb_results/diagnostics/test_diagnostics.json') as f:
    diag = json.load(f)

fn_events = [e for e in diag['examples'] if e['error'] == 'FN']
# Xem FN gần threshold nhất (dễ fix nhất)
fn_sorted = sorted(fn_events, key=lambda x: -x['score'])
for e in fn_sorted[:10]:
    print(f"score={e['score']:.6f}, source_id={e.get('source_id','?')[:16]}, line={e.get('source_line','?')}")
```

### Bước 3: Map về source file

```python
with open('code/output/host_ml/model_input/manifest.json') as f:
    manifest = json.load(f)

target = fn_events[0]
source_entry = next(
    e for e in manifest['sources']
    if e['source_id'] == target['source_id']
)
print(f"Source file: {source_entry['source']['path']}")
```

### Bước 4: Đọc raw log gốc (read-only)

```python
with open(source_entry['source']['path']) as f:
    for i, line in enumerate(f):
        if i == target['source_line']:
            raw_event = json.loads(line)
            break
print(json.dumps(raw_event, indent=2))
```

### Bước 5: Re-tokenize để debug

```python
import sys
sys.path.insert(0, 'code/preprocess')
from ecar_tokenizer import tokenize_record, flatten_tokens

grouped, audit = tokenize_record(raw_event)
tokens = sorted(set(flatten_tokens(grouped)))

print("Eligible:", audit['eligible'])
print("Tokens:")
for t in tokens:
    print(f"  {t}")

with open('code/output/host_ml/vocab.json') as f:
    vocab = json.load(f)
oov = [t for t in tokens if t not in vocab]
print(f"OOV ({len(oov)}): {oov}")
```

### Bước 6: Tìm collision trong train

```python
target_cols = frozenset(vocab[t] for t in tokens if t in vocab)
# Stream qua benign train shards, so sánh column sets
# Match → đây là collision (Category A)
```

### Bước 7: Kiểm tra feature importance

```python
import xgboost as xgb
model = xgb.Booster()
model.load_model('model-slot-1.ubj')

scores = model.get_score(importance_type='gain')
top50 = sorted(scores.items(), key=lambda x: -x[1])[:50]

with open('code/output/host_ml/vocab.json') as f:
    vocab = json.load(f)
rev = {v: k for k, v in vocab.items()}

for feat, gain in top50:
    idx = int(feat.replace('f', ''))
    print(f"gain={gain:.1f}  {rev.get(idx,'?')}")
```

---

## Files cần download từ Kaggle

| File | Mục đích |
|------|---------|
| `diagnostics/test_diagnostics.json` | **Quan trọng nhất**: FN/FP examples + source_id + line |
| `diagnostics/val_pr_curve.*` | Full PR curve → tìm threshold tốt hơn |
| `diagnostics/val_score_distribution.*` | Histogram score malicious vs benign |
| `diagnostics/validation_threshold_curve.npz` | F1/P/R tại mỗi threshold |
| `diagnostics/day_host_counts.*` | FN phân bố theo host/ngày |
| `model-slot-1.ubj` | Model → feature importance locally |

---

## Files reference local

| File | Mục đích |
|------|---------|
| [`vocab.json`](file:///mnt/SSD_Data/optc/code/output/host_ml/vocab.json) | 204 969 tokens |
| [`vocab_metadata.json`](file:///mnt/SSD_Data/optc/code/output/host_ml/vocab_metadata.json) | Policy, min_tf=2 |
| [`split/manifest.json`](file:///mnt/SSD_Data/optc/code/output/host_ml/split/) | Split identity |
| [`model_input/manifest.json`](file:///mnt/SSD_Data/optc/code/output/host_ml/model_input/) | Shard inventory, source_id → file |
| [`xgb_f1_diagnosis.md`](file:///mnt/SSD_Data/optc/analyst/xgb_f1_diagnosis.md) | Root-cause analysis F1=0.72 |
| [`xgb_f1_diagnosis_mission3.md`](file:///mnt/SSD_Data/optc/analyst/xgb_f1_diagnosis_mission3.md) | Mission 3: lineage + temporal |
| [Mission 4 audit](file:///mnt/SSD_Data/optc/code/kaggle/mission4_audit_results_final/code/output/audits/mission4/) | Real FN/FP examples + field loss breakdown |

---

## Roadmap cải thiện (Tokenizer v4)

Dựa trên Mission 3 + Mission 4 findings:

| Cải tiến | Giải quyết vấn đề | Priority |
|---------|-----------------|---------|
| Parent process lineage | FN Cat B (collisions giảm 41%→29%) | **HIGH** |
| Temporal 60s window | FN Cat B (collisions giảm 41%→4.5%) | **HIGH** |
| `shell::class_namespace` token từ payload | FP SHELL (24 errors) | **HIGH** |
| `file_path::stem` token | FN FILE Cat A (8 errors) | Medium |
| `module_path::stem` token | FN MODULE Cat A (11 errors) | Medium |
| Threshold tuning (0.99968 → ~0.999x) | F1 +2–4 points | **QUICK WIN** |

> [!NOTE]
> Tokenizer v4 phải vẫn giữ tính **deterministic, non-executing, bounded**. Temporal features cần được tính từ sorted event stream của mỗi host. `shell::class_namespace` phải được extract bằng regex tĩnh từ payload, không execute.
