# Quy tắc xử lý Host eCAR: Structure, Anchor, Syntax và chuẩn hóa ngữ nghĩa

Tài liệu này mô tả policy **`host_ml_structure_anchor_syntax`** của nhánh Host ML
(Random Forest, XGBoost, LightGBM). Cập nhật theo yêu cầu của giảng viên: phải chỉ
ra thông tin **Structure, Anchor và Syntax** nào được token hóa. “Structure-aware
semantic tokenization” là tên mô tả phương pháp engineering của dự án, không tự
chứng minh rằng parser đã giữ đủ cấu trúc hoặc mô hình phát hiện APT tốt hơn.

Nguồn implementation: [`ecar_tokenizer.py`](../code/ecar_tokenizer.py), lexer
[`command_syntax.py`](../code/command_syntax.py), builder
[`build_vocab.py`](../code/build_vocab.py). Nguồn lập luận nghiên cứu:
[`host_ml_tokenization_research.md`](host_ml_tokenization_research.md). Đặc tả
ngắn về tokenizer: [`host_ml_command_line_vocabulary.md`](host_ml_command_line_vocabulary.md).
Fit/split và lệnh vận hành hiện hành nằm ở mục 9 của tài liệu này.

## 1. Yêu cầu biểu diễn

“Anchor” được hiểu theo nghĩa đã thống nhất: tên/keyword ổn định được nhận diện
trong một vai trò cú pháp, chẳng hạn executable, command, module hoặc API. Đây là
định nghĩa làm việc của dự án, không phải tuyên bố về một thuật toán ba tầng cụ
thể trong literature.

| Thành phần | Cần giữ | Ví dụ token |
|---|---|---|
| **Structure** | Vai trò, quan hệ có hướng, ranh giới clause và payload | `command_line::relation::pipeline=get-process->select-object` |
| **Anchor** | Tên đầy đủ đã chuẩn hóa trong vai trò launcher/command/module/API | `command_line::anchor::command=get-process` |
| **Syntax** | Switch, operator, quote/escape và AST type an toàn | `command_line::syntax::operator=pipe` |
| **Semantic** | Loại/vai trò của operand trước khi che literal biến động | `command_line::relation::switch_value=/p->password` với `schtasks.exe` |
| **Lexical fallback** | Mảnh từ đã chuẩn hóa, có namespace field/family | `command_line::powershell::process` |

Các thành phần bổ sung và có thể chồng lấp. Operator vừa là syntax vừa đóng góp
structure. Không cần ba vocabulary riêng. `token_layers()` ghi tag chồng lấp vào
metadata để audit/ablation; tag không tạo thêm cột. Tokenizer giữ cả namespace
`structure::switch/operator` cũ và namespace `syntax` rõ ràng; phần dư thừa này
cần được đo bằng ablation, không coi là tín hiệu độc lập mới.

Một command name nằm trong **chuỗi dữ liệu** không tự trở thành command anchor.
Username, password, PID, UUID và chuỗi định danh ngẫu nhiên không phải anchor.
Tên API trích từ AST là tên quan sát trong source, không khẳng định binding hoặc
lời gọi runtime thực sự xảy ra.

Ví dụ input:

```text
powershell.exe -Command "Get-Process | Select-Object Name"
```

Một phần candidate token thực tế:

```text
command_line::anchor::launcher=powershell.exe
command_line::anchor::command=get-process
command_line::anchor::command=select-object
command_line::syntax::switch=-command
command_line::syntax::operator=pipe
command_line::relation::pipeline=get-process->select-object
command_line::relation::launcher_payload=powershell->inline_command
```

Đảo chiều pipe sẽ thay đổi relation token. Trong khi đó
`Write-Output 'Get-Process | Select-Object'` không sinh pipe operator hoặc hai
command anchor từ nội dung literal đó. Các token mô tả cấu trúc quan sát được,
không phải nhãn benign/malicious.

## 2. “Ai làm gì lên đối tượng nào và ở đâu?”

```text
WHO    = executable/process context đã chuẩn hóa
ACTION = action eCAR
OBJECT = object type eCAR
WHERE  = path/registry category hoặc vai trò operand phù hợp
```

Đây là cách giải thích feature, không phải một token ghép toàn bộ identity.
Không gọi `image_path` là actor tuyệt đối cho mọi PROCESS action:

| PROCESS action | Cách đọc an toàn |
|---|---|
| CREATE | `parent_image_path` cung cấp parent/launcher context; `image_path` và command thường mô tả process con |
| OPEN | Cần `actorID/objectID` để xác định actor và target chính xác |
| TERMINATE | Actor có thể trùng hoặc khác target; phải resolve identity nếu cần khẳng định |

Nhánh Host ML dùng basename/category và relation parent → child. Muốn điều tra
đúng instance process phải quay lại source/sidecar. Không đưa ID instance vào X.

## 3. Tách feature, join, raw và target

| Trạng thái | Vai trò | Ví dụ |
|---|---|---|
| MODEL_FEATURE | Token đã chuẩn hóa đi vào X | `action::create`, `image_path::basename=cmd.exe` |
| JOIN_ONLY | Identity/time để nối hoặc audit, không đi vào X | `id`, `actorID`, `objectID`, timestamp, `bro_uid` khi có trong FLOW |
| RAW_ONLY | Giữ nguyên ở source bất biến; không sinh feature | principal/account chính xác, raw registry data, địa chỉ bộ nhớ |
| TARGET | Nhãn dùng cho y và đánh giá | `label` và ground truth đã kiểm chứng |

“Bỏ field” nghĩa là **không sinh feature**, không xóa khỏi source. Bốn thư mục
`host-begnin/`, `host-malicious/`, `ecar-bro/`, `bro/` luôn read-only, kể cả cache,
checkpoint, file giải nén và log. Output phải nằm dưới `code/output/` hoặc nơi
writable được cho phép ở ngoài tất cả data root. Shared guard resolve symlink
trước khi chấp nhận output; metadata reuse cũng phải qua guard.

## 4. Allowlist theo object

| Object | Property được giữ | Cách biểu diễn |
|---|---|---|
| PROCESS | `image_path`, `parent_image_path`, `command_line` | basename/category, parent → child, command features |
| FILE | `image_path`, `file_path`, `new_path` | actor basename; resource chỉ category/extension |
| MODULE | `image_path`, `module_path` | executable/module basename và path category |
| REGISTRY | `image_path`, một trong `key`, `registry_key`, `registry_path` | executable; registry root và finite category |
| TASK | `image_path`, `path` | executable; task path category/extension |
| SHELL | `image_path`, `payload` | `CommandInvocation(...)` và `ParameterBinding(...)` được nhận diện |
| THREAD, USER_SESSION, SERVICE, HOST | Không property | action, object, action → object |
| FLOW | Không | Loại khỏi nhánh Host ML hiện tại |
| Object thiếu/không biết | Không | Loại record, audit lý do |

Mỗi object được giữ có `action`, `object`, `structure::action_object`. Action lạ
được chuẩn hóa thành `unknown`; code chưa kiểm chứng toàn bộ ma trận cặp
action/object hợp lệ. Bốn object chỉ có schema cần ablation riêng.

Không tokenize generic property inventory, field mới chưa allowlist, nested
dict/list, nhãn, timestamp, account field, PID/TID/SID/UUID, memory address,
raw registry value/data, raw SHELL context, hoặc network property trên object Host.
Identity chính xác vẫn ở source.

Path resource dùng category hữu hạn: `startup`, `temp`, `appdata`, `programdata`,
`system`, `windows`, `program_files`, `user_profile`, `unc`, `other_path`,
`relative`; extension ngoài danh sách thành `other`. FILE basename không được giữ.
Executable/module giữ basename đã chuẩn hóa; không đảm bảo mọi basename đều có
giá trị dự đoán. REGISTRY giữ root và các nhóm như run/run_once, services,
winlogon, task_cache, powershell, policies, defender, environment, other.

## 5. Thứ tự xử lý và hierarchy

```text
eCAR JSON → chọn field → xác định launcher/family
         → parse source với whitespace/case gốc và source spans
         → xác định command/clause, switch, operand, quote/operator
         → gán anchor và role; trích payload inline nếu grammar cho phép
         → che literal biến động theo role → sinh candidate token
         → lọc TF trên fit corpus → vocab[token] = chỉ số cột
         → transform record bằng vocabulary đóng băng → sparse X
```

Phân cấp **Command_line → Paragraph → Sentence/Clause → Word/Lexeme → Token** vẫn
là cách trình bày phương pháp:

| Tầng | Ý nghĩa |
|---|---|
| Command_line | Chuỗi telemetry sau JSON unescape đúng một lần |
| Root paragraph P0 | Một command_line của đúng một record |
| Nested paragraph | Payload inline/code được trích hoặc decode từ chính telemetry |
| Sentence/clause | Invocation/statement phân theo grammar; không tách theo dấu chấm NLP |
| Word/lexeme | Đơn vị có span, quote và vai trò |
| Token | Feature đã chuẩn hóa; một lexeme có thể sinh nhiều token |

Implementation có `Lexeme(kind, value, start, end, quoted)`, xử lý clause/payload
và parse-status token. Nó **không** materialize một object graph P0/P1/Sentence
đầy đủ. Offset và hierarchy ID không trở thành vocabulary feature. Source record
không bị mutate. Quan hệ option/value và role transition không vượt shell operator.

Parser đọc source trước khi collapse whitespace/case-fold. Vì vậy newline và
indentation của Python `-c` còn nguyên cho `ast.parse`. NFKC, NUL removal,
case-fold và whitespace collapse chỉ áp dụng khi sinh feature lexical chuẩn hóa.

## 6. Bảy launcher/grammar family

Đây là convention của dự án, không phải bảy kiểu dữ liệu chính thức của eCAR.
Ưu tiên basename `image_path`; chỉ fallback executable đầu command khi thiếu
image. Không dùng parent hoặc keyword trong argument để đoán family. Path launcher
có quote và khoảng trắng được xử lý bằng argv lexer. Thiếu launcher có marker.

| Family | Xử lý hiện có | Giới hạn |
|---|---|---|
| CMD | `/c`, `/k`; lấy remainder, bỏ một outer payload quote; clause, pipe/redirect, caret escape, directed pipeline | Không mô phỏng toàn bộ CMD quoting/expansion/grouping |
| PowerShell | Host switches; `-Command` inline; command anchors, pipe, `;`/newline, quote/backtick, call operator; encoded payload | Group lồng nhau được giữ opaque; chưa dùng Microsoft AST, chưa resolve aliases/variables |
| Python | Phân biệt interpreter `-c`/`-m` trước script boundary; source AST không execute; module/API anchor có giới hạn | Parser theo Python version hiện chạy; option forms lạ vẫn là fallback, không runtime name resolution |
| WScript | WSH switch, script extension, typed operands | Không mở script VBS/JS/WSF |
| CScript | Tương tự WScript, giữ console-host family và attached option evidence | Không đọc script body, không đoán protocol chỉ từ tên argument |
| Rundll32 | DLL/entry-point delimiter và relation; quoted DLL path; fragment thiếu launcher dựa trên image | Không load DLL, không resolve entry point |
| Native | argv, executable/command anchor, switch và audited utility-specific values | Không coi metacharacter trong argv là shell operator; không đoán nghĩa mọi option |

Ví dụ `python.exe script.py -c "print(1)" -m pretend` được xử lý là script mode, không
phải hai interpreter mode và không parse `print(1)` như source `-c`. Với
`python.exe -c "import os; print(os.getcwd())"`, code chỉ parse AST để sinh node,
edge và tên quan sát; không import `os`, không gọi `getcwd()`.

## 7. Anchor và chuẩn hóa operand

Giữ tên ghép `get-process` cạnh lexical `get`, `process`. Anchor được gán từ vị trí
command hoặc node AST đã kiểm tra, không từ việc tìm keyword ở mọi nơi.

Nghĩa switch phải dựa trên family/utility. Ví dụ:

```text
schtasks.exe /query /s server /u alice /p 12345
  → /u->username, /p->password, /s->host_name
  → lexical username_value/password_value/host_name_value
  → không giữ alice và không gán 12345 thành port

unknown.exe /p 12345
  → giữ /p và kiểu số
  → không suy /p là password hoặc port
```

Các utility có bảng audited hiện gồm schtasks, net, runas, wmic, psexec, ssh.
Với vị trí credential/task-name đã biết, che cả attached value trước lexical
emission. Không tuyên bố rule này nhận ra mọi identity trong command tùy biến,
Python string literal hoặc mã obfuscated. UUID/SID/hex/Base64 dài, số độc lập,
host counter và user segment trong path cũng có normalization chung.

## 8. Encoded PowerShell và an toàn parser

Chỉ decode operand của encoded-command switch đã nhận diện trong host options.
Tách operand trước khi kiểm tra alphabet, để malformed operand cũng bị che và có
`encoded_not_decoded`. Thiếu operand cũng có failure marker. Không case-fold blob
trước decode. Sau `-File`, option thuộc script không tự trở thành encoded host mode.

Decoder hỗ trợ tối đa hai lớp Base64 với UTF-16LE/UTF-8, có status success/partial/
failure. Partial chỉ là prefix khôi phục được, không khẳng định code hoàn chỉnh.
Không sửa source, không execute/evaluate/import mã telemetry, không expand env,
không mở script/response file hoặc tự giải mã thuật toán tùy ý trong payload.

| Giới hạn | Giá trị |
|---|---:|
| Command_line/SHELL payload được xử lý | 32.768 ký tự |
| Lexeme mỗi lần parse | 1.024 |
| Nesting depth | 4 |
| Python AST node được duyệt | 256 |
| Encoded input của decoder riêng | 131.072 ký tự |
| Decoded text mỗi lớp | 65.536 ký tự |

Giới hạn command áp dụng trước decoder trong đường tokenize. Parse lỗi/limit có
marker; fallback lexical cũng bounded. Marker `opaque_group` không phải một AST
parse thành công. Không suy parser này tương đương shell execution.

## 9. Pipeline supervised: một split chung 75/10/15, seed 01

RF, XGBoost và LightGBM dùng **cùng một split đã lưu**, không tự chia lại khi
train từng model. Nguồn là corrected Host eCAR từ `host-begnin/` (16–22/09) và
`host-malicious/` (23–25/09). Tên thư mục attack-day không phải nhãn: cả event
`label=0` và `label=1` đều được xử lý. FLOW và object không hỗ trợ bị loại.
Nhãn thiếu/null chỉ được coi là 0 trong benign partition tin cậy; attack-day
Host event bắt buộc có nhãn integer 0/1. Không suy nhãn từ token hay command.
Một file corrected có thể chứa event của sysclient khác tên file. Giữ nguyên
hostname/nhãn trong event; index ghi `hostname_differs_from_file`, sidecar ghi
`host` theo event và `file_host` theo container. Sai khác này không tự làm event
bị loại hoặc đổi nhãn. Hostname thiếu/không hợp lệ vẫn báo lỗi kèm file và dòng.

```text
Full Host label index (16–25/09, cả hai nguồn)
                  ↓
Persisted stratified random split, seed 1 (= 01)
         TRAIN 75% / validation 10% / test 15%
                  ↓
Vocabulary fit: benign TRAIN + malicious TRAIN
                  ↓
Transform ba tập bằng cùng vocabulary → CSR binary
                  ↓
RF / XGBoost / LightGBM dùng cùng X/y và split identity
```

### 9.1. Split và vocabulary contract

`build_host_index.py` quét EOF và lưu luồng nhãn nén: một byte cho mỗi source
line (0 = excluded, 1 = benign, 2 = malicious). Không tokenize command ở bước
index. `build_split.py` đọc index này, lưu một luồng split nén cho mỗi file
(0 = excluded, 1 = train, 2 = val, 3 = test). Hai bước không nạp toàn corpus vào
RAM và không ghi vào dataset roots.

Split ngẫu nhiên theo event, phân tầng theo **file nguồn × nhãn** để phân bố
file/ngày ổn định (file không nhất thiết chỉ chứa một hostname). Tổng số mỗi lớp được chia đúng 75/10/15 với làm tròn số nguyên;
hạn mức theo file được phân bổ tỷ lệ và điều chỉnh phần dư. Không bảo đảm mọi
stratum rất nhỏ có mặt trong cả ba split. RNG seed mặc định là `1`; có thể nhập
`--seed 01`. Đây không phải kết quả bit-for-bit của sklearn với cùng seed.
Đổi số worker không đổi assignment. Split manifest và các luồng split được giữ
lại cho mọi model. Mặc định dùng tất cả Host events, không undersample.

Đơn vị nhận diện row là source path + source line. Pipeline kiểm tra nguồn
không lặp trong manifest, nhưng **chưa deduplicate theo event ID trên toàn
corpus**. Không coi random-event split là process/host/campaign/temporal
isolation. Event tương quan có thể ở các split khác nhau; chỉ báo cáo đây là
baseline random-event. Việc kiểm tra duplicate ID toàn corpus/group split là
phép kiểm tra bổ sung, không được ngầm tuyên bố đã hoàn thành.

`build_vocab.py --split` chỉ đếm token trong TRAIN, gồm **cả hai lớp**.
TF là tổng lần token xuất hiện; DF là số TRAIN Host event chứa token. TF ≥ 2,
không cap vocabulary, không loại token chỉ vì nó xuất phát từ malicious TRAIN.
Validation/test không ảnh hưởng tần suất, lựa chọn token hay feature selection.
Tokenizer Structure/Anchor/Syntax vẫn là bộ quy tắc cố định, không học từ nhãn.

`vocab.json` ánh xạ token → cột, không phải ordinal token value. Baseline dùng
CSR binary. Đường shard hiện tại chỉ lưu binary; đường matrix truyền thống
có `--representation both` cho count ablation trên tập vừa tài nguyên.
TF-IDF là tương lai. Model học cả hai lớp qua `X_train, y_train`.

Vocabulary metadata chứa `fit_classes=[0,1]`, `fit_counts`, `split_sha256`,
`split_seed`, hash tokenizer và TF/DF. Matrix bắt buộc khớp split/vocabulary
hash, đồng thời kiểm tra số row mỗi lớp đúng assignment đã lưu. Ba script model
kiểm tra bundle và ghi split/vocabulary identity vào training log; model seed
mặc định cũng là 1. Hyperparameter/threshold chọn trên validation; test chỉ
đánh giá cuối cùng. Package kiểm tra checksum và có đủ hai lớp ở từng split.

### 9.2. Checkpoint, dung lượng và thư mục

Thư mục vận hành chung là `/mnt/SSD_Data/optc/code/output/host_ml/`:

```text
host_ml/
  logs/
  index/manifest.json + *.labels.gz
  split/manifest.json + *.split.gz
  vocab.json
  vocab_metadata.json
  model_input/manifest.json
  model_input/assets/vocab.json + vocab_metadata.json
  model_input/host_shards.py + shard_metrics.py
  model_input/host_{rf,xgb,lgbm}_shards.ipynb
  model_input/volumes/ssd/.../*.npz
  model_input/checkpoints/.../*.json
  sample_tokenization.md
```

Giữ vocabulary/split cùng nhau. Vocabulary fit benign 16–20/09 không đáp ứng
contract của random split mới và không được dùng để tạo matrix thí nghiệm này.
Các artifact ngoài `host_ml/` hiện có được giữ nguyên. Các artifact dùng tên thống nhất, không thêm hậu tố phiên bản.

Index/split/vocabulary/model input resume theo file hoàn tất. Checkpoint validate
code/config, split/vocab identity khi áp dụng, source path/size/mtime_ns và
SHA256 artifact. Đây **không** phải content hash toàn bộ dataset. Chạy lại cùng
lệnh khi bị ngắt; file đang dở sẽ được đọc lại. Directory output index/split/
matrix cuối phải chưa tồn tại; output hoàn tất được giữ lại, không ghi đè bằng
partial run. Vocabulary publish cặp JSON theo từng file atomic; consumer kiểm
tra checksum để phát hiện cặp không đồng bộ.

Các lệnh dưới đây là full corpus. Split hiện có 4.695 file và 4.635.036.829
Host events. Bước 5 dùng shard nén trên các volume được cho phép, không ghép
CSR/sidecar toàn corpus. Không cần chạy lại bước 1–4 đã thành công. TF/DF counters
của vocabulary vẫn tăng theo số token khác nhau; resource của preprocessing và
resource khi train trên Kaggle là hai vấn đề riêng.

### 9.3. Lệnh local đầy đủ

**Chạy tuần tự: chỉ bắt đầu bước tiếp theo sau khi bước trước thành công.**
`nohup` giữ tiến trình khi ngắt SSH; `-u` cập nhật log ngay. Ctrl-C trên `tail`
chỉ dừng xem log. Khi máy reboot, cần chạy lại lệnh để resume. Không khởi chạy
hai bản của cùng bước vào cùng output/checkpoint directory.

**Bước 0 — kiểm thử và kiểm tra phạm vi (foreground, không tạo corpus artifact):**

```bash
cd /mnt/SSD_Data/optc
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp python3 -m unittest discover -s code -p 'test_*.py'
python3 /mnt/SSD_Data/optc/code/build_host_index.py --dry-run
mkdir -p /mnt/SSD_Data/optc/code/output/host_ml/logs
```

**Bước 1 — full label index cho cả benign và malicious:**

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/build_host_index.py \
  --benign-root /mnt/SSD_Data/optc/host-begnin \
  --malicious-root /mnt/SSD_Data/optc/host-malicious \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/index \
  --workers 12 \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/build_host_index.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/build_host_index.log
```

Thành công có dòng `Published .../index/manifest.json`. `build_malicious_index.py`
chỉ kiểm kê nhanh và đọc prefix mặc định 50 dòng/file; không thay thế full index
và không phải dependency của pipeline mới. Nếu cần báo cáo kiểm kê nhanh riêng:

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/build_malicious_index.py \
  --root /mnt/SSD_Data/optc/host-malicious \
  --output /mnt/SSD_Data/optc/code/output/host_ml/malicious_index.json \
  --sample-lines 50 \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/build_malicious_index.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/build_malicious_index.log
```

**Bước 2 — tạo split chung 75/10/15, seed 01:**

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/build_split.py \
  --index /mnt/SSD_Data/optc/code/output/host_ml/index/manifest.json \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/split \
  --seed 01 --workers 12 \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/build_split.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/build_split.log
```

Log cuối in `counts` cho cả ba tập. Phải có label 0 và 1 trong mỗi tập; bước
split từ chối tập quá nhỏ không thỏa điều kiện này.

**Bước 3 — build vocabulary từ cả hai lớp trong TRAIN:**

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/build_vocab.py \
  --split /mnt/SSD_Data/optc/code/output/host_ml/split/manifest.json \
  --output /mnt/SSD_Data/optc/code/output/host_ml/vocab.json \
  --metadata-output /mnt/SSD_Data/optc/code/output/host_ml/vocab_metadata.json \
  --min-frequency 2 --workers 12 \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/build_vocab.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/build_vocab.log
```

Không dùng `--fit-purpose training` của đường scan benign theo ngày. `--split`
đã yêu cầu đọc EOF và áp dụng chính xác assignment TRAIN. Log cuối có
`wrote ... tokens to .../host_ml/vocab.json`.

**Bước 4 — audit vocabulary qua 12 mẫu (nhẹ, không fit lại):**

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/explain_sample_tokenization.py \
  --vocab /mnt/SSD_Data/optc/code/output/host_ml/vocab.json \
  --output /mnt/SSD_Data/optc/code/output/host_ml/sample_tokenization.md \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/explain_sample_tokenization.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/explain_sample_tokenization.log
```

Script walkthrough có thể thành công với log rỗng vì báo cáo nằm trong Markdown.
Đây là audit mẫu, không thay thế đánh giá OOV trên corpus.

**Bước 5 — tạo full input dạng shard nén, dùng chung cho ba model:**

Đã xong bước 4 thì bắt đầu ở đây. Dùng `build_model_input.py` thay cho lệnh
`build_matrix.py` ghép toàn corpus. Không build lại index/split/vocabulary.
Builder mới kiểm tra nguyên trạng các artifact hiện có và không sửa hash hoặc
metadata của chúng.

Cấu hình ở [`code/model_input_volumes.json`](../code/model_input_volumes.json):

| Volume | Thư mục output | Hạn mức file output | Giữ trống tối thiểu |
|---|---|---:|---:|
| `ssd` | `/mnt/SSD_Data/optc/code/output/host_ml/model_input/volumes/ssd` | 500 GiB | 20 GiB |
| `hdd` | `/mnt/HDD_Data/optc_model_input` | 220 GiB | 20 GiB |
| `system` | `/home/nguyen/optc_model_input` | 100 GB (100.000.000.000 byte) | 30 GiB |

Các thư mục HDD/system đã được user cho phép riêng, nằm ngoài dataset roots.
Builder ưu tiên SSD, rồi HDD, rồi system; không cần trải đều khi output còn nhỏ.
Quota tính tổng kích thước file trong thư mục volume, gồm run trước còn giữ lại;
filesystem có thể có thêm overhead nhỏ. Giới hạn kiểm tra cả dung lượng trống
thực tế mỗi lần ghi. Nếu hết cả ba volume, builder dừng và giữ checkpoint.
Không tự xóa artifact, thay đổi nhãn, lấy mẫu hay gộp các event giống nhau.

Kiểm tra input/placement trước (read-only; checksum split có thể mất thời gian):

```bash
python3 /mnt/SSD_Data/optc/code/build_model_input.py \
  --split /mnt/SSD_Data/optc/code/output/host_ml/split/manifest.json \
  --vocab /mnt/SSD_Data/optc/code/output/host_ml/vocab.json \
  --vocab-metadata /mnt/SSD_Data/optc/code/output/host_ml/vocab_metadata.json \
  --storage-config /mnt/SSD_Data/optc/code/model_input_volumes.json \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/model_input \
  --workers 4 --rows-per-shard 100000 --buffer-mib 32 --dry-run
```

Chạy full preprocessing nền:

```bash
mkdir -p /mnt/SSD_Data/optc/code/output/host_ml/logs
nohup python3 -u /mnt/SSD_Data/optc/code/build_model_input.py \
  --split /mnt/SSD_Data/optc/code/output/host_ml/split/manifest.json \
  --vocab /mnt/SSD_Data/optc/code/output/host_ml/vocab.json \
  --vocab-metadata /mnt/SSD_Data/optc/code/output/host_ml/vocab_metadata.json \
  --storage-config /mnt/SSD_Data/optc/code/model_input_volumes.json \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/model_input \
  --workers 4 --rows-per-shard 100000 --buffer-mib 32 \
  < /dev/null >> /mnt/SSD_Data/optc/code/output/host_ml/logs/build_model_input.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/build_model_input.log
```

Mỗi worker có tối đa ba buffer, mỗi buffer flush khi đủ 100.000 row hoặc chạm
32 MiB array thô. RAM còn gồm vocabulary, cache tokenizer, nén và các bản sao
ngắn hạn; đây không phải giới hạn RSS tuyệt đối. Có thể đổi `--workers` khi
resume mà không thay đổi output assignment. Giữ nguyên `--rows-per-shard`,
`--buffer-mib`, tokenizer/vocabulary/split và builder để reuse checkpoint.
Chạy lại cùng lệnh khi bị ngắt. Log `RESUME` là file đã kiểm tra checksum và tái
sử dụng. File đang dở được đọc lại, shard đã ghi đúng có thể được tái sử dụng.
Khóa builder/volume ngăn hai builder ghi đồng thời vào cùng output volume.

Mỗi shard `.npz` là container numeric nén, chỉ gồm:

- `row_nnz`: số cột có mặt trong từng event.
- `column_delta`: chênh lệch các chỉ số cột đã sắp xếp, uint32.
- `label`: nhãn 0/1 cho từng event, uint8.
- `source_line_delta`: vị trí source line nén theo chênh lệch, uint64.

Giá trị feature là **1 ngầm định**, khôi phục được CSR binary ban đầu. Không lưu
float `1` lặp hàng chục tỷ lần; không tạo JSONL sidecar và không ghép matrix lớn.
Manifest ghi file nguồn một lần và liên kết từng shard với source ID. Kết hợp
source ID + source line để đọc lại hostname/UUID/timestamp từ dữ liệu gốc khi cần
join; các trường đó không phải feature và không cần lặp trong input training.
`OOV` của builder này đếm token duy nhất trong từng event, không phải TF lặp.

Chỉ publish `model_input/manifest.json` với `complete=true` sau khi mọi file
được xử lý và tổng nhãn của ba tập khớp chính xác split gốc. Shard vừa là output
cuối vừa là phần được checkpoint tham chiếu; không có bản sao CSR tạm toàn corpus.
Dung lượng cuối lấy từ `splits.*.bytes`; chưa thể suy chắc từ dung lượng gzip nguồn.

**Bước 6 — kiểm tra full output, đọc mỗi shard một lần:**

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/verify_model_input.py \
  --manifest /mnt/SSD_Data/optc/code/output/host_ml/model_input/manifest.json \
  --decode \
  < /dev/null >> /mnt/SSD_Data/optc/code/output/host_ml/logs/verify_model_input.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/verify_model_input.log
```

Chờ log kết thúc bằng JSON có `verified_shards` bằng tổng shard trong manifest,
không có traceback. Lần build hiện tại có **53.249 shard**, nên cần thấy
`"verified_shards": 53249`. `Ctrl+C` khi đang chạy `tail -f` chỉ đóng tail;
process verifier đã chạy bằng `nohup` vẫn tiếp tục. Không khởi chạy thêm verifier
khi process cũ còn chạy.

**Bước 7 — đóng gói full input để upload Kaggle:**

Số liệu từ manifest của lần build hoàn tất ngày 15/09/2026:

| Split | Event | Benign | Malicious | Shard nén (GB thập phân) |
|---|---:|---:|---:|---:|
| TRAIN | 3.476.277.622 | 3.476.076.071 | 201.551 | 12,487 |
| Validation | 463.503.683 | 463.476.810 | 26.873 | 2,687 |
| Test | 695.255.524 | 695.215.214 | 40.310 | 3,752 |
| Tổng | 4.635.036.829 | 4.634.768.095 | 268.734 | 18,926 |

Cả 53.249 shard đều nằm ở volume `ssd`; chưa dùng dung lượng shard ở `hdd`
hoặc `system`. Một dataset chứa đủ ba split cho cả ba model. Không fit lại
vocabulary, không build lại matrix và không copy dữ liệu nguồn. Script mới
[`code/kaggle/package_host_shards.py`](../code/kaggle/package_host_shards.py)
đọc manifest, giữ nguyên checksum/split/feature và tạo một TAR khoảng **19 GB**.
NPZ bên trong đã nén nên TAR không nén thêm; chỉ cần khoảng **19 GB SSD bổ sung**,
không tạo CSR hay staging copy toàn bộ shard. Script giữ ít nhất 20 GiB trống.
RAM dành cho manifest và buffer copy, không dựng toàn bộ dataset trong RAM.
Archive dùng **USTAR** để tên dài được lưu bằng trường prefix/name tiêu chuẩn,
không phụ thuộc PAX extended headers. Script kiểm tra giới hạn USTAR trước khi ghi.

Chạy sau khi Bước 6 thành công:

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/kaggle/package_host_shards.py \
  --manifest /mnt/SSD_Data/optc/code/output/host_ml/model_input/manifest.json \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/package_host_shards.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/package_host_shards.log
```

Thêm `--dry-run` để chỉ kiểm tra đường dẫn/kích thước trước khi tạo TAR.
Sau thành công, log có `"ready_for_upload": true` và thư mục upload chứa:

```text
code/output/host_ml/kaggle_upload/
  host-input.tar       # khoảng 19 GB, đủ manifest/assets/helper/notebook/shard
  package_report.json # tổng số event/shard, split identity, SHA256 của TAR
```

Script kiểm tra SHA256 mỗi shard khi chép vào TAR, tính SHA256 của TAR và chỉ
publish thư mục cuối sau thành công. Nếu lỗi thông thường, staging được dọn;
chạy lại cùng lệnh sẽ đóng gói lại, không đọc lại eCAR và không ảnh hưởng Bước 1–6.
Đóng gói TAR không resume theo byte. Nếu mất điện/SIGKILL có thể còn thư mục ẩn
`.kaggle_upload.stage-*`; không upload thư mục dở đó. Script từ chối ghi đè một
`kaggle_upload/` đã tồn tại. Checkpoint, lock, storage ledger và shard không được
manifest tham chiếu đều không nằm trong TAR.

**Bước 8 — tạo Kaggle Dataset riêng tư từ máy local:**

Theo [Kaggle Datasets documentation](https://www.kaggle.com/docs/datasets)
(kiểm tra 15/09/2026), giới hạn là **200 GB/dataset**, tổng private datasets tối
đa 200 GB và tối đa 50 file ở cấp trên cùng. Archive được giải nén và giữ cấu
trúc thư mục. Gói khoảng 19 GB này phù hợp với giới hạn dataset nếu tài khoản
còn đủ quota. Giới hạn dataset không phải RAM/scratch của notebook.

Cài Kaggle CLI trong môi trường riêng để không đổi thư viện preprocessing:

```bash
python3 -m venv /mnt/SSD_Data/optc/code/output/kaggle_cli
/mnt/SSD_Data/optc/code/output/kaggle_cli/bin/pip install --upgrade kaggle
/mnt/SSD_Data/optc/code/output/kaggle_cli/bin/kaggle auth login
```

Lệnh login dùng đăng nhập qua trình duyệt. Nếu chạy SSH không thuận tiện, dùng
API token file tại `~/.kaggle/access_token` hoặc legacy `~/.kaggle/kaggle.json`
theo [hướng dẫn xác thực chính thức](https://github.com/Kaggle/kaggle-cli/blob/main/docs/README.md#authentication).
Credential ở máy local, không đặt trong thư mục upload.

Tạo metadata sau khi Bước 7 hoàn tất:

```bash
/mnt/SSD_Data/optc/code/output/kaggle_cli/bin/kaggle datasets init \
  -p /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload
nano /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload/dataset-metadata.json
```

Điền `title` là `OpTC Host ML Full Input`, `id` là
`YOUR_KAGGLE_USERNAME/optc-host-input` (thay username thật), và `licenses`
theo giấy phép áp dụng cho dữ liệu nguồn. Không mặc định nhận CC0 từ template.
Định dạng metadata ở [Kaggle CLI metadata](https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets_metadata.md).
Sau khi lưu metadata và đăng nhập, chạy upload:

```bash
nohup /mnt/SSD_Data/optc/code/output/kaggle_cli/bin/kaggle datasets create \
  -p /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/upload_kaggle.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/upload_kaggle.log
```

CLI mặc định tạo **private dataset**; lệnh này không có `--public`. Thư mục
upload chỉ có file ở cấp trên cùng, nên không cần `--dir-mode`. Không trỏ CLI
thẳng vào `model_input/`, vì CLI mặc định bỏ qua subdirectory và sẽ thiếu shard.
Nguồn: [Kaggle CLI datasets](https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets.md#kaggle-datasets-create).

Kiểm tra Kaggle đã xử lý xong (thay username thật):

```bash
/mnt/SSD_Data/optc/code/output/kaggle_cli/bin/kaggle datasets status \
  YOUR_KAGGLE_USERNAME/optc-host-input
```

Nếu upload bị ngắt, kiểm tra status trước khi chạy lại `create`; `nohup` giữ
process khi ngắt SSH nhưng không bảo đảm resume upload khi máy/mạng hỏng.
Cũng có thể dùng giao diện **New Dataset**, tải `host-input.tar`, giữ **Private**
và tạo dataset. Không cần tải riêng 53.249 file NPZ.

Nếu gói cũ báo `File already exists: 09e83798ff9316cb73f555b`: chuỗi này khớp
với tên bị cắt trong raw header của TAR PAX cũ. Kiểm tra local xác nhận tên đầy
đủ không trùng; đây là dấu hiệu Kaggle không dùng PAX extended path. Lỗi không
đòi hỏi tài khoản phải có dataset khác. Script đã đổi sang USTAR; không cần chạy
lại index/split/vocabulary/shards. Giữ gói cũ để đối chiếu, tạo gói sửa riêng:

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/kaggle/package_host_shards.py \
  --manifest /mnt/SSD_Data/optc/code/output/host_ml/model_input/manifest.json \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/kaggle_upload_ustar \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/package_host_shards_ustar.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/package_host_shards_ustar.log
```

Chỉ chạy lệnh này nếu thư mục `kaggle_upload_ustar/` chưa được tạo thành công.
Upload **`kaggle_upload_ustar/host-input.tar`** thay gói cũ. Nếu dùng CLI, tạo
`dataset-metadata.json` trong `kaggle_upload_ustar/` và đổi `-p` của lệnh create
sang thư mục này. Không upload cả hai TAR vào cùng dataset. Việc Kaggle nhận
gói mới cần xác nhận bằng lần upload thực tế; kiểm tra local chỉ xác nhận cấu
trúc USTAR và checksum. Tham khảo [Python TAR formats](https://docs.python.org/3/library/tarfile.html#supported-tar-formats).

**Bước 9 — gắn cùng dataset vào ba notebook:**

Tạo ba Kaggle notebook riêng, import lần lượt bản mới trong `code/kaggle/`:
`host_rf_shards.ipynb`, `host_xgb_shards.ipynb`, `host_lgbm_shards.ipynb`.
Ở mỗi notebook, dùng **Add Input** để gắn `YOUR_KAGGLE_USERNAME/optc-host-input`.
Các notebook mới cũng nằm trong TAR; bản builder đã chép vào `model_input/`
trước đây giữ nguyên và có thể còn cấu hình đường dẫn cũ.

Cell setup tự tìm `manifest.json` trong `/kaggle/input`, kể cả khi Kaggle thêm
một cấp thư mục khi giải nén TAR, và map mọi volume về `manifest.parent/volumes/`.
Nếu gắn nhiều Host datasets, đặt `MANIFEST` cụ thể trong cell đó. Setup kiểm tra
vocabulary/manifest rồi decode một shard của mỗi split và in shape/nhãn. Đây là
kiểm tra đường dẫn/format sau upload, không phải full validation lần thứ hai.
Không giải nén NPZ hoặc copy toàn bộ dataset sang `/kaggle/working`.

### 9.4. Ba notebook riêng và phạm vi đã kiểm thử

Builder chép các notebook và helper vào `model_input/`:

| Notebook | Cách đọc/train |
|---|---|
| `host_xgb_shards.ipynb` | `DataIter` + `ExtMemQuantileDMatrix`, CPU external memory; cần XGBoost ≥ 3.0 và đủ scratch/cache |
| `host_rf_shards.ipynb` | Dựng full TRAIN CSR sau kiểm tra budget; RF chuẩn vẫn cần nhiều RAM |
| `host_lgbm_shards.ipynb` | Dựng full TRAIN CSR rồi LightGBM Dataset; Dataset/model vẫn cần RAM bổ sung |

Ba notebook dùng cùng manifest, không tự chia lại, không tự undersample,
không dùng `warm_start` để giả lập việc RF học toàn bộ dữ liệu qua từng shard.
Với 4,64 tỷ event, RF/LightGBM trên notebook Kaggle thông thường có thể dừng ở
kiểm tra RAM. Input vẫn là full-data và tương thích qua CSR, nhưng nén input
không biến hai estimator này thành thuật toán external-memory. Cần quyết định
môi trường train sau khi đo kích thước; không tuyên bố train full cả ba đã chạy.
Với nnz đã đo, full TRAIN CSR theo reader hiện tại cần khoảng **591,5 GiB**,
chưa gồm RAM bổ sung của estimator. Vì vậy hai notebook RF/LightGBM hiện tại sẽ
dừng ở budget check 12 GiB trên bộ full này. Upload thành công chỉ xác nhận lưu
được input; không phải bằng chứng train full ba model trên Kaggle đã khả thi.
XGBoost external memory cũng cần cache, RAM cho trạng thái model và thời gian;
không được hiểu là bảo đảm vừa giới hạn Kaggle.
Tham khảo [XGBoost external memory](https://xgboost.readthedocs.io/en/stable/tutorials/external_memory.html),
[RF API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
và [LightGBM Dataset](https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.Dataset.html).

Metric helper đọc validation/test theo shard, chọn threshold trên validation,
giữ nguyên cho test. Precision/recall/F1/FPR tại threshold là số đếm chính xác;
PR-AUC/ROC-AUC ghi rõ `*_binned` vì dùng histogram score để tránh giữ hàng tỷ
probability trong RAM. Đây không phải AP/AUC tính chính xác trên mọi score.

Kiểm thử local gồm: round-trip mọi cột/nhãn/source line, row rỗng, source line
lớn, quota và chuyển volume, resume sau gián đoạn/corrupt shard, tổng nhãn đúng
split, reader đổi mount, và RF trên fixture tổng hợp. XGBoost/LightGBM không có
trong môi trường local này, nên adapter/notebook chỉ được kiểm tra cấu trúc và
interface; chưa chạy training hai thư viện đó. Probe 18.000 event đầu file ở
sáu ngày đã round-trip, nhưng prefix probe không đại diện tỷ lệ nén toàn corpus.
Packaging được kiểm thử round-trip TAR trên fixture nhiều volume, giữ nguyên
manifest/cột/nhãn, từ chối checksum sai và output vào nguồn, bảo vệ output đã có,
và chạy cell setup của cả ba notebook sau đổi mount. Chưa upload/training thực
tế trên Kaggle trong các kiểm thử local này.

## 10. Join và phạm vi tương lai

Host ↔ FLOW ↔ Network join vẫn là future work. Contract cần kiểm chứng:

```text
PROCESS.objectID → FLOW.actorID
FLOW.properties.bro_uid → Zeek.uid
```

Không join UUID eCAR với Zeek UID chỉ vì cùng là string. Fallback tuple/time phải
có host scope, protocol, tolerance và audit riêng. `sample/sample_ecarbro.json`
minh họa liên kết, không chứng minh coverage toàn corpus.

Shard hiện hành giữ source ID + source line để truy hồi event gốc có UUID,
host/time và PID. FLOW không tạo row Host, nên mapping này không thay thế
FLOW/linkage index. Network DL, fusion, graph joins và incremental retraining chưa được triển
khai bởi thay đổi tokenization này.

## 11. Kết quả lần chạy, kiểm thử và bằng chứng

Sau lần build đầu tiên, đọc số token, số record và phạm vi corpus từ
[`code/output/host_ml/vocab_metadata.json`](../code/output/host_ml/vocab_metadata.json).
Không ấn định trước kích thước vocabulary hoặc số record đã xử lý. Quy trình là
fit `code/output/host_ml/vocab.json` từ TRAIN, sau đó tạo
`code/output/host_ml/model_input/manifest.json` và shard theo cùng split đã lưu.
Số liệu trong sample nhỏ không phải bằng chứng distribution toàn corpus.

Kiểm thử local:

```bash
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp python3 -m unittest discover -s code -p 'test_*.py'
python3 code/build_host_index.py --dry-run
python3 code/explain_sample_tokenization.py --output code/output/sample_tokenization.md
```

Tests bao gồm pipeline direction, quoted literal, Python boundary/whitespace,
credential invariance, malformed Base64, output guards, deterministic build,
train-only fit validation, true counts, failed-input publication và resume.
Walkthrough dùng [`sample/command_line_sample.json`](sample/command_line_sample.json),
không fit vocabulary từ sample. Test pass không thay thế kiểm chứng full corpus.

Toolscaler chỉ cung cấp ý tưởng shared component, không phải implementation learned
codebook được sao chép vào đây. Các paper/nguồn lexical, AST và provenance được
liên kết trong research note. Ablation nên so lexical → anchors → syntax →
semantics/relations → AST trên cùng fit boundary. Báo cáo PR-AUC/AP, recall tại
ngân sách FPR, false alerts/host/day, OOV/parse status theo family/layer, số cột,
nnz, RAM và thời gian. Hiệu quả APT của phương pháp vẫn là giả thuyết cần đo.

## 12. Pipeline v2 — Contextual Split Option B (21/09/2026)

Implementation v4: lần chạy mới bên dưới dùng seed `02` và namespace
`code/output/host_ml_v2_seed02/`, giữ nguyên index,
split, vocab và shard v1. Plan gốc và checklist đã copy vào
`code/output/implementation_v4/`. Chưa chạy full scan hoặc training.

### 12.1 Phạm vi và số liệu đã kiểm tra

- Baseline: `[10:00, 10:30)` ET (UTC−04:00), ngày 21 và 22/09/2019.
- Attack: `[first_malicious, last_malicious]` inclusive trong 42 host-day files
  ngày 23–25/09, gồm cả benign và malicious đủ điều kiện Host ML.
- Dry-run trên index hiện có: **106 files**, **268,734 indexed malicious events**.
  Có 34 attacked hosts nhưng chỉ **32 hosts có baseline files** mỗi ngày.
- Theo xác nhận của người dùng, chỉ bỏ qua các baseline file bị thiếu:
  `sysclient0005` và `sysclient0010`, mỗi host thiếu cả ngày 21 và 22.
  Manifest ghi `missing_baseline_host_days`. Không bỏ qua attack file thiếu.
- Các con số ~6.6M events, ~5M TRAIN và ~23:1 trong plan là ước tính cũ,
  **chưa phải kết quả đo của implementation này**. Dry-run không ước lượng
  bằng giả định event phân bố đều theo thời gian. Hai ngày baseline là thứ Bảy
  và Chủ nhật; không thể dùng chúng để khẳng định weekday coverage.

Split vẫn là random event 75/10/15, exact global class quotas với
largest-remainder rounding, phân bổ theo source-file/label. **Lần chạy mới này
chọn seed `2` (hiển thị `02`)**; default CLI vẫn là `1`, nên luôn truyền
`--seed 02` theo các lệnh bên dưới.

Host/day/time quyết định **event nào thuộc cohort**; seed quyết định **event đó
vào TRAIN, VAL hay TEST**. Đổi cohort không bắt buộc đổi seed, nhưng dùng seed 2
cho experiment mới là hợp lệ. Seed 2 giữ nguyên cohort và class quotas, thay đổi
assignment ngẫu nhiên. Cả RF/XGB/LGBM phải dùng cùng manifest seed 2; không tạo
split riêng cho từng model. Seed của thuật toán training là một tham số khác.
Không chọn seed theo kết quả TEST. Khi cohort, tokenizer và seed cùng thay đổi,
chênh lệch metrics không thể quy riêng cho tokenizer.
Với 268,734 positives, quotas là TRAIN 201,550; VAL 26,874; TEST 40,310.
Không có temporal/process/campaign isolation. Cohort được chọn theo attack
labels, chỉ phản ánh các file-host đã bị tấn công; không suy ra FPR deployment
trên toàn bộ corpus. Hostname trong event có thể khác hostname trong tên file;
selection giữ semantics theo file của plan, không loại positives khác hostname.

### 12.2 Compatibility, integrity và resume

`build_split_contextual.py` xuất `kind=host_random_split` và gzip mask một byte
cho mỗi source line (0 exclude, 1 TRAIN, 2 VAL, 3 TEST). Vocab/shard readers dùng
trực tiếp format này. Raw labels là **0/1**; index codes là **0/1/2**
(exclude/benign/malicious), không được nhầm lẫn.

Index cũ có thể có tokenizer hash khác: contextual builder lưu provenance gốc,
kiểm tra checksum label streams và source path/size/mtime, rồi kiểm tra lại
**từng raw label và eligibility** trong các file được chọn. Nó không sửa index
và không bỏ qua tokenizer checks của split/vocab readers. Raw source content
không được hash toàn file; label streams và derived artifacts có SHA256.

File thiếu, timestamp không hợp lệ, checksum sai, eligibility thay đổi, hoặc
positive ngoài attack window đều làm build thất bại, không publish manifest.
Checkpoint theo file nằm ở `.split_contextual.checkpoints/<config-hash>/`, bind
với source identity, index checksum, selection, seed và implementation/tokenizer.
Chạy lại cùng lệnh để resume; completed output khác config được bảo vệ.
`--require-complete-baseline` có thể bật để từ chối cả baseline bị thiếu.

Vocab v2 phải fit lại trên **cả hai lớp của TRAIN v2**, rồi build shard v2.
Không reuse vocab v1 vì cả split và feature policy đã thay đổi. RF/XGB/LGBM
phải dùng cùng split/vocab/shards. Default representation là binary presence.

### 12.3 Chạy lại từ đầu với code mới — seed 02

“Chạy lại từ đầu” ở đây nghĩa là **build contextual split mới → vocab mới →
shards mới → verify → package**. Không cần scan lại toàn corpus để tạo index:
`code/output/host_ml/index/manifest.json` hiện có được reuse và revalidate như
mục 12.2. Không cần chạy `build_split.py` trước contextual builder. Không dùng
vocab/shards cũ cho experiment này.

Tất cả lệnh chạy từ `/mnt/SSD_Data/optc`. Namespace mới là
`code/output/host_ml_v2_seed02/`, không ghi đè `host_ml/` hoặc `host_ml_v2/`.
**Các bước dưới đây chưa được chạy full; đây là lệnh để người dùng chạy.**

#### Bước 0 — Chuẩn bị biến đường dẫn và log

Chạy block này trong terminal Bash; khi mở terminal mới, chạy lại để có các biến:

```bash
cd /mnt/SSD_Data/optc
export OPTC_RUN=/mnt/SSD_Data/optc/code/output/host_ml_v2_seed02
export OPTC_INDEX=/mnt/SSD_Data/optc/code/output/host_ml/index/manifest.json
export OPTC_STORAGE=/mnt/SSD_Data/optc/code/others/model_input_volumes.json

# Kiểm tra read-only boundary (kể cả symlink) trước khi tạo thư mục output/log.
python3 - <<'PY_SETUP'
import os, sys
from pathlib import Path
sys.path.insert(0, 'code/preprocess')
from pipeline_contract import validate_output_path
run = validate_output_path(Path(os.environ['OPTC_RUN']))
validate_output_path(run / 'logs').mkdir(parents=True, exist_ok=True)
PY_SETUP
```

#### Bước 1 — Kiểm tra cohort và build split seed 02

Dry-run không scan raw telemetry hoặc tạo split:

```bash
python3 code/preprocess/build_split_contextual.py \
  --index "$OPTC_INDEX" \
  --output-dir "$OPTC_RUN/split_contextual" \
  --seed 02 --dry-run
```

Mong đợi: 106 files, 42 attack windows, 268,734 indexed positives; báo thiếu
benign của sysclient0005/sysclient0010 ở ngày 21 và 22. Không truyền
`--require-complete-baseline` vì người dùng đã cho phép bỏ qua benign bị thiếu.

Build thật, có thể mất nhiều thời gian vì phải stream các source files:

```bash
python3 -u code/preprocess/build_split_contextual.py \
  --index "$OPTC_INDEX" \
  --output-dir "$OPTC_RUN/split_contextual" --seed 02
```

Sau khi thành công, kiểm tra seed, selected counts thực tế và missing baseline:

```bash
python3 - <<'PY_SPLIT'
import json, os
from pathlib import Path
p = Path(os.environ['OPTC_RUN']) / 'split_contextual/manifest.json'
m = json.loads(p.read_text())
assert m['kind'] == 'host_random_split' and m['seed'] == 2
print(json.dumps({k: m[k] for k in ('seed', 'counts', 'missing_baseline_host_days')}, indent=2))
PY_SPLIT
```

#### Bước 2 — Fit vocab.json mới, chỉ từ TRAIN seed 02

```bash
python3 -u code/preprocess/build_vocab.py \
  --split "$OPTC_RUN/split_contextual/manifest.json" \
  --output "$OPTC_RUN/vocab.json" \
  --metadata-output "$OPTC_RUN/vocab_metadata.json" \
  --min-frequency 2 --min-document-frequency 1 \
  --rank-by term-frequency --workers 4
```

Fit cả benign + malicious TRAIN, gồm các feature tokenizer v4 mới. Không đặt
`--max-vocab-size` nên không có cap bổ sung. Validation/test không đóng góp TF/DF
hoặc feature columns. Metadata ghi split hash, seed, tokenizer hashes, thresholds
và token statistics. `vocab.json` map token → sparse column index.

#### Bước 3 — Build binary sparse shards mới

```bash
python3 -u code/preprocess/build_model_input.py \
  --split "$OPTC_RUN/split_contextual/manifest.json" \
  --vocab "$OPTC_RUN/vocab.json" \
  --vocab-metadata "$OPTC_RUN/vocab_metadata.json" \
  --output-dir "$OPTC_RUN/model_input" \
  --storage-config "$OPTC_STORAGE" \
  --workers 4 --rows-per-shard 100000 --buffer-mib 32
```

Manifest/assets ở `$OPTC_RUN/model_input/`. Physical NPZ shards nằm theo run ID
trong approved volumes của `model_input_volumes.json`, **không nhất thiết ở trong
OPTC_RUN**. Volume ledger đếm cả dữ liệu cũ để giữ quota/free-space reserve.
Không sửa volume paths tùy ý hoặc xóa shard cũ; pipeline không cần global CSR.

#### Bước 4 — Verify từng shard, gồm decode

```bash
python3 -u code/preprocess/verify_model_input.py \
  --manifest "$OPTC_RUN/model_input/manifest.json" --decode
```

#### Bước 5 — Package để upload Kaggle

```bash
python3 -u code/kaggle/scripts/package_host_shards.py \
  --manifest "$OPTC_RUN/model_input/manifest.json" \
  --output-dir "$OPTC_RUN/kaggle_upload"
```

Output: `$OPTC_RUN/kaggle_upload/host-input.tar` và `package_report.json`.
Dùng cùng package này cho RF/XGB/LGBM. Bước này chỉ package, không tự upload
hoặc train. Chỉ chạy bước kế tiếp khi bước trước đã exit thành công.

#### Cách chạy toàn chuỗi bằng một nohup job, có log từng bước

Đây là **cách thay thế** cho việc chạy thủ công các bước 1–5 bên trên. Chạy
Bước 0 trước, rồi copy cả block này. Các job chạy tuần tự; một bước lỗi thì
script dừng. Không chạy block này đồng thời với các lệnh build thủ công.

```bash
nohup bash -s > "$OPTC_RUN/logs/pipeline.log" 2>&1 <<'PIPELINE' &
set -euo pipefail
cd /mnt/SSD_Data/optc
: "${OPTC_RUN:?Run step 0 first}"
: "${OPTC_INDEX:?Run step 0 first}"
: "${OPTC_STORAGE:?Run step 0 first}"

run_stage() {
  local stage="$1"
  shift
  echo "[$(date -Is)] START $stage"
  "$@" 2>&1 | tee -a "$OPTC_RUN/logs/$stage.log"
  echo "[$(date -Is)] DONE $stage"
}

run_stage 00_dry_run python3 -u code/preprocess/build_split_contextual.py \
  --index "$OPTC_INDEX" --output-dir "$OPTC_RUN/split_contextual" --seed 02 --dry-run
run_stage 01_split python3 -u code/preprocess/build_split_contextual.py \
  --index "$OPTC_INDEX" --output-dir "$OPTC_RUN/split_contextual" --seed 02
run_stage 02_vocab python3 -u code/preprocess/build_vocab.py \
  --split "$OPTC_RUN/split_contextual/manifest.json" \
  --output "$OPTC_RUN/vocab.json" --metadata-output "$OPTC_RUN/vocab_metadata.json" \
  --min-frequency 2 --min-document-frequency 1 --rank-by term-frequency --workers 4
run_stage 03_shards python3 -u code/preprocess/build_model_input.py \
  --split "$OPTC_RUN/split_contextual/manifest.json" \
  --vocab "$OPTC_RUN/vocab.json" --vocab-metadata "$OPTC_RUN/vocab_metadata.json" \
  --output-dir "$OPTC_RUN/model_input" --storage-config "$OPTC_STORAGE" \
  --workers 4 --rows-per-shard 100000 --buffer-mib 32
run_stage 04_verify python3 -u code/preprocess/verify_model_input.py \
  --manifest "$OPTC_RUN/model_input/manifest.json" --decode
run_stage 05_package python3 -u code/kaggle/scripts/package_host_shards.py \
  --manifest "$OPTC_RUN/model_input/manifest.json" --output-dir "$OPTC_RUN/kaggle_upload"
echo "[$(date -Is)] ALL STAGES COMPLETE"
PIPELINE
OPTC_JOB_PID=$!
echo "Pipeline PID: $OPTC_JOB_PID"
```

Theo dõi bằng terminal hiện tại hoặc terminal khác sau khi chạy Bước 0:

```bash
tail -n 50 -f "$OPTC_RUN/logs/pipeline.log"
# Hoặc theo dõi riêng bước đang chạy:
tail -n 50 -f "$OPTC_RUN/logs/02_vocab.log"
```

`Ctrl+C` khi đang `tail` chỉ dừng xem log. Dòng `ALL STAGES COMPLETE` xác nhận
chuỗi đã thành công; chỉ có PID hoặc thấy file log chưa có nghĩa là hoàn tất.

Nếu bị gián đoạn: không xóa checkpoints; chạy lại lệnh của bước lỗi với cùng
config, rồi tiếp tục các bước sau. Split/shards completed cùng config có thể
reuse; vocab có checkpoint trong lúc scan. Package chưa publish có thể chạy lại;
package đã tồn tại sẽ được bảo vệ và lệnh từ chối ghi đè. Nếu muốn một lần build
hoàn toàn độc lập nữa, đổi `OPTC_RUN` sang tên mới, không xóa output cũ.
Giữ code/tokenizer cố định trong suốt run; đổi code sau split có thể yêu cầu
build lại split/vocab/shards ở namespace mới.

### 12.4 Tokenizer v4

| Feature | Hành vi |
|---|---|
| `principal::*` | finite built-in/domain/absent buckets, admin marker; không emit username/domain/SID |
| `*::subcategory` | system32/syswow64/sysnative, windows_other, windows_temp/user_temp, roaming/local; giữ category hiện có |
| `file_path::system_stem`, `module_path::system_stem` | normalized stems chỉ ở system32/syswow64; không emit raw UUID/counter |
| `shell::class_namespace`, `shell::class_name` | bounded static parse `ParameterBinding(New-Object)` + `TypeName`; namespace 2 segments và leaf |
| `command_line::cmd::self_spawn=true` | image và parent cùng cmd.exe |
| `command_line::context::suspicious_parent=python->network_tool` | actual Python parent → ping/net/net1/ipconfig child; heuristic context |
| WSH | `//` host options trước script, timeout presence, script-extension anchor, arguments sau script |
| rundll32 | DLL/entrypoint anchors + relation; finite review list comsvcs/advpack/ieadvpack |

Các feature này là giả thuyết cải thiện FP/FN, **chưa chứng minh sửa được số lỗi
trong plan**. Không thực thi command hoặc payload. Python AST và PowerShell
parsing hiện có được giữ nguyên.

### 12.5 Notebook result zip và raw provenance

RF/XGB/LGBM dùng cùng export cell trong generator
`code/kaggle/scripts/refresh_host_notebooks.py`. Zip gồm `results/`,
`provenance/vocab.json`, `vocab_metadata.json`, `shard_manifest.json`,
`split_manifest.json` (new packages), `results/diagnostics/val_errors.json`,
`test_errors.json` và `shard_source_index.json`. Diagnostic JSON hiện chỉ giữ
tối đa 100 FP + 100 FN mỗi split (extreme scores), không phải toàn bộ lỗi;
notebook chưa tạo per-error-type JSONL. Xem mục 13 để export toàn bộ lỗi. Legacy packages thiếu split manifest vẫn export được
và thông báo thiếu; split hash vẫn có trong shard manifest.

Index key là `volume/path`, join `shard.source_id` với manifest `sources`.
Không suy ra source root từ shard label: file host-malicious có thể chứa benign.
Diagnostic row chứa **`source_id`, `source_line` (1-based raw JSONL line)**,
không phải zero-based shard offset. Join `source_id` với `sources[].source.path`,
rồi stream gzip local bằng `enumerate(handle, 1)` để lấy đúng raw record.
`code/audit/extract_raw_events.py` là helper Mission 4 hard-coded, không phải CLI
trực tiếp cho mọi result zip. README trong zip giải thích lookup.

Split manifest được copy vào assets khi build shards, package upload giữ asset
này. Zip publish bằng rename sau khi hoàn tất; SHA256 tính streaming.

### 12.6 Kiểm thử

```bash
python3 code/test/test_ecar_tokenizer.py
python3 code/test/test_build_vocab.py
python3 code/test/test_build_split_contextual.py
python3 code/test/test_notebook_exports.py
PYTHONPATH=code/preprocess:code/others:code/kaggle:code/kaggle/scripts:code/test \
  python3 -m unittest test_stratified_pipeline test_host_shards \
  test_pipeline_contract test_package_host_shards
```

Synthetic fixtures kiểm tra boundary ET, giữ positives, exact quotas,
interruption/resume, deterministic masks, TRAIN-only vocab, shard compatibility,
archive provenance và read-only protections. Không xem fixtures hoặc dry-run là
bằng chứng về phân bố event hay chất lượng model toàn corpus.

## 13. Audit XGBoost seed02/run1 — toàn bộ FN/FP

Kết quả đã kiểm tra: test F1 **0.907662**, precision **0.983890**, recall
**0.842396**, threshold validation **0.88845**. Test có **556 FP + 6,353 FN**.
Saved model inference local tái tạo chính xác confusion counts cả VAL và TEST,
không retrain. Đã trace toàn bộ **6,909 test errors** và **4,652 validation errors**
về raw JSONL source lines; không sửa dataset/model/split/vocab.

Notebook hiện chỉ lưu 100 extreme FP + 100 extreme FN mỗi split trong
`val_errors.json` / `test_errors.json`. Để có toàn bộ errors dùng frozen model và
local shards với `code/audit/audit_xgb_run.py`, sau đó resolve raw logs bằng
`code/audit/extract_error_rows.py`. Không chỉ tăng số examples rồi giả định đã đủ.

Artifacts của run này ở `code/output/host_ml_v2_seed02/kaggle_output/run1/`:

- `audit_report.md`: phân tích chi tiết, case traces, lệnh tái tạo cho run sau.
- `error_audit/summary.json`: full confusion, signature collisions, error counts.
- `error_audit/error_signatures.json`: tokens, full TRAIN class counts, nhóm lỗi.
- `all_raw_errors/test_all_errors_raw.jsonl`: toàn bộ 556 FP + 6,353 FN, có raw_event.
- `all_raw_errors/val_all_errors_raw.jsonl`: toàn bộ 389 FP + 4,263 FN, có raw_event.

Trong test, 362 vectors mang cả hai labels: ít nhất 6,235 errors không tránh được
với deterministic classifier dùng cùng representation. Empirical test-label oracle
F1 ceiling = 0.916770; đây chỉ là phân tích khả năng phân biệt của feature vectors,
không phải valid trained model/threshold. THREAD image_path bị bỏ hiện tạo nhiều
collisions; 3,288 FN thuộc THREAD. Non-THREAD lwabeat.exe tạo thêm 2,180 FN.
Bốn Chrome FILE vectors tạo 277 FP. Report phân biệt feature loss, label/context
ambiguity và model errors; chưa thay đổi tokenizer dựa trên audit này.
