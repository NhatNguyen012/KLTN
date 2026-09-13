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
CSR binary; `--representation both` ở bước matrix thêm count để ablation.
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
  matrix/X_{train,val,test}.npz
  matrix/y_{train,val,test}.npy
  matrix/row_sidecar_{train,val,test}.jsonl
  matrix/split_metadata.json
  sample_tokenization.md
```

Giữ vocabulary/split cùng nhau. Vocabulary fit benign 16–20/09 không đáp ứng
contract của random split mới và không được dùng để tạo matrix thí nghiệm này.
Các artifact ngoài `host_ml/` hiện có được giữ nguyên. Các artifact dùng tên thống nhất, không thêm hậu tố phiên bản.

Index/split/vocabulary/matrix resume theo file hoàn tất. Checkpoint validate
code/config, split/vocab identity khi áp dụng, source path/size/mtime_ns và
SHA256 artifact. Đây **không** phải content hash toàn bộ dataset. Chạy lại cùng
lệnh khi bị ngắt; file đang dở sẽ được đọc lại. Directory output index/split/
matrix cuối phải chưa tồn tại; output hoàn tất được giữ lại, không ghi đè bằng
partial run. Vocabulary publish cặp JSON theo từng file atomic; consumer kiểm
tra checksum để phát hiện cặp không đồng bộ.

Các lệnh dưới đây là full corpus. Dry-run hiện tìm thấy 4.695 file; đó là số
file nguồn, không phải số event. Với hàng tỷ Host events, matrix/sidecar và
checkpoint có thể cần rất nhiều dung lượng. Bộ nhớ merge dùng disk-backed
arrays, nhưng không bảo đảm full training vừa RAM 31 GiB. Index và split phải
hoàn tất trước để biết số row chính xác; đọc metadata và kiểm tra `df -h` trước
bước matrix. Không suy rằng pipeline streaming đồng nghĩa full model training
sẽ vừa RAM. TF/DF counters của vocabulary vẫn tăng theo số token khác nhau.

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

**Bước 5 — build ba matrix cùng split, binary sparse:**

```bash
df -h /mnt/SSD_Data/optc/code/output/host_ml
nohup python3 -u /mnt/SSD_Data/optc/code/build_matrix.py \
  --split /mnt/SSD_Data/optc/code/output/host_ml/split/manifest.json \
  --vocab /mnt/SSD_Data/optc/code/output/host_ml/vocab.json \
  --vocab-metadata /mnt/SSD_Data/optc/code/output/host_ml/vocab_metadata.json \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/matrix \
  --representation binary --workers 12 --chunk-rows 10000 \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/build_matrix.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/build_matrix.log
```

Đọc `matrix/split_metadata.json` sau khi thành công: số row/nhãn phải khớp split;
OOV, nnz và avg_nnz_per_row phản ánh phép transform thực tế. Matrix không tự
chia lại theo ngày/host. `build_host_pilot.py` là công cụ scenario train/test
riêng, không dùng cho baseline này.

**Bước 6 — đóng gói local để chuyển sang Kaggle (sau khi matrix hoàn tất):**

```bash
nohup python3 -u /mnt/SSD_Data/optc/code/package_kaggle_input.py \
  --input-dir /mnt/SSD_Data/optc/code/output/host_ml \
  --matrix-dir /mnt/SSD_Data/optc/code/output/host_ml/matrix \
  --output-dir /mnt/SSD_Data/optc/code/output/host_ml/kaggle_input \
  < /dev/null > /mnt/SSD_Data/optc/code/output/host_ml/logs/package_kaggle_input.log 2>&1 &
tail -n 30 -f /mnt/SSD_Data/optc/code/output/host_ml/logs/package_kaggle_input.log
```

Packaging tạo bản sao, cần thêm dung lượng tương ứng matrix. Bước này chỉ tạo
thư mục local, không upload hay chạy model. Full training trên Kaggle vẫn phụ
thuộc giới hạn dung lượng/RAM của môi trường; preprocessing thành công không
bảo đảm toàn bộ corpus vừa môi trường đó. Các script model đọc sẵn cùng
`matrix/`, không gọi random split lần nữa.

## 10. Join và phạm vi tương lai

Host ↔ FLOW ↔ Network join vẫn là future work. Contract cần kiểm chứng:

```text
PROCESS.objectID → FLOW.actorID
FLOW.properties.bro_uid → Zeek.uid
```

Không join UUID eCAR với Zeek UID chỉ vì cùng là string. Fallback tuple/time phải
có host scope, protocol, tolerance và audit riêng. `sample/sample_ecarbro.json`
minh họa liên kết, không chứng minh coverage toàn corpus.

Row sidecar hiện có event ID, actor/object ID, host/time, pid khi có, source file
và line. FLOW không tạo row Host, nên sidecar Host này không thay thế FLOW/linkage
index. Network DL, fusion, graph joins và incremental retraining chưa được triển
khai bởi thay đổi tokenization này.

## 11. Kết quả lần chạy, kiểm thử và bằng chứng

Sau lần build đầu tiên, đọc số token, số record và phạm vi corpus từ
[`code/output/host_ml/vocab_metadata.json`](../code/output/host_ml/vocab_metadata.json).
Không ấn định trước kích thước vocabulary hoặc số record đã xử lý. Quy trình là
fit `code/output/host_ml/vocab.json` từ TRAIN, sau đó transform matrix ở
`code/output/host_ml/matrix/` theo cùng split đã lưu.
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
