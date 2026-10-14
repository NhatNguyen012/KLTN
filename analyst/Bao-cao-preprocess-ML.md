# Báo cáo tiền xử lý Host ML: từ eCAR thô đến đầu vào RF/XGBoost/LightGBM


> Cập nhật đối chiếu artifact ngày 14/10/2026. Báo cáo phân biệt **số liệu đọc từ artifact**, **đại lượng tính từ số liệu đó**, **ví dụ minh họa** và **thí nghiệm đề xuất**. Lần cập nhật tài liệu này không chạy lại huấn luyện hoặc tái tạo split/vocabulary.

## Tóm tắt nghiên cứu

Nhánh Host ML giải quyết bài toán phân loại nhị phân ở **cấp sự kiện** trên corrected OpTC. Đầu vào là bản ghi eCAR có cấu trúc; đầu ra tiền xử lý là vector hiện diện token, có thể truy ngược về file và dòng nguồn. Phương pháp kết hợp đặc trưng trường, chuẩn hóa giá trị động, cấu trúc lệnh và quan hệ trong cùng record để cung cấp đầu vào chung cho ba mô hình cây.

Run được duyệt có **8.331.257 event**, vocabulary **9.048 cột**, **358 shard** và **114.547.913 phần tử khác 0**. Tỉ lệ malicious của cohort xấp xỉ **3,23%**. Đây là cohort contextual được chọn, không đại diện cho mọi event trong corpus. Kết quả baseline LightGBM trên TEST đạt F1 **95,3324%**; kết quả này dùng Host features, chưa cộng GraphSAGE hoặc DL. Điểm số chứng minh đầu vào có ích cho phân loại trong protocol hiện tại; chưa chứng minh khả năng nhận diện APT chưa biết hay tổng quát xuyên dataset.

Đóng góp kỹ thuật của bước tiền xử lý nằm ở hợp đồng feature có thể kiểm tra, biểu diễn sparse dùng chung và khả năng truy vết/reproduce. Không xem bộ quy tắc tokenizer là một mô hình ngôn ngữ học được; không quy kết toàn bộ cải thiện cho một nhóm token khi chưa có ablation.

**Bố cục:** mục 1–2 xác định dữ liệu/protocol; mục 3–6 giải thích token; mục 7–8 mô tả artifact và ví dụ đầu–cuối; mục 9 nêu giới hạn; mục 10–15 bổ sung định nghĩa toán học, số liệu biểu diễn, kết quả baseline, tái lập và hướng mở rộng.

## 1. Phạm vi và căn cứ tái lập

Báo cáo này mô tả **run đã duyệt `host_ml_seed02`**, tức thí nghiệm trước đây gọi là v4, tại `code/output/host_ml_seed02/`. Dữ liệu đầu vào là telemetry Host/eCAR đã hiệu chỉnh trong `host-begnin/` và `host-malicious/`; hai thư mục này chỉ được đọc. `bro/` và `ecar-bro/` không tham gia nhánh Host ML. Mục tiêu của tiền xử lý là biến **mỗi event Host được chọn** thành một hàng vector sparse nhị phân, dùng chung cho Random Forest, XGBoost và LightGBM. Nó không tạo embedding câu, đồ thị provenance thực, hoặc đặc trưng mạng. GraphSAGE thuộc thí nghiệm khác trong `code/provenace_graph/`.

Các phát biểu về hành vi lấy từ `code/preprocess/{build_host_index.py,build_split_contextual.py,build_vocab.py,ecar_tokenizer.py,command_syntax.py,build_model_input.py,host_shards.py}` và `code/kaggle/host_training_runtime.py`. Các con số lấy từ manifest/vocabulary metadata **đã xuất bản**; ví dụ event thật ở mục 8 được kiểm tra lại bằng cách giải mã shard. Các lệnh mẫu ở mục 6 là **ví dụ sư phạm chạy qua tokenizer hiện hành**, không phải trích dẫn log thật hay bằng chứng rằng toàn bộ token minh họa còn trong vocabulary.

```text
eCAR JSON.GZ, từng dòng một
  → chỉ mục nhãn/đủ điều kiện + danh tính file nguồn
  → cohort contextual seed 02 + mặt nạ TRAIN/validation/TEST cố định
  → tokenize TRAIN cả hai lớp → đếm tần suất → vocab.json (9.048 cột)
  → tokenize lại từng event đã chọn → tra vocab → vector 0/1
  → NPZ shard nén + manifest + provenance source_id/source_line
  → Kaggle: giải mã từng shard thành CSR X, nhãn y → lấy mẫu TRAIN → fit model
  → đánh giá toàn bộ validation/TEST
```

**Không tái dựng run đã duyệt** bằng các mặc định seed 01 của builder tổng quát. Split của run này là seed **02**; seed **1** trong notebook chỉ điều khiển lấy mẫu TRAIN. Metadata còn một số đường dẫn lịch sử do di chuyển run; đó là provenance, không phải nơi ghi output hiện hành. Danh tính được đối chiếu bằng SHA-256, không sửa lại hash để khớp đường dẫn mới.

## 2. Đọc log, gán nhãn và chọn tập event

Một file `.json.gz` là luồng **JSON mỗi dòng một event**. Chỉ mục ghi nhãn và tình trạng đủ điều kiện theo thứ tự dòng, đồng thời gắn định danh nguồn bằng đường dẫn, kích thước, thời gian sửa và checksum của artifact. Trong split, byte mask ứng với mỗi dòng nguồn: `0` = bỏ khỏi cohort, `1` = TRAIN, `2` = validation, `3` = TEST. Dòng được chọn được đọc lại từ JSON nguồn; nhãn được kiểm tra đối chiếu với chỉ mục rồi chuyển thành `y ∈ {0,1}`. `source_line` là số dòng **1-based** trong file nén khi đọc tuần tự, phục vụ truy vết chứ không là feature.

Tokenizer chỉ chấp nhận `object` trong `PROCESS`, `FILE`, `MODULE`, `REGISTRY`, `TASK`, `SHELL`, `THREAD`, `USER_SESSION`, `SERVICE`, `HOST`. `FLOW` và object thiếu/không biết bị loại. Với action ngoài danh mục hữu hạn, giữ event nhưng dùng `action::unknown`. Thuộc tính được đọc theo allowlist theo từng object; không serialize toàn bộ JSON thành từ. Ví dụ `PROCESS` chỉ lấy `image_path`, `parent_image_path`, `command_line`; `FILE` lấy `image_path`, `file_path`, `new_path`; `MODULE` lấy `image_path`, `module_path`; `REGISTRY` lấy `image_path` và một trong `key/registry_key/registry_path`; `TASK` lấy `image_path/path`; `SHELL` lấy `image_path/payload`; `THREAD` chỉ lấy `image_path`; ba object còn lại không lấy property. Trường nhãn, timestamp, event ID, PID, UUID, địa chỉ, khóa liên kết và host/source ID **không được đưa trực tiếp vào X**.

Run seed02 dùng cohort `contextual_option_b`: các cửa sổ baseline 21–22/09 theo host liên quan và cửa sổ tấn công theo file/host; baseline `[10:00,10:30)` và cửa sổ attack đóng cả hai đầu. Mọi positive đủ điều kiện trong cửa sổ tấn công được giữ; nhiều dòng ngoài cửa sổ có mask `0`. Trên cohort này, chia ngẫu nhiên theo strata file nguồn/nhãn với tỉ lệ 75/10/15 và seed 02, làm tròn để giữ quota lớp toàn cục. Đây là **split event**, không phải split theo tiến trình, host, thời gian hay campaign. Bản thân việc chọn cohort dựa trên nhãn/cửa sổ đã biết nên kết quả chỉ phản ánh thí nghiệm được duyệt, không chứng minh khả năng tổng quát trên bối cảnh chưa thấy.

| Partition cố định | Benign (`y=0`) | Malicious (`y=1`) | Tổng event |
|---|---:|---:|---:|
| TRAIN | 6.046.892 | 201.551 | 6.248.443 |
| Validation | 806.252 | 26.873 | 833.125 |
| TEST | 1.209.379 | 40.310 | 1.249.689 |

Các con số này là số hàng sau chọn cohort, không phải tổng mọi dòng JSON đọc được. `split/manifest.json` còn ghi file thiếu ở một số cặp baseline host/ngày. `split_rows()` đối chiếu lại nhãn và quota trước khi builder tạo shard.

### 2.1. Phân biệt nhãn nguồn, mã index và mã split

Ba loại mã sau không được dùng thay thế cho nhau:

| Đối tượng | Mã | Ý nghĩa |
|---|---|---|
| Nhãn học `y` | `0 / 1` | Benign / malicious. |
| Luồng nhãn index | `0 / 1 / 2` | Bị loại / benign đủ điều kiện / malicious đủ điều kiện. |
| Mặt nạ split | `0 / 1 / 2 / 3` | Ngoài cohort / TRAIN / validation / TEST. |

`label_of()` kiểm tra `hostname` trong event; tên file là nơi chứa dữ liệu, không bảo đảm mọi dòng phát sinh từ host ghi trên filename. Object không hỗ trợ được loại. Nhãn phải là số nguyên 0 hoặc 1; riêng nguồn benign cho phép nhãn thiếu và quy về 0, đồng thời từ chối nhãn khác 0. Không gán mọi dòng trong `host-malicious/` thành malicious: nguồn này vẫn có event benign. Quy tắc benign thiếu nhãn thuộc hợp đồng dữ liệu corrected OpTC, không được tự áp dụng cho dataset mới chưa có ground truth.

### 2.2. Ba phạm vi dữ liệu cần báo cáo riêng

- **Corpus nguồn:** các file có thể đọc trong kho corrected OpTC; không đồng nhất với cohort.
- **Cohort/split đóng băng:** các event được chọn bởi contextual windows và eligibility, tổng 8.331.257 hàng.
- **Tập fit model:** subset TRAIN do notebook chọn sau khi fit vocabulary; không thay đổi validation/TEST.

Manifest đầu vào chứa 106 nguồn; metadata vocabulary ghi các ngày 21–25/09/2019. Phạm vi tổng quát 16–25/09 trong hướng dẫn workspace không có nghĩa run này dùng mọi ngày hoặc mọi dòng. Danh sách thiếu baseline host/ngày phải được giữ để người đọc biết bối cảnh benign chưa hoàn chỉnh.

## 3. Một event được chuyển thành những nhóm token nào?

`tokenize_record()` trả về sáu nhóm có token trong run này: `action`, `object`, `principal`, `command_line`, `property_value`, `structure_semantic`; nhóm `property_key` được khai báo trong giao diện nhưng chủ ý không phát token. Quy trình cho một event `PROCESS` điển hình:

1. **Ngữ cảnh eCAR:** `action=CREATE`, `object=PROCESS` → `action::create`, `object::process`, `structure::action_object=create->process`.
2. **Principal:** `NT AUTHORITY\SYSTEM` → `principal::nt_system`. Tài khoản miền được gom thành `principal::domain_user`, có thể thêm `principal::admin_account`; tên domain/user thô không trở thành cột.
3. **Đường dẫn:** chuẩn hóa dấu gạch, chữ hoa/thường và phần thay đổi, rồi lấy nhóm vị trí và basename. `\Device\HarddiskVolume1\Windows\system32\cmd.exe` → `image_path::category=system`, `image_path::subcategory=system32`, `image_path::basename=cmd.exe`. Đường dẫn cha được xử lý theo phạm vi `parent_image_path`.
4. **Quan hệ cha–con trong *cùng event*:** nếu có hai path, basename `Explorer.EXE` và `cmd.exe` → `structure::process_lineage=explorer.exe->cmd.exe`. Đây là token quan hệ từ hai trường, **không phải** cạnh tra cứu từ graph database; không xác minh cha bằng PID/đồ thị.
5. **Command line:** nếu object là `PROCESS` và có `command_line`, nhận diện một trong bảy họ lệnh; lexer/parser hữu hạn sinh thêm token launcher, cú pháp, vai trò tham số, quan hệ và từ chuẩn hóa. Mục 5–6 trình bày chi tiết.

Các object khác không bị ép thành command line: `FILE` phát đặc trưng loại vị trí/extension của `file_path/new_path`; `MODULE` có basename/module path; `REGISTRY` có root và các loại khóa hữu hạn; `SHELL` có token cho payload kiểu được nhận biết. Không ghép các event khác nhau thành một chuỗi lịch sử ở bước Host ML.

### Chuẩn hóa literal và giới hạn an toàn

Tokenizer chuẩn hóa Unicode NFKC, khoảng trắng/chữ thường ở token phát ra, đồng nhất các thành phần động như thư mục user thành `user_name`, `sysclient####` thành `host_name`, `HarddiskVolume#` thành `harddiskvolume`, UUID/SID/IP/hex/số dài thành loại giá trị. Các giá trị mật khẩu, user, task, host ở vị trí tham số nhạy cảm được thay bằng **kiểu** (`password_value`, `task_name_value`...), không đưa nguyên văn vào feature. Token quá dài (>160 ký tự) hoặc chỉ có dấu câu bị bỏ. Command line tối đa 32.768 ký tự; lexer tối đa 1.024 lexeme, độ sâu lồng tối đa 4; Python AST giới hạn 256 node; giải mã PowerShell encoded command có giới hạn độ dài/độ sâu. Cú pháp ngoài khả năng parser được giữ ở trạng thái opaque hoặc gắn token parse-status, không đoán thay cho shell. **Không thực thi** command, script, DLL hay payload trong log.

## 4. “Anchor, Structure, Syntax, Graph, Sentences, Words” nghĩa là gì trong mã hiện tại?

Tên dễ gây nhầm vì đây không phải sáu encoder độc lập. **Một token chuỗi là một cột** của X; `token_layers()` chỉ gắn nhãn bằng chứng phục vụ audit/ablation và một token có thể thuộc nhiều lớp.

| Thuật ngữ | Mã thực sự làm | Ví dụ token | Giới hạn diễn giải |
|---|---|---|---|
| **Context** | Action, object, family, principal tổng quát | `action::create`, `object::process`, `command_line::family=cmd` | Không phải ngữ cảnh nhiều event. |
| **Anchor** | Giữ tên launcher/command/module/API/DLL đã chuẩn hóa khi parser nhận đúng vai trò | `command_line::anchor::launcher=cmd.exe` | Tên hiếm có thể không qua lọc tần suất TRAIN. |
| **Structure** | Vai trò theo mệnh đề và quan hệ có hướng | `command_line::relation::pipeline=whoami->findstr` | “Graph” ở đây là **token cạnh/quan hệ trong một event**; không tạo node/edge provenance hay message passing. |
| **Syntax** | Switch, toán tử, quote, mode, node/edge AST an toàn | `command_line::syntax::switch=/c`, `command_line::python::ast_node=call` | Không mô phỏng đầy đủ `cmd`/PowerShell. |
| **Semantic** | Loại principal, path, operand, extension, giá trị động | `command_line::semantic::value_type=password` | Là phân loại hữu hạn theo quy tắc, không phải hiểu nghĩa bằng embedding. |
| **Words / lexical** | Tách từ đã chuẩn hóa trong phạm vi family/field | `command_line::cmd::whoami` | Từ không có thứ tự ngữ nghĩa như câu gốc; X chỉ lưu hiện diện. |
| **Sentences** | Không có sentence tokenizer/embedding riêng. Parser dùng chuỗi lệnh/cụm lệnh để rút các token trên | `-Command "Get-Process | Select-Object Name"` → token operator/pipeline/word | Không có cột chứa nguyên câu, n-gram câu, BERT hay vector dense. |

Số token vocabulary theo **nhóm**: `action` 22, `object` 8, `principal` 6, `command_line` 3.603, `property_value` 5.044, `structure_semantic` 365; tổng **9.048**. Theo **nhãn lớp bằng chứng**: anchor 5.321, context 37, lexical 2.249, semantic 377, structure 973, syntax 291. Tổng các nhãn lớp lớn hơn 9.048 vì chúng **chồng lấn**, không phải tạo thêm cột.

## 5. Cơ chế chung trước khi tách bảy họ command

`classify_command_line(command_line, image_path)` ưu tiên **basename của `image_path`**; nếu thiếu thì lấy executable đầu tiên của lexer argv. Bảng tra cứu chính xác: `cmd(.exe)` → `cmd`; `powershell/pwsh(.exe)` → `powershell`; các tên `python`, `pythonw`, `python3`, `python3.x` tương ứng → `python`; `wscript(.exe)` → `wscript`; `cscript(.exe)` → `cscript`; `rundll32(.exe)` → `rundll32`; còn lại → `native`. Đây là phân loại **launcher/grammar**, không phải nhãn malicious/benign. Một malware gọi `schtasks.exe` vẫn là `native`; một `cmd.exe` benign vẫn là `cmd`.

Lexer trong `command_syntax.py` nhận argv Windows, quote/backslash, caret/toán tử CMD, quote/backtick/comment/semicolon PowerShell và span của từng lexeme. Trình phân tích tách vai trò launcher/switch/value, shallow clauses và nested command khi đủ bằng chứng. Các loại token thường xuất hiện đồng thời:

```text
command_line::family=cmd                     # họ launcher
command_line::anchor::launcher=cmd.exe      # Anchor: tên trong vai trò launcher
command_line::syntax::switch=/c             # Syntax: switch
command_line::relation::switch_value=/c->command_fragment
command_line::cmd::whoami                   # Word/lexical: từ chuẩn hóa
```

Sau parser, `flatten_tokens()` nối các nhóm theo thứ tự ổn định; khi xây X, mỗi event dùng `set(...)` nên token lặp trong cùng event vẫn chỉ bật cột **1 lần**. Trong lúc fit vocabulary, TF/DF được đếm trên **TRAIN**: metadata ghi ngưỡng TF ≥ 2, DF ≥ 1, không giới hạn số cột, thứ tự ranking theo TF rồi DF và token. Token ngoài vocab trở thành OOV và không có cột. Không có TF-IDF hoặc số đếm trong input đã duyệt.

## 6. Bảy họ lệnh: ví dụ input → token output và lý do

Để chỉ ra khác biệt do command parser, các ví dụ sau có cùng vỏ eCAR giả định: `action=CREATE`, `object=PROCESS`, `principal=NT AUTHORITY\SYSTEM`, `parent_image_path=C:\Windows\explorer.exe`; `image_path` là executable ở cột “input”. Vì vậy mỗi ví dụ còn sinh `action::create`, `object::process`, `principal::nt_system`, `structure::action_object=create->process`, các token path và `structure::process_lineage=explorer.exe-><launcher>`. Các token liệt kê bên dưới là **một phần tiêu biểu thực sự do tokenizer phát ra**, không phải toàn bộ token hoặc cột chắc chắn còn sau lọc TRAIN.

### 6.1. `cmd`: lệnh nội tuyến và pipeline

**Input:** `image_path=C:\Windows\System32\cmd.exe`; `command_line=cmd.exe /c "whoami | findstr SYSTEM"`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=cmd`; `command_line::anchor::launcher=cmd.exe`; `command_line::anchor::command=whoami`; `command_line::anchor::command=findstr` | Nhận executable và các command ở vị trí cú pháp. |
| Syntax | `command_line::cmd::mode=/c`; `command_line::syntax::switch=/c`; `command_line::syntax::operator=pipe` | `/c` là chế độ chạy chuỗi; `|` là toán tử. |
| Structure/“graph” | `command_line::relation::switch_value=/c->command_fragment`; `command_line::relation::pipeline=whoami->findstr` | Bảo tồn hướng nguồn→đích trong pipe, nhưng chỉ là cột token. |
| Words | `command_line::cmd::whoami`; `command_line::cmd::findstr`; `command_line::cmd::system` | Từ đã lower-case, không giữ nguyên câu hay số lần lặp. |

Parser chỉ nhận cấu trúc nông của `/c`/`/k`; không chạy `whoami`, không đánh giá biến môi trường, redirection hay kết quả pipe.

### 6.2. `powershell`: option host và lệnh `-Command`

**Input:** `image_path=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`; `command_line=powershell.exe -NoProfile -Command "Get-Process | Select-Object Name"`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=powershell`; `command_line::anchor::launcher=powershell.exe`; `command_line::anchor::command=get-process`; `command_line::anchor::command=select-object` | Nhận cmdlet trong vai trò command. |
| Syntax | `command_line::syntax::switch=-noprofile`; `command_line::syntax::switch=-command`; `command_line::syntax::operator=pipe` | Phân biệt option của host với cú pháp lệnh nội tuyến. |
| Structure | `command_line::relation::launcher_payload=powershell->inline_command`; `command_line::relation::pipeline=get-process->select-object` | Giữ quan hệ host→payload, cmdlet→cmdlet. |
| Words | `command_line::powershell::get`; `command_line::powershell::process`; `command_line::powershell::select`; `command_line::powershell::object`; `command_line::powershell::name` | Có lexical fallback bên cạnh anchor. |

`-EncodedCommand` được nhận biết và giải mã Base64 có giới hạn để **phân tích tĩnh**, tối đa hai lớp; lỗi/không hỗ trợ được audit, không thực thi. `-File` chuyển phần sau thành script path, không tiếp tục hiểu mọi tham số script như option PowerShell host. Đây không phải PowerShell AST đầy đủ.

### 6.3. `python`: `-c`, `-m` và Python AST an toàn

**Input:** `image_path=C:\Python39\python.exe`; `command_line=python.exe -c "import os; print(os.getcwd())"`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=python`; `command_line::anchor::launcher=python.exe`; `command_line::anchor::module=os`; `command_line::anchor::api=print`; `command_line::anchor::api=os.getcwd` | Module/API chỉ phát khi phân tích cú pháp có căn cứ. |
| Syntax | `command_line::python::mode=-c`; `command_line::python::ast=parse_success`; `command_line::python::ast_node=import`; `command_line::python::ast_node=call` | `ast.parse` trích node theo giới hạn, không chạy Python. |
| Structure | `command_line::python::ast_edge=module->import`; `command_line::relation::switch_value=-c->command_fragment` | Có quan hệ cú pháp AST/option→code fragment. |
| Words | `command_line::python::import`; `command_line::python::os`; `command_line::python::print`; `command_line::python::getcwd` | Fallback lexical khi phù hợp. |

`-m` được hiểu là chạy module và tạo anchor module; file `.py` là chế độ script. Các option như `-W/-X` được xử lý như ranh giới option của Python, không lấy code/string thô làm nhãn định danh.

### 6.4. `wscript`: Windows Script Host chế độ GUI

**Input:** `image_path=C:\Windows\System32\wscript.exe`; `command_line=wscript.exe //B C:\Users\Alice\job.vbs`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=wscript`; `command_line::anchor::launcher=wscript.exe`; `command_line::anchor::script_ext=.vbs` | Giữ loại script, không mở nội dung `.vbs`. |
| Syntax | `command_line::syntax::wsh_option=//b`; `command_line::syntax::switch=//b` | `//B` là option của WSH trước script. |
| Structure/semantic | `command_line::relation::command_switch=wscript.exe->//b`; `command_line::relation::role_transition=switch->script`; `command_line::semantic::role=script`; `command_line::semantic::subtype=.vbs` | Ranh giới host option→script được giữ. |
| Words | `command_line::wscript::users`; `command_line::wscript::user_name`; `command_line::wscript::job`; `command_line::wscript::vbs` | `Alice` được chuẩn hóa thành `user_name`. |

### 6.5. `cscript`: Windows Script Host chế độ console

**Input:** `image_path=C:\Windows\System32\cscript.exe`; `command_line=cscript.exe //Nologo C:\Scripts\job.js`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=cscript`; `command_line::anchor::launcher=cscript.exe`; `command_line::anchor::script_ext=.js` | Family riêng dù cùng kiểu WSH với `wscript`. |
| Syntax | `command_line::syntax::wsh_option=//nologo`; `command_line::syntax::switch=//nologo` | Nhận switch WSH. |
| Structure/semantic | `command_line::relation::role_transition=switch->script`; `command_line::semantic::role=script`; `command_line::semantic::subtype=.js` | Giữ vị trí script và extension. |
| Words | `command_line::cscript::nologo`; `command_line::cscript::scripts`; `command_line::cscript::job`; `command_line::cscript::js` | Các từ scoped theo family `cscript`. |

Hai họ WSH chỉ phân tích option và path/extension; không thực thi VBScript/JScript, không suy ra nội dung file từ đường dẫn.

### 6.6. `rundll32`: thư viện và entry point

**Input:** `image_path=C:\Windows\System32\rundll32.exe`; `command_line=rundll32.exe C:\Windows\System32\advpack.dll,LaunchINFSection C:\Temp\setup.inf`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=rundll32`; `command_line::anchor::launcher=rundll32.exe`; `command_line::anchor::dll=advpack.dll`; `command_line::anchor::entrypoint=launchinfsection` | Nhận DLL và entry point quanh dấu phẩy. |
| Syntax | `command_line::syntax::delimiter=dll_entry` | Dấu phẩy có vai trò ngăn DLL/entry. |
| Structure | `command_line::relation::dll_entry=advpack.dll->launchinfsection`; `command_line::relation::launcher_target=library->entry_point` | Quan hệ cặp mục tiêu, không tải DLL. |
| Word/context | `command_line::rundll32::review_dll=advpack.dll`; lexical `advpack`, `dll`, `launchinfsection`, `setup`, `inf` | Danh mục DLL cần chú ý là hữu hạn; không thay cho kết luận ác ý. |

### 6.7. `native`: executable còn lại, ví dụ `schtasks.exe`

**Input:** `image_path=C:\Windows\System32\schtasks.exe`; `command_line=schtasks.exe /Create /TN DemoTask /SC ONCE /P TopSecret`.

| Tầng | Output tiêu biểu | Diễn giải |
|---|---|---|
| Family/anchor | `command_line::family=native`; `command_line::anchor::launcher=schtasks.exe` | Fallback cho launcher không thuộc sáu họ trên. |
| Syntax | `command_line::syntax::switch=/create`; `...=/tn`; `...=/sc`; `...=/p` | Tách switch theo argv. |
| Structure/semantic | `command_line::relation::switch_value=/tn->task_name`; `...=/sc->schedule`; `...=/p->password`; `command_line::semantic::value_type=task_name`; `...=password` | Vai trò option đặc thù được nhận bằng allowlist công cụ. |
| Words đã bảo vệ | `command_line::native::task_name_value`; `command_line::native::password_value`; `command_line::native::once` | Không phát nguyên văn `DemoTask` hay `TopSecret`. |

Các quy tắc switch đặc thù chủ yếu áp dụng cho `schtasks`, `net`, `runas`, `wmic`, `psexec`, `ssh`; với executable không biết, parser giữ bằng chứng chung và tránh tự gán vai trò bảo mật cho switch mơ hồ. `native` không đồng nghĩa “lệnh hệ thống an toàn”.

## 7. Fit vocabulary TRAIN và tạo shard nhị phân

Builder vocabulary chỉ đi qua các dòng được gán **TRAIN**, gồm cả benign và malicious. Với mỗi event, tokenizer phát nhóm token; thống kê TF/DF theo token, áp dụng ngưỡng trong mục 5 rồi ghi `vocab.json` ánh xạ `token → column_index`. Chỉ số cột là **định danh**, không mang thứ bậc/tương quan số học. Validation và TEST **chỉ transform** qua vocabulary đã đóng băng, không đóng góp vào việc chọn token/cột. Validation vẫn được dùng ở bước huấn luyện/đánh giá để chọn threshold; TEST không được dùng để chọn threshold.

Builder `build_model_input.py` xác nhận split/vocabulary cùng danh tính, duyệt lại từng dòng được chọn, tính `C = sorted({vocab[t] | t ∈ set(tokens), t ∈ vocab})`, rồi append `(C, label, source_line)` vào buffer của partition tương ứng. Nếu token không có trong vocab thì bỏ riêng token đó; event vẫn được giữ kể cả khi `C` rỗng. `host_shards.py` ghi NPZ nén với bốn mảng: `row_nnz` (số cột bật mỗi hàng), `column_delta` (chênh lệch giữa cột đã sort trong hàng), `label` (`uint8`) và `source_line_delta` (chênh lệch số dòng nguồn). Manifest giữ `source_id` cho mỗi shard và thông tin nguồn ở bảng `sources`; chỉ `X` mang feature. Mỗi shard/asset có kiểm tra kích thước, checksum và quota lớp. Không có ma trận CSR toàn cục trong artifact.

Ở phía notebook, reader xác minh manifest và vocabulary asset rồi giải mã từng shard thành `X` CSR kích thước `n_rows × 9.048`, các giá trị khác 0 là `float32(1)`, cùng `y` và tùy chọn dòng nguồn để audit. Kaggle dùng `host-input.tar` của run này và một trong ba notebook `host_rf_shards.ipynb`, `host_xgb_shards.ipynb`, `host_lgbm_shards.ipynb`. Cấu hình đã duyệt của notebook lấy **toàn bộ positive TRAIN** và undersample negative theo mục tiêu `NEG_PER_POS=30`, RNG seed 1; đây là bước **fit model**, xảy ra sau khi vocabulary và shard của toàn TRAIN đã được chốt. Validation/TEST được đánh giá đầy đủ. Xem `code/kaggle/docs/KAGGLE_RUNBOOK.md` để chạy lại, không thay input đã duyệt.

Manifest `model_input/manifest.json` ghi format `host_binary_delta_npz`, `complete=true`, **358 shard**. Số phần tử khác 0: TRAIN 85.911.106, validation 11.457.427, TEST 17.179.380. Các giá trị này đếm cột bật, không đếm số từ xuất hiện trong câu lệnh thô.

## 8. Kiểm chứng đầu–cuối bằng một dòng log eCAR thật

Dòng 2.379.509 của `host-malicious/2019-09-24/AIA-1-25/AIA-1-25.ecar-2019-09-24-sysclient0005.json.gz` là event thật nằm **ngay đầu cửa sổ attack**. Đây là ví dụ về **định dạng và phép biến đổi**, không dùng nhãn validation để fit vocabulary. Một phần JSON liên quan:

```json
{
  "timestamp": "2019-09-24T13:58:55.992-04:00",
  "action": "CREATE", "object": "PROCESS", "principal": "SYSTEMIACOM\\sysadmin", "label": 1,
  "properties": {
    "image_path": "\\Device\\HarddiskVolume1\\Windows\\system32\\cmd.exe",
    "parent_image_path": "\\Device\\HarddiskVolume1\\Windows\\Explorer.EXE",
    "command_line": "\"C:\\Windows\\system32\\cmd.exe\" "
  }
}
```

Trong split mask của file này, byte ứng với dòng 2.379.509 là **2 = validation**. Tokenizer chọn `family=cmd`, sinh **24 token duy nhất**; toàn bộ 24 token đã có trong vocabulary TRAIN. Những cặp token→cột tiêu biểu (đã kiểm tra trên `vocab.json`):

| Token | Cột zero-based |
|---|---:|
| `image_path::category=system` | 3 |
| `image_path::subcategory=system32` | 4 |
| `object::process` | 10 |
| `principal::domain_user` | 18 |
| `action::create` | 47 |
| `image_path::basename=cmd.exe` | 66 |
| `principal::admin_account` | 72 |
| `command_line::anchor::launcher=cmd.exe` | 142 |
| `command_line::family=cmd` | 143 |
| `parent_image_path::basename=explorer.exe` | 150 |
| `structure::action_object=create->process` | 248 |
| `structure::process_lineage=explorer.exe->cmd.exe` | 5291 |

Vector đúng của event có 24 vị trí bật:

```text
X[0].indices = [3, 4, 6, 9, 10, 13, 18, 42, 47, 66, 72, 77,
                140, 141, 142, 143, 150, 152, 159, 162, 192, 193, 248, 5291]
y[0] = 1
```

Chúng nằm trong `val_000000.npz` thuộc nguồn `source_id=1b70bf046dfc4b986018604e0cfb71164280863a53edfbb18ae8446f05e76882`, `run_id=f49109280acd8c1660fbe1c837664215964c46f7927f15a1bb986a224247e0fa`. Lần kiểm chứng đầu–cuối đã ghi nhận việc giải mã shard bằng `decode_shard()` và xác nhận `source_line[0]=2.379.509`, nhãn `1`, tập cột **bằng đúng** tập cột tra từ 24 token. `timestamp`, `source_id`, `source_line`, tên `SYSTEMIACOM` và chữ `sysadmin` thô không có trong X; tên tài khoản chỉ đóng góp hai bucket `domain_user` và `admin_account`. Sự kiện có parent path nên có token lineage; điều đó không có nghĩa parser đã dựng/duyệt provenance graph.

## 9. Kiểm soát rò rỉ, giới hạn và tài liệu kiểm chứng

- **Không fit trên validation/TEST:** split được đóng băng trước khi quét TRAIN để xây vocabulary; notebook chỉ dùng validation để chọn threshold/đánh giá và giữ TEST cho báo cáo. Kiểm tra `split_sha256` và `vocabulary_sha256` trong manifest, metadata và kết quả notebook.
- **Không biến danh tính thành feature:** ID/PID/source line/timestamp dùng để trace hoặc quản lý split, không làm cột X. Danh sách field được phép đọc là hữu hạn; giá trị động được chuẩn hóa/định kiểu. Điều này giảm memorization nhưng cũng bỏ bớt thông tin có thể hữu ích.
- **Giới hạn token quan hệ:** `structure::process_lineage` từ hai path trong record không chứng minh tiến trình cha thực, và không bao gồm FILE/MODULE node lân cận. Những sự kiện khác nhãn nhưng có cùng Host vector là giới hạn biểu diễn của nhánh này; đổi routing hoặc mô hình tree đơn thuần không tự tạo thêm thông tin.
- **Giới hạn split:** cohort chọn theo bối cảnh/nhãn đã biết; event split có thể đặt event cùng tiến trình/campaign ở các partition khác nhau. Không diễn giải metric như kiểm chứng độc lập theo host/campaign/thời gian.
- **Giới hạn parser:** không giải mã vô hạn, không chạy mã, không hiểu trọn shell; token `parse_status`, truncation hoặc opaque biểu thị phần chưa phân tích chắc chắn. Cần kiểm tra OOV/độ phủ khi áp dụng cho corpus khác.

Tệp kiểm chứng chính: `code/output/host_ml_seed02/split/manifest.json`, `vocab.json`, `vocab_metadata.json`, `model_input/manifest.json` và `model_input/volumes/ssd/`; hướng dẫn run ở `code/README.md` và `code/kaggle/docs/KAGGLE_RUNBOOK.md`. Lệnh đọc/kiểm tra có sẵn:

```bash
python3 code/preprocess/verify_model_input.py \
  --manifest code/output/host_ml_seed02/model_input/manifest.json --decode
python3 code/test/test_ecar_tokenizer.py
python3 code/test/test_host_shards.py
```

## 10. Định nghĩa biểu diễn và lý do thiết kế

### 10.1. Từ sự kiện đến bài toán học

Gọi `r_i` là event thô và `T(r_i)` là danh sách token do tokenizer phát ra. Vocabulary `V` chỉ được chọn từ TRAIN; `v(t)` ánh xạ token sang một trong `d = 9.048` cột. Biểu diễn nhị phân được định nghĩa:

```text
x_ij = 1 nếu tồn tại t thuộc T(r_i) sao cho v(t) = j; ngược lại bằng 0.
X thuộc {0,1}^(n × d), y thuộc {0,1}^n.
s_i = f_theta(x_i)
y_hat_i = 1[s_i >= tau_val]
```

`theta` được học trên tập fit TRAIN, còn `tau_val` được chọn bằng validation. Một hàng không đại diện một tiến trình đầy đủ, một cửa sổ 15 phút hoặc một campaign. Malicious event prediction là bằng chứng cho hệ thống APT ở mức cao hơn, chưa phải kết luận tự động về chiến dịch.

Có hai thao tác khác nhau: **fit vocabulary** quyết định những cột nào tồn tại; **fit classifier** quyết định cách kết hợp các cột để dự đoán. Vocabulary dùng cả hai lớp TRAIN nhưng không đưa nhãn thành token. Khi phục vụ inference, phải dùng đúng tokenizer/schema và vocabulary của model, không tạo cột mới theo log đến sau.

### 10.2. TF, DF và binary presence khác nhau

TF là tổng số lần tokenizer phát token trong TRAIN; DF là số event TRAIN chứa token, mỗi event đếm tối đa một lần. Mã fit dùng `tf.update(tokens)` và `df.update(set(tokens))`. Ví dụ token lặp ba lần trong một event đóng góp TF=3, DF=1 nhưng chỉ đóng góp `x_ij=1` vào ma trận cuối. Ngưỡng TF≥2, DF≥1 không bảo đảm token xuất hiện ở ít nhất hai event: hai lần trong cùng event vẫn có thể đủ điều kiện. Thứ tự cột theo tần suất không phải trọng số hoặc thứ bậc ngữ nghĩa.

### 10.3. Các quyết định và đánh đổi

| Quyết định hiện tại | Mục đích | Thông tin mất đi / điều cần kiểm chứng |
|---|---|---|
| Allowlist field/object | Giới hạn đầu vào và tránh đưa nhãn/ID vào feature | Không khai thác mọi trường telemetry. |
| Typed normalization | Giảm vocabulary do username, host, UUID và literal động | Có thể hợp nhất những hành vi khác nhau thành cùng vector. |
| Field-scoped token | Phân biệt cùng basename ở image path và parent path | Tăng số cột so với bag-of-words không có scope. |
| Cấu trúc launcher/switch/operand | Giữ một phần quan hệ và vai trò cú pháp | Phụ thuộc parser hữu hạn; không hiểu đầy đủ chương trình. |
| Binary sparse presence | Biểu diễn gọn, dễ truy vết, dùng chung cho mô hình cây | Bỏ tần suất token trong event và thứ tự tổng quát. |
| Shard delta + nén | Lưu đầu vào lớn theo từng phần, có checksum và resume | Cần giải mã; kích thước file nén không phải RAM huấn luyện. |
| Event-level classification | Có target và provenance rõ cho baseline | Không tự sử dụng lịch sử nhiều event hoặc phát hiện chiến dịch. |

Đây là lý do thiết kế, chưa phải bằng chứng binary tốt hơn counts/TF-IDF hoặc semantic tokens tốt hơn mọi biểu diễn khác. Các so sánh đó cần ablation cùng protocol.

## 11. Quy mô, độ thưa và độ phủ vocabulary

### 11.1. Thống kê từ manifest đã xuất bản

Bảng dưới tính từ `model_input/manifest.json`; `nnz` là số cột bật. Mật độ = `nnz / (rows × 9.048)`. MiB dùng 2²⁰ byte.

| Partition | Event | nnz | Cột bật/event (trung bình) | Mật độ | NPZ nén (MiB) |
|---|---:|---:|---:|---:|---:|
| TRAIN | 6.248.443 | 85.911.106 | 13.749 | 0.1520% | 24.267 |
| Validation | 833.125 | 11.457.427 | 13.752 | 0.1520% | 5.161 |
| TEST | 1.249.689 | 17.179.380 | 13.747 | 0.1519% | 7.197 |

Tổng dung lượng NPZ được manifest ghi nhận là **38.403.324 byte (36.624 MiB)**, chưa gồm asset, manifest, checkpoint và model. Ma trận dense `float32` cho cả cohort về lý thuyết cần `n × d × 4`, khoảng **280.82 GiB** chỉ cho giá trị. Đây là phép tính kích thước, không phải số đo peak RAM. CSR còn cần indices/indptr, nhãn, buffer giải mã và bộ nhớ riêng của thuật toán; không suy ra RAM huấn luyện từ 36–37 MiB file nén.

Ngưỡng shard là tối đa 100.000 hàng hoặc buffer 33.554.432 byte, nhưng shard còn tách theo nguồn/partition và được flush cuối file. Vì vậy 358 shard không bằng phép chia đơn giản tổng event cho 100.000. Delta encoding phục hồi được chính xác binary vector và source line; “lossless” ở đây là không mất thêm dữ liệu **sau bước feature extraction**, không có nghĩa phục hồi được toàn bộ JSON từ X.

### 11.2. OOV phải đọc đúng đơn vị

Builder thống kê token duy nhất **trong từng event**, rồi cộng trên toàn cohort và từng lớp bằng chứng. Một token OOV xuất hiện ở 100 event đóng góp 100 lượt; đây không phải số loại token OOV toàn corpus. Các lớp chồng lấn, không cộng các hàng để suy ra số token độc lập.

| Lớp bằng chứng | Lượt token-event ứng viên | Lượt OOV | OOV / ứng viên |
|---|---:|---:|---:|
| anchor | 16.654.025 | 2.070 | 0.012429% |
| context | 18.446.921 | 2 | 0.000011% |
| lexical | 11.872.578 | 441 | 0.003714% |
| semantic | 48.123.448 | 21 | 0.000044% |
| structure | 18.478.512 | 166 | 0.000898% |
| syntax | 2.647.696 | 9 | 0.000340% |

Các số trên gộp TRAIN/validation/TEST; không phải OOV riêng TEST hoặc đo domain shift. OOV nhỏ không đồng nghĩa khả năng tổng quát tốt: normalization mạnh, shared process context giữa partition và token phổ biến đều có thể làm OOV thấp. Báo cáo triển khai cần bổ sung OOV theo nguồn, object, family, thời gian và lớp nhãn; không tự đặt OOV bằng xác suất malicious.

## 12. Kết quả baseline và quan hệ với tiền xử lý

### 12.1. Đầu vào thực tế của ba lần fit

Cả RF, XGBoost và LightGBM lưu cùng `sample_id`, split hash và vocabulary hash. Tập fit có **6.248.110 hàng**, gồm **201.551 positive** và **6.046.559 negative**, nnz **85.906.198**. So với TRAIN đóng băng, bước sampling chỉ loại **333 negative**, giữ toàn bộ positive. Vì cohort đã gần 30:1, không mô tả bước này như undersampling mạnh hay cân bằng 1:1. Tỉ lệ fit thực tế xấp xỉ 30,00014 negative/positive.

| Model | Cấu hình checkpoint đã lưu | Phiên bản thư viện |
|---|---|---|
| RF | 500 cây; max_depth=20; min_samples_leaf=5; max_features=sqrt; class weights theo mẫu fit | scikit-learn 1.6.1 |
| XGBoost | 300 rounds; max_depth=8; eta=0,05; hist; max_bin=16; device=cuda; scale_pos_weight≈30,00014 | XGBoost 3.2.0 |
| LightGBM | 300 rounds; num_leaves=31; learning_rate=0,05; deterministic=true; force_col_wise=true; scale_pos_weight≈30,00014 | LightGBM 4.6.0 |

Đây là cấu hình ghi trong artifact kết quả, không suy ra từ default của thư viện hiện tại. Cùng input không có nghĩa ba model có cùng capacity hoặc chi phí tính toán. Class weighting cũng khiến score không mặc nhiên là xác suất đã calibration; threshold không bắt buộc bằng 0,5.

### 12.2. Đánh giá toàn bộ TEST với threshold chọn từ validation

| Model | Threshold | F1 validation | Precision TEST | Recall TEST | F1 TEST | FPR TEST |
|---|---:|---:|---:|---:|---:|---:|
| RF | 0.56634 | 91.1234% | 95.8746% | 86.7676% | 91.0940% | 0.12444% |
| XGB | 0.87878 | 94.7974% | 97.9265% | 92.0888% | 94.9180% | 0.06499% |
| LGBM | 0.94016 | 95.3032% | 98.8128% | 92.0888% | 95.3324% | 0.03688% |

| Model | TP | FP | FN | TN | PR-AUC binned | ROC-AUC binned |
|---|---:|---:|---:|---:|---:|---:|
| RF | 34.976 | 1.505 | 5.334 | 1.207.874 | 0.923689 | 0.984778 |
| XGB | 37.121 | 786 | 3.189 | 1.208.593 | 0.952314 | 0.995290 |
| LGBM | 37.121 | 446 | 3.189 | 1.208.933 | 0.957761 | 0.995706 |

Nguồn: các file `results/{rf,xgb,lgbm}_metrics.json` được liên kết ở mục 15. Confusion counts được đếm trực tiếp trên toàn TEST; AUC lấy từ histogram 100.000 bins, nên phải gọi là **binned**, không thay bằng tuyên bố exact AUC.

`Precision = TP/(TP+FP)`, `Recall = TP/(TP+FN)`, `F1 = 2TP/(2TP+FP+FN)`, `FPR = FP/(FP+TN)`. Ví dụ LightGBM có 446 FP trên 1.209.379 benign TEST, tương đương khoảng 369 false positives trên một triệu **event benign** cùng phân phối. Đây không phải 369 cảnh báo/ngày hay/host: quy đổi cảnh báo còn phụ thuộc lưu lượng, aggregation và suppression.

LightGBM có F1 cao nhất trong ba cấu hình đã chạy. XGBoost và LightGBM có cùng số FN nhưng chưa đủ căn cứ nói chúng sai trên cùng những event; cần join source identity để kiểm tra. Không dùng thứ hạng này để kết luận thuật toán nào luôn tốt nhất trên dataset khác.

### 12.3. Điều kết quả này chưa chứng minh

Kết quả là baseline Host ML với event split, không phải kết quả cascade LightGBM+GraphSAGE F1≈98,50% trong thư mục `provenace_graph`. Không gộp hai metric vào một bảng mà thiếu mô tả feature/model/protocol. Tương tự, chưa có đo latency end-host, peak RAM triển khai, robust unknown detection hoặc cross-dataset evaluation trong các file metrics được trích ở đây. Để chứng minh lợi ích của token cấu trúc, cần so sánh có kiểm soát với lexical-only; chỉ một kết quả cuối không tách được đóng góp từng nhóm feature.

## 13. Hợp đồng tái lập và kiểm chứng artifact

### 13.1. Danh tính cần đóng băng

```text
split_sha256      = f771b56d8f70adc8d452b37cd430d847de877f6ef97e076db094864c450bb560
vocabulary_sha256 = f3e1331a29ff451de2c97af8c016e1e4694bf91a8b506ca2d04f65b96bfbef8e
model_input_run_id = f49109280acd8c1660fbe1c837664215964c46f7927f15a1bb986a224247e0fa
model_fit_sample  = acbac01adfb83604371fd54c740044981f4226fab9101d131f2866074d4666ff
```

Cần ghi cùng nhau tokenizer policy/code hash, vocabulary, split masks, manifest/shard hashes, training sample, thư viện và model parameters. Seed đơn lẻ không đủ để tái lập. Đường dẫn cũ trong provenance có thể khác vị trí hiện tại; không sửa lịch sử hoặc checksum để ép resume. Thay đổi tokenizer có thể làm thay đổi cột bật dù tên policy không đổi, vì vậy phải kiểm tra code identity và compatibility.

### 13.2. Tiêu chí kiểm tra theo từng bước

| Bước | Điều phải kiểm tra | Sai lệch cần dừng xử lý |
|---|---|---|
| Index / nguồn | Host hợp lệ, label contract, source identity | Nhãn ngoài 0/1, nguồn thay đổi, dòng không đúng schema. |
| Split | Mặt nạ, quota lớp, split SHA-256 | Số hàng/lớp không khớp hoặc artifact chưa hoàn tất. |
| Vocabulary | Fit counts chỉ TRAIN, cột duy nhất/liên tục, policy | Dùng validation/TEST để chọn cột hoặc vocabulary khác model. |
| Shard | Checksum, dtype, row_nnz, column bounds, line delta | Hỏng payload, dòng không tăng, cột ngoài vocabulary, label mismatch. |
| Training | Sample identity, class counts, model/runtime compatibility | Vô tình đổi tập fit hoặc resume checkpoint khác input. |
| Evaluation | Đủ hàng, threshold từ validation, confusion khớp tổng | Bỏ hàng TEST hoặc lựa chọn policy bằng TEST. |
| Error audit | `(source_id, source_line)` và model version | Join lỗi giữa các run hoặc coi ID là feature. |

Các test tokenizer/shard kiểm tra hành vi trên fixture và round-trip; chúng không chứng minh ground truth của corpus là hoàn hảo. Chạy full decode verifier kiểm tra integrity artifact nhưng không thay thế đánh giá model hay audit nhãn.

Trong lần mở rộng báo cáo này, đã đối chiếu trực tiếp manifest, vocabulary metadata và ba metrics JSON; kiểm tra hash split/vocabulary hiện hành, tổng lớp/hàng/nnz/shard, đồng nhất sample giữa ba model và tính lại metric từ confusion counts. Ví dụ raw-event ở mục 8 giữ kết quả kiểm chứng đã ghi nhận trước đó; lần cập nhật này không quét lại toàn corpus hoặc huấn luyện model.

## 14. Hướng mở rộng có thể kiểm nghiệm

| Câu hỏi nghiên cứu | Thí nghiệm đề xuất | Kiểm soát bắt buộc |
|---|---|---|
| Token cấu trúc có thêm ích lợi? | Lexical/context baseline so với thêm anchor, syntax, relations | Cùng split và fit sample; fit vocabulary từng cấu hình chỉ trên TRAIN; ghi rõ lớp token có chồng lấn. |
| Binary có phù hợp hơn counts/TF-IDF? | So sánh representation | Fit IDF trên TRAIN; không mặc định cấu hình model tối ưu giống nhau. |
| Mô hình có tổng quát qua host/thời gian? | Grouped host/process split, temporal holdout hoặc campaign holdout riêng | Không thay approved split; tạo experiment namespace mới. |
| Graph có bổ sung thông tin bị mất? | Learned graph/cascade so với Host-only | Cùng target, chỉ dùng bằng chứng sẵn có tại thời điểm dự đoán; không dùng nhãn ancestor. |
| Dataset khác có giúp học thêm? | External evaluation; pooled training; sequential update + replay | Phân biệt ba protocol; mapping feature/label/unit, split theo nguồn/campaign và fit transform TRAIN-only. |
| Có thể đưa lên endpoint? | Đo throughput, p95 latency, peak RAM và FPR theo host/thời gian | Dùng nguồn log thực và mô hình đóng gói; không suy từ độ nhỏ file NPZ. |

**Đánh giá trên dataset mới** chỉ đo model cũ; **pooled training** fit trên TRAIN đã harmonize từ nhiều nguồn; **sequential update** dùng checkpoint phù hợp và dữ liệu mới, kèm replay/validation miền cũ. Ba việc này không tương đương. Thêm dataset không tự tạo multi-label, không tự mở rộng vocabulary cũ và không mặc định RF/XGB/LGBM hỗ trợ cùng cơ chế cập nhật như DL. Nếu đổi schema/cột, cần pipeline/model version mới.

Đối với Linux, các giả định Windows path/registry/launcher trong tokenizer hiện tại cần adapter và feature policy phù hợp. Không chỉ đổi đường dẫn dataset rồi đưa auditd vào tokenizer eCAR. Đối với kiến trúc đa nguồn mục tiêu, đầu ra Host ML phải gắn target, thời gian bằng chứng, model version và source mask để fusion căn chỉnh với DL; bản báo cáo này chưa xác nhận phần fusion đã được triển khai.

## 15. Bản đồ bằng chứng và tài liệu liên quan

| Nội dung | Nguồn kiểm chứng |
|---|---|
| Run và đường dẫn hiện hành | [code README](../code/README.md), [Kaggle runbook](../code/kaggle/docs/KAGGLE_RUNBOOK.md) |
| Lựa chọn cohort và quota | [Split manifest](../code/output/host_ml_seed02/split/manifest.json), [contextual split builder](../code/preprocess/build_split_contextual.py) |
| Hợp đồng label/index | [stratified_pipeline.py](../code/preprocess/stratified_pipeline.py) |
| Rule/field và parsing | [ecar_tokenizer.py](../code/preprocess/ecar_tokenizer.py), [command_syntax.py](../code/preprocess/command_syntax.py) |
| Fit vocabulary và thống kê | [build_vocab.py](../code/preprocess/build_vocab.py), [vocab metadata](../code/output/host_ml_seed02/vocab_metadata.json) |
| Encoding và tính toàn vẹn | [build_model_input.py](../code/preprocess/build_model_input.py), [host_shards.py](../code/preprocess/host_shards.py), [shard manifest](../code/output/host_ml_seed02/model_input/manifest.json) |
| Runtime dùng chung | [host_training_runtime.py](../code/kaggle/host_training_runtime.py) |
| Kết quả RF | [rf_metrics.json](../code/output/host_ml_seed02/kaggle_ouput/rf_kaggle_results/results/rf_metrics.json) |
| Kết quả XGBoost | [xgb_metrics.json](../code/output/host_ml_seed02/kaggle_ouput/xgb_kaggle_results/results/xgb_metrics.json) |
| Kết quả LightGBM | [lgbm_metrics.json](../code/output/host_ml_seed02/kaggle_ouput/lgbm_kaggle_results/results/lgbm_metrics.json) |
| Nền tảng thiết kế tokenizer | [Phân tích tokenization](host_ml_tokenization_research.md) |
| Nhánh provenance riêng | [Provenance README](../code/provenace_graph/README.md) |
| Thiết kế hệ thống mục tiêu | [High-level architecture](image/host_apt_high_level/README.md), [ontology](image/host_multisource_ontology_v2/README.md) |
| Thực tế DL của Lam | [Audit Lam](lam_dl_review_2026-10-14/README.md) |

Các liên kết source giải thích cơ chế hiện hành; metadata/checkpoint đã xuất bản mới là căn cứ cho cấu hình và danh tính của run. Nếu source thay đổi sau ngày tạo artifact, cần đối chiếu hash trước khi tuyên bố tái lập bit-for-bit.
