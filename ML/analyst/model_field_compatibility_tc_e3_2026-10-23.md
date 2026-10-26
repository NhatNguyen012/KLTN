Đối chiếu feature OpTC với THEIA/FIVEDIRECTIONS E3 — 2026-10-23

Kết luận: bản CSV/Parquet đang có chưa đủ để khẳng định có thể học tiếp nguyên trạng cả ba checkpoint. THEIA vẫn là ứng viên Linux đáng kiểm tra raw; FIVEDIRECTIONS chưa nên được chốt làm dataset thứ hai. Thiếu dữ liệu trong bản xuất và khác biệt biểu diễn Windows–Linux là hai vấn đề riêng, đều phải giải quyết.

**Phạm vi và bằng chứng**

- Đã đọc các trao đổi Temp/1.md–11.md trong lần đánh giá trước; báo cáo này cập nhật giả định về DL bằng code notebook mới.
- Đã đọc hai PDF người dùng chỉ định, mã xuất CSV/Parquet THESEUS, tokenizer Host ML, mã xây graph và mã nhúng trong hai notebook mới. Không thực thi notebook hoặc payload telemetry.
- Đã quét toàn bộ process và netflow CSV của hai dataset. Với file/event CSV chỉ kiểm tra header; không quét toàn bộ event table để xác nhận graph coverage.
- Đã đọc schema và số dòng từ footer cả tám file Parquet bằng Thrift Compact metadata. Các cột trùng CSV; chưa so sánh từng giá trị CSV–Parquet.
- Đã đối chiếu process UUID với nhãn REAPr và thử ánh xạ basename/path vào preprocess spec DL hiện có. Đây là thống kê process node, không phải thống kê flow hoặc sample huấn luyện.
- Trong hai thư mục dataset được kiểm tra, không có bản raw CDM. Archive THEIA là `DARPA-TC-E3-CSV.zip`, không phải raw. Vì vậy chưa có phép đo trực tiếp độ đầy đủ field trong raw của hai dataset.
- Số đo và SHA-256 nguồn được lưu ở `model_field_compatibility_tc_e3_2026-10-23.evidence.json` cạnh báo cáo này.

**1. Input thực sự của các mô hình**

Hai notebook:

- `DL/04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb`
- `DL/04_notebooks/07d_Mixed_Type_Kaggle_v2_final.ipynb`

Cell 7 của cả hai giữ:

```python
KEEP_CAT = ['app_family', 'proto', 'resp_port_class', 'image_dir_class']
spec['active_numerical_features'] = []
# feature_subset: drop_numeric=True, zero_binary=True
# delta_t_log1p vẫn giữ
```

Đã kiểm tra cả dataset loader và đầu vào forward: numerical bị cắt hết, binary được zero hóa, delta vẫn đi vào mô hình. Như vậy notebook bỏ các thống kê Bro nhưng CHƯA bỏ hết thông tin Layer 3/4: protocol và response-port class vẫn là feature. BiLSTM hiện không đọc command line, parent image hay chuỗi PROCESS/FILE thay cho flow.

Pipeline `DL/01_code/s4_shards.py` vẫn tạo sample theo host/cửa sổ 15 phút, sắp flow theo `(ts, uid)`, chia chunk tối đa 512 flow. `delta_t_log1p` là log1p khoảng cách thời gian giữa các flow trong chunk. Sample dương khi có ít nhất một flow dương. Loại bỏ cột không làm thay đổi đơn vị sample này.

Host LightGBM: `ML/code/output/host_ml_seed02/vocab_metadata.json` ghi policy `v5_canonical_office_registry`, cùng allowlist field với tokenizer hiện tại. Hash code hiện tại khác hash lịch sử trong metadata; không coi đó là bằng chứng checkpoint được xây bằng byte-identical source hiện tại. Allowlist đã được đối chiếu trực tiếp với metadata frozen:

| Loại event | Field thuộc tính được dùng |
|---|---|
| PROCESS | image_path, parent_image_path, command_line |
| FILE | image_path, file_path, new_path |
| MODULE | image_path, module_path |
| REGISTRY | image_path, key / registry_key / registry_path |
| TASK | image_path, path |
| SHELL | image_path, payload |
| THREAD | image_path |
| USER_SESSION, SERVICE, HOST | không có property riêng trong allowlist |

Ngoài ra có action, object và principal được chuẩn hóa. FLOW và field mạng bị loại khỏi nhánh LightGBM này. Không phải mỗi event phải có tất cả field trong bảng; cần so sánh theo loại event. Linux không có Windows Registry không phải lỗi mất dữ liệu. Tuy nhiên nguồn chỉ có vài nhóm event sẽ không kích hoạt được nhiều feature mà mô hình đã học.

GraphSAGE hai hop đang dùng Process/Host, bốn relation `creates`, `hosts`, `communicates`, `communicates_reverse`, với 40 node attributes. Mã thực tế ở `ML/code/provenace_graph/model/ego.py` và `preprocess/graph.py` cần:

- hostname, actorID, objectID, timestamp, object/action để xác định node, event và cutoff;
- PROCESS CREATE để tạo cạnh cha–con; image_path, parent_image_path, command_line để tạo role/location/launch traits;
- FLOW direction, src_ip, dest_ip, dest_port để tạo host binding, giao tiếp, network service/scope.

GraphSAGE này vẫn có đặc trưng mạng. Chỉ dùng evidence trước cutoff, không dùng nhãn cha/ông hoặc metadata xuất hiện trong tương lai. Một graph Process/File/Netflow của THESEUS không phải input tương đương graph Process/Host này.

**2. Raw có khả năng chứa gì, bản xuất mất gì?**

Paper CDM mô tả mô hình chung; đã kiểm tra thêm [CDM18 của BBN](https://raw.githubusercontent.com/raytheonbbn/tc-ta3-serialization-schema/master/avro/CDM18.avdl), đúng phiên bản E3 theo [DARPA README](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md).

Schema có Subject metadata/parent, Host, Principal, Event, NetFlowObject và RegistryKeyObject. `cmdLine`, `parentSubject`, `ipProtocol` cho phép null. Subject không có field chuẩn `image_path`/`path`: executable path cần lấy từ properties hoặc sự kiện phù hợp. Khai báo schema không chứng minh giá trị được collector điền đầy đủ hoặc đúng.

| Thông tin cần | Nơi tìm trong CDM | Bản CSV/Parquet hiện có |
|---|---|---|
| Executable/image path | Subject properties; executable event và file/path liên quan | process.path, độ đầy đủ khác nhau rất lớn |
| Command line | Subject.cmdLine; properties đặc thù nguồn | process.cmd; fallback có thể chỉ là tên tiến trình |
| Parent identity + thời gian | Subject.parentSubject/type/startTimestampNanos; sự kiện tạo tiến trình | không có cột parent/start/type; có thể phục hồi một phần từ creation edges nếu chúng được giữ |
| Host identity | Subject/Event.hostId, Host | không có bảng/cột host |
| Principal | Subject.localPrincipal nối Principal | không có bảng/cột principal |
| Protocol | NetFlowObject.ipProtocol | không xuất |
| Endpoint | NetFlowObject local/remote address, port | bốn cột src/dst address/port |
| Event semantics/time | Event type, timestamp và các object/path liên quan | operation, timestamp_rec và một cặp đầu mút |
| Registry/path thay đổi | RegistryKeyObject; event path và object thứ hai | không có registry table, không có event path thứ hai |

Schema tham chiếu trên xác nhận các vị trí có thể tìm, không xác nhận coverage của raw THEIA/FIVEDIRECTIONS.

Kiểm tra trực tiếp `paper-general/code/NDSS/theseus-main/scripts/create_csv_files_e3.py`:

- Chỉ ghi process `(node_uuid, hash_id, path, cmd, index_id)`; không giữ host, principal, parentSubject, Subject.type và start time.
- Netflow chỉ ghi địa chỉ/cổng; không giữ ipProtocol.
- Event chỉ ghi hai đầu mút, operation, UUID và timestamp. Không giữ predicateObject2, path tại thời điểm event, parameters hoặc properties đầy đủ.
- Chỉ dựng các node process/file/netflow; các object ngoài ba nhóm không được bảo toàn theo schema gốc.
- Có lọc loại event và bỏ event không nối được vào node tables. Không thể tái tạo event đã bỏ chỉ bằng đổi schema CSV.
- Metadata process/path được gom qua toàn bộ lượt quét; bảng node không có thời điểm quan sát từng thuộc tính. Dùng giá trị này cho mọi event quá khứ có thể vi phạm cutoff của GraphSAGE.
- Script CSV đọc `event.process`, trong khi schema BBN CDM18 dùng `event.subject`; raw audit script đi kèm đã hỗ trợ cả hai. Adapter mới phải kiểm tra record thực tế, không chạy lại exporter nguyên xi và giả định mọi biến thể được xử lý đúng.

Hai bản script trong `paper-general/code/NDSS` và `DATASET/research/code_references/NDSS` có cùng SHA-256. Tuy nhiên chưa có manifest chứng minh các file CSV đang có được sinh bằng đúng phiên bản script này. Những cột bị thiếu được xác nhận trực tiếp từ dữ liệu; không quy mọi ô rỗng cho một nhánh code cụ thể.

**3. Số đo trên dữ liệu hiện có**

| Process CSV | THEIA | FIVEDIRECTIONS |
|---|---:|---:|
| Tổng process rows | 279.369 | 519.493 |
| path có giá trị | 278.363 (99,64%) | 0 |
| cmd có giá trị | 271.834 (97,30%) | 15.912 (3,06%) |
| UUID xuất hiện với nhãn attack khớp process | 125 | 26 |
| Trong số attack: path có giá trị | 125 | 0 |
| Trong số attack: cmd có giá trị | 125 | 4 |
| UUID nhãn contaminated khớp process | 1 | 13 |

`present` loại chuỗi rỗng, n/a, na, none, null. Có cmd không chứng minh có đầy đủ arguments. Số UUID là process duy nhất, không phải số campaign hoặc số sample độc lập. FIVEDIRECTIONS có 32 UUID được annotation: 26 xuất hiện với attack, 13 với contaminated, giao của hai tập là 7; cả 7 đều thiếu path/cmd. Không cộng hai cột nhãn như hai tập rời nhau, hoặc để dòng cuối ghi đè dòng trước. Cần giữ attack_chain và chính sách xử lý nhiều annotation cho cùng UUID. THEIA không có giao hai tập trong bản nhãn này.

Netflow CSV có 186.100 node THEIA và 123.279 node FIVEDIRECTIONS. remote/dst address có giá trị lần lượt 157.859 (84,82%) và 87.167 (70,71%). Bốn cột endpoint tồn tại không đồng nghĩa mọi endpoint hợp lệ: phép đo này chưa kiểm tra IP/cổng, socket type hoặc hướng kết nối.

Paper `How benchmarks and evaluation protocols shape conclusions in provenance-based intrusion detection.pdf`, phần V-B, trang in 9, cũng báo cáo command của FIVEDIRECTIONS chỉ có ở khoảng 3,1% process trong raw logs. Đây là bằng chứng tác giả báo cáo, không phải phép đo raw độc lập của lần audit này. Vì thế không hứa rằng tải raw sẽ làm command coverage trở nên đầy đủ. Các thống kê paper và bản local không hoàn toàn đồng nhất; ưu tiên số đo local cho quyết định trên bản đang có.

**4. Đối chiếu riêng năm feature DL**

| Feature | THEIA processed | FIVEDIRECTIONS processed | Việc còn thiếu |
|---|---|---|---|
| app_family | có path để lấy basename cho phần lớn process | không có path; cmd chỉ thưa | join đúng process phát sinh network event; xử lý vocabulary |
| image_dir_class | có path nhưng quy tắc Windows gom Linux về OTHER/BARE_NAME | MISSING toàn bộ nếu dùng process.path | thiết kế biểu diễn xuyên OS hoặc báo cáo suy giảm |
| proto | không có cột | không có cột | lấy ipProtocol từ raw nếu được điền; không đoán từ cổng |
| resp_port_class | có local/remote port | có local/remote port | xác định responder; remote không luôn là responder |
| delta_t_log1p | có event timestamp | có event timestamp | dựng đơn vị kết nối và chuỗi tương thích, không coi mỗi syscall là một Bro flow |

CSV đặt tên src/dst nhưng exporter lấy local/remote endpoint. Khi máy bị quan sát nhận kết nối, responder có thể là local. Không ánh xạ máy móc `dst_port -> resp_port_class`. CONNECT/ACCEPT, loại thao tác, identity và lifecycle phải được dùng để xác định vai trò; thiếu thì giữ unknown.

Probe theo `DL/02_artifacts/22_v2_pipeline/S3_preprocess/data/preprocess_spec.json` và quy tắc basename hiện tại:

- THEIA: 0/278.363 process có path khớp app_family vocabulary OpTC. Nếu dùng chính path này với vocab hiện có, các basename đó đều thành UNK. Chưa tính trọng số theo network flow; cũng chưa chứng minh file spec local chính là spec đóng gói với mọi checkpoint của bạn.
- THEIA image_dir_class: OTHER 271.859; BARE_NAME 6.504; MISSING 1.006.
- FIVEDIRECTIONS image_dir_class: MISSING 519.493.
- Các role/location rules của GraphSAGE cũng thiên về Windows; ví dụ `/bin/bash` không được nhận thành role shell và system location bởi rules hiện tại.

Như vậy đầy đủ field là điều kiện đầu vào, chưa đủ cho học tiếp có ý nghĩa. Adapter đổi tên cột không sửa được feature collision/OOV. Không nên thêm đuôi `.exe` giả cho binary Linux hoặc đưa process_name từ file nhãn vào feature để chữa thiếu path.

**5. Có cần làm lại raw từ đầu không?**

Nếu muốn giữ ý nghĩa input hiện tại của cả ba nhánh, cần quay lại raw hoặc tìm một bản xuất phong phú hơn. Riêng CSV/Parquet hiện tại không khôi phục chắc chắn protocol, host/principal, metadata có thời gian và các event đã bị lọc. Creation edges có thể cứu một phần lineage, nhưng chưa được kiểm toán đầy đủ.

Không cần đồng nhất việc này với làm lại toàn bộ THESEUS hay tự gán nhãn từ đầu:

1. Kiểm kê raw trước: coverage cmd/path/parent/host/protocol, UUID resolution, thời gian, creation edges, process gắn netflow. Tách attack/contaminated/unlabelled và các khoảng thời gian. Một vài record mẫu không đủ chứng minh toàn corpus.
2. Nếu đạt, xuất lớp dữ liệu trung gian giữ metadata và thời điểm quan sát, rồi dựng ba adapter riêng. Có thể phải quét toàn bộ raw để tìm đủ records; không cần xuất lại mọi graph/cache của tác giả.
3. Tái sử dụng REAPr qua raw UUID nếu cùng phiên bản/phạm vi dữ liệu. Giữ attack_chain, attack và contaminated, xử lý UUID có nhiều annotation theo chính sách được công bố. Dữ liệu CSV dùng hash ở đầu cạnh, phải nối qua node_uuid/hash_id; không nối hash trực tiếp với UUID nhãn.
4. Chốt nhãn theo đơn vị dự đoán: process label không tự động là event label hoặc flow/window label. Gán mọi event của process dương là một weak-label policy cần công bố, không phải nhãn event nguyên bản.
5. Đánh giá representation trước khi fine-tune. Muốn mở rộng categorical vocabulary DL phải giữ ID cũ và xử lý embedding mới; không fit lại và đánh số lại vocabulary rồi nạp checkpoint. Với LightGBM, mở rộng feature schema cần thiết kế riêng, không mặc định chỉ thêm cột rồi tiếp tục booster cũ. Nếu sửa nghĩa các feature/role/path cho Linux, cần một baseline OpTC được huấn luyện với cùng biểu diễn mới để so sánh công bằng.

Không yêu cầu cả ba mô hình phải đọc mọi field giống nhau hoặc mọi OS phải có đầy đủ loại event của Windows. Yêu cầu là từng nhánh còn tín hiệu đủ mạnh, input có nghĩa nhất quán, nhãn/split hợp lệ và thí nghiệm đo được học mới lẫn quên kiến thức OpTC.

Quyết định đề xuất: giữ THEIA ở trạng thái ứng viên Linux có điều kiện; chưa chọn FIVEDIRECTIONS làm dataset thứ hai cho cả ba checkpoint. Nếu raw FIVEDIRECTIONS không cải thiện được executable/command metadata ở các process liên quan, xử lý lại không giải quyết được nút thắt. Hiện chưa có hai dataset được chứng minh tương thích đầy đủ cho cả ba mô hình.

Không huấn luyện, thay checkpoint, đổi split/vocab frozen hoặc sửa dữ liệu nguồn trong lần đánh giá này.
