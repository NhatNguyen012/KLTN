Đối chiếu field OpTC → THEIA raw / ATLASv2 raw — 2026-10-24

Phạm vi: code và artifact hiện có trong workspace; không chứng nhận một checkpoint ngoài workspace hoặc notebook chưa đồng bộ. Chỉ đọc dataset. Không thay split, vocabulary, model hay nguồn raw. Kết quả ATLASv2 trong báo cáo này thay thế kết luận “chưa có telemetry” của báo cáo ngày 23/10: archive `atlasv2.tar.gz` đã được tải thêm.

Dataset mới không cần trùng tên cột với OpTC. Adapter phải tái tạo đúng ý nghĩa feature, quan hệ, thời gian và đơn vị sample. Một field bị thiếu có thể mã hóa missing nếu hợp đồng model cho phép, nhưng điều đó không có nghĩa nó cung cấp cùng tín hiệu cho incremental learning. Schema trong Figure 2 CDM là khả năng biểu diễn chung; field tùy chọn có thể null trong toàn bộ dữ liệu của collector.

**Số lượng field và feature**

| Model / thành phần | Field nguồn mà code đọc | Biểu diễn đưa vào model |
|---|---|---|
| LightGBM Host seed02 | 14 tên field: 3 top-level + 11 property keys; nếu gộp 3 alias registry thành một khái niệm thì 12 nhóm ngữ nghĩa | Sparse binary vector, vocabulary frozen có 9.048 token/column |
| Bộ dựng graph cho 2-hop GraphSAGE | 13 field: 6 top-level cho identity/time/type/relations + 7 properties | 40 thuộc tính/node và graph có 4 loại cạnh |
| BiLSTM `06d_BiLSTM_Kaggle_v2_final.ipynb` | 4 nguồn trực tiếp: image_path, Bro proto, Bro id.resp_p, Bro ts; thêm khóa host/flow để join và chia chuỗi | 5 kênh feature có thông tin: app_family, image_dir_class, proto, resp_port_class, delta_t_log1p |

Đây là ba cách đếm có vai trò khác nhau, không phải ba model đều nhận trực tiếp các cột raw. Không tính label vào feature. UUID/PID/host identity phục vụ join không được đưa thành vocabulary lexical. Các nhánh đọc property theo loại event; không cần 14 field LightGBM cùng có trên mỗi dòng. Số field trong allowlist không chứng minh mỗi field đều đóng góp feature có importance khác 0 trong booster.

Nguồn kiểm tra: `ML/code/preprocess/ecar_tokenizer.py`, `ML/code/output/host_ml_seed02/{vocab.json,vocab_metadata.json}`, `ML/code/provenace_graph/preprocess/graph.py`, `ML/code/provenace_graph/model/ego.py`, notebook BiLSTM và `DL/01_code/{s1_join.py,v2_common.py,s4_shards.py}`. Allowlist phù hợp metadata frozen; không đồng nhất hash code hiện tại với hash lịch sử xây artifact.

**LightGBM: toàn bộ 14 tên field**

Các tên THEIA dưới đây tính từ record bên trong `datum[com.bbn.tc.schema.avro.cdm18.<Type>]`. JSON Avro union cần unwrap, ví dụ `cmdLine.string` và `parentSubject[com.bbn.tc.schema.avro.cdm18.UUID]`.

| Field OpTC | THEIA raw | ATLASv2 raw CBC EDR | Giới hạn |
|---|---|---|---|
| object | Loại record/object nối từ Event.subject / predicateObject; Event.type bổ sung ngữ nghĩa | type: endpoint.event.procstart, filemod, moduleload, regmod… | Phải map ontology, không sao chép enum nguyên xi |
| action | Event.type | action, có thể chứa nhiều ACTION_* phân cách bằng `|` | CLONE/EXECUTE và procstart DISCOVERED không được đánh đồng với mọi PROCESS CREATE |
| principal | Subject.localPrincipal → Principal.uuid → userId | process_username, chọn đúng actor/target theo event | THEIA username null; UID Linux không phải username Windows |
| image_path | Subject.properties.map.path của process đúng vai trò | process_path; ở PROCESS CREATE lấy childproc_name cho child | Process tạo event và process bị tác động có thể khác nhau |
| parent_image_path | Subject.parentSubject → Subject.uuid → properties.map.path | parent_path cho parent của process_guid; ở procstart, parent của childproc_guid là process_guid với process_path | Không dùng parent_path của procstart làm trực tiếp parent-image của child: thường đó là ông của child |
| command_line | Subject.cmdLine.string | process_cmdline; ở procstart child dùng target_cmdline | Có giá trị không đồng nghĩa đầy đủ arguments; process_cmdline của procstart thuộc parent/actor |
| file_path | Event.predicateObject → FileObject.uuid → baseObject.properties.map.filename | filemod_name | THEIA filename đã thấy trực tiếp, chưa có census độ đầy đủ filename |
| new_path | Chưa xác nhận cặp old/new path tương đương; Event.predicateObjectPath và predicateObject2Path null toàn bộ | Không có field old/new thứ hai trong CBC đã audit; có ACTION_FILE_RENAME và một filemod_name | Không tự gán một path cho cả old và new; Security nguồn khác chưa được audit đầy đủ |
| module_path | Có thể nối file của EVENT_MMAP; không phải mọi mmap đều là module load | modload_name trong endpoint.event.moduleload | THEIA cần quy tắc ngữ nghĩa module có kiểm chứng |
| key | Không có RegistryKeyObject trong corpus THEIA đã quét | regmod_name | Registry là khái niệm Windows, không gán file Linux thành registry để lấp chỗ trống |
| registry_key | Như trên | regmod_name | Alias cùng nhóm registry |
| registry_path | Như trên | regmod_name | Alias cùng nhóm registry |
| path (TASK) | Chưa có đối ứng TASK path được kiểm chứng | Không có trường TASK tương đương trong CBC/Sysmon đã audit | Cron/systemd/task command không tự động bằng event TASK của OpTC |
| payload (SHELL) | Chưa có payload CommandInvocation/ParameterBinding tương đương | Không có shell payload tương đương trong CBC/Sysmon đã audit | scriptload có count/reputation, không phải nội dung script; command line không bằng shell instrumentation payload |

LightGBM hiện loại FLOW và field network. Port/protocol không phải điều kiện đầu vào của nhánh LightGBM này. Các field thiếu theo OS/event type không tự động làm dataset vô dụng, nhưng cần đo lượng token còn kích hoạt trong vocabulary OpTC và hiệu quả sau học tiếp.

**GraphSAGE: toàn bộ 13 field của bộ dựng graph**

| Field OpTC | THEIA raw | ATLASv2 CBC EDR |
|---|---|---|
| hostname | Event.hostId / Subject.hostId; dùng identity có namespace, vì Host.hostName rỗng | device_name, giữ thêm host/scenario namespace |
| actorID | Event.subject → Subject.uuid | process_guid |
| objectID | Event.predicateObject / predicateObject2, tùy ngữ nghĩa event | childproc_guid cho procstart; crossproc_guid cho target process khi thích hợp |
| timestamp | Event.timestampNanos, chuyển đơn vị chính xác | device_timestamp, không mặc định dùng thời điểm backend nhận log |
| object | Adapter suy từ loại object/event | Adapter từ type |
| action | Adapter từ Event.type | Adapter từ action |
| image_path | Subject.properties.map.path | process_path; childproc_name cho child CREATE |
| parent_image_path | Join parentSubject → Subject.properties.map.path | procstart dùng process_path cho parent của child; parent_path dùng cho parent của process_guid |
| command_line | Subject.cmdLine.string | target_cmdline cho child CREATE; process_cmdline cho actor |
| direction | Không có field tương đương trực tiếp; xác định từ ngữ nghĩa kết nối khi đủ chứng cứ | netconn_inbound (0.0/1.0 hoặc boolean), cần chuẩn hóa có kiểm tra |
| src_ip | NetFlowObject.localAddress / remoteAddress, chọn theo direction | local_ip / remote_ip, chọn theo direction |
| dest_ip | NetFlowObject.remoteAddress / localAddress, chọn theo direction | remote_ip / local_ip, chọn theo direction |
| dest_port | NetFlowObject.remotePort / localPort, chọn theo direction | remote_port / local_port, chọn theo direction |

40 thuộc tính gồm 6 node/status flags + 34 fact categories. Cạnh: creates, hosts, communicates, communicates_reverse. Đây là graph Host/Process; một graph Process/File/NetFlow xuất sẵn không thay thế trực tiếp được. Model này không đọc ipProtocol. THEIA thiếu protocol không chặn trực tiếp GraphSAGE, nhưng thiếu hướng/lifecycle hoặc host quan sát sẽ ảnh hưởng communication edges.

Cần ánh xạ lifecycle một cách nhân quả: parentSubject là quan hệ metadata, không được giả một PROCESS CREATE ở mọi EXECUTE. ATLAS procstart có cả ACTION_CREATE_PROCESS và ACTION_PROCESS_DISCOVERED; record discovered chỉ cho biết quan sát tại thời điểm đó, không chứng minh thời điểm sinh tiến trình. Giữ cutoff, loại sentinel/cycle và không dùng metadata thu được tương lai. THEIA chỉ có một host được quan sát, nên không đánh giá được đầy đủ nhánh liên lạc giữa nhiều host có instrumentation như OpTC/ATLAS.

**BiLSTM: 5 feature thực tế và tên nguồn**

| Feature BiLSTM | OpTC | THEIA raw | ATLASv2 CBC EDR |
|---|---|---|---|
| app_family | basename chuẩn hóa từ eCAR-Bro properties.image_path | basename của Subject.properties.map.path sau join đúng network actor | basename của process_path trên netconn |
| image_dir_class | phân loại image_path | phân loại Subject.properties.map.path; quy tắc hiện tại thiên Windows | phân loại process_path |
| proto | Bro proto | NetFlowObject.ipProtocol có trong schema nhưng null toàn bộ raw đã quét | netconn_protocol, ví dụ PROTO_TCP/PROTO_UDP, cần map tcp/udp |
| resp_port_class | Bro id.resp_p → resp_p → port_class | localPort hoặc remotePort sau xác định responder | local_port nếu inbound, remote_port nếu outbound, chỉ áp dụng khi ngữ nghĩa kết nối đã được kiểm tra |
| delta_t_log1p | ln(1 + chênh lệch Bro ts trong chunk) | Event.timestampNanos sau dựng đơn vị connection/flow tương thích | device_timestamp sau xử lý lifecycle/trùng lặp connection |

Notebook đã bỏ service, conn_state, principal_class, numeric thống kê Bro và zero hóa binary has_missed_bytes. Nó vẫn giữ proto và resp_port_class, vì vậy chưa bỏ toàn bộ Layer 3/4. BiLSTM hiện không dùng command_line, parent_image_path, principal hoặc chuỗi PROCESS/FILE như một số tài liệu kiến trúc đề xuất. Host/UID dùng grouping/join; IP/direction có thể vẫn cần cho adapter, dù không là kênh model trực tiếp.

Không coi mỗi syscall READ/WRITE/SEND/RECV của THEIA là một Zeek connection; không coi LISTEN/CREATE/ESTABLISHED của CBC là ba connection độc lập. netconn_community_id hoặc tuple không đủ chứng minh một connection duy nhất vĩnh viễn; cần identity, thời gian và lifecycle. Chỉ sau bước đó mới dựng cửa sổ host 15 phút, thứ tự thời gian, chunk tối đa 512 và delta như OpTC.

**Bằng chứng THEIA đã có**

Tái sử dụng census ngày 23/10: toàn bộ 4 JSON tar.gz, 25 member, 113.293.343 record, 0 lỗi JSON. 279.369 Subject UUID và 186.100 NetFlow UUID (unique metadata theo record cuối trong thứ tự archive, không phải temporal join). Subject có sentinel và process hệ thống nên không diễn giải mọi UUID là một execution bình thường.

- Path: 278.363/279.369 = 99,64%; cmdLine hữu ích theo tiêu chí presence của audit: 271.834/279.369 = 97,30%.
- Parent không phải UUID 0, nối được: 279.211/279.369 = 99,94%. Chưa chứng minh toàn bộ ancestry 2-hop hợp lệ theo thời gian.
- ipProtocol: 0/186.100 unique flow có giá trị; null trên cả 245.107 NetFlowObject records.
- Hai đầu mút là địa chỉ IP parse được: 156.944/186.100 = 84,33%; có LOCAL/NA/port 0.
- Principal.userId có dữ liệu, username null toàn bộ; một Host UUID, hostName rỗng.
- Event.subject mới là actor reference; Event.process không có. predicateObjectPath và predicateObject2Path null toàn bộ. Không dùng exporter đọc nhầm Event.process.
- Có 205 EVENT_SHM timestamp bất thường ở archive -3; phải điều tra/cách ly trước temporal split.
- REAPr 125 attack UUID + 1 contaminated UUID đều nối được raw Subject; không phải xác nhận mọi event của process đó là malicious.
- Probe trước đây: 0/278.363 path THEIA khớp basename vocabulary app_family của preprocess spec OpTC local. Đây là thống kê process, không phải flow-weighted hay chứng nhận checkpoint ngoài workspace. Phần lớn image_dir_class thành OTHER; quy tắc GraphSAGE cũng thiên Windows.

Raw THEIA không sửa được protocol null và không tự sửa vocabulary mismatch. Bản CSV đã giữ được độ đầy đủ path/cmd tương đương raw; lợi ích rõ của raw là parent/host/principal/time/object metadata mà CSV giản lược đã bỏ.

**Kết luận sử dụng**

ATLASv2 là nguồn Windows phù hợp hơn về field đối với cả ba nhánh; THEIA đáp ứng Linux và có nền tảng host/process khá tốt. Tuy nhiên cả hai cần adapter và kiểm tra nhãn theo đơn vị dự đoán. THEIA chưa feature-complete cho BiLSTM hiện tại vì thiếu protocol; chỉ encode missing là một thí nghiệm thiếu modality/feature, không phải đã khôi phục dữ liệu.

Nếu muốn một hợp đồng feature chung xuyên OS, thiết kế biểu diễn Linux/Windows trước, tạo baseline OpTC tương ứng rồi mới so sánh các bước học tiếp. Nếu giữ checkpoint hiện tại, giữ ý nghĩa/chỉ số feature cũ, khai báo missing/OOV rõ và đo cả hiệu quả dataset mới lẫn độ quên OpTC. Đổi tên cột hoặc bổ sung cột vào tensor/LightGBM không tự bảo đảm checkpoint tương thích. Không lấy tên process từ ground truth để lấp thiếu feature; không dùng vendor alert/reputation làm chứng cứ đầu vào thay telemetry đã chọn.

Ngữ nghĩa CBC được đối chiếu thêm với [Endpoint Event Schema 1.0.0 của Carbon Black](https://developer.carbonblack.com/reference/carbon-black-cloud/data-forwarder/schema/deprecated/endpoint.event-1.0.0/): childproc/target_cmdline mô tả child, netconn_inbound xác định hướng so với endpoint. Các số đo coverage bên dưới lấy từ archive local, không suy từ tài liệu API. Với ACTION_PROCESS_DISCOVERED, process có thể là OS/system thay vì cha thực; không dựng cạnh cha–con thực tế chỉ từ việc type là procstart.


**Census ATLASv2 raw hoàn tất**

- Archive: 12,208,351,555 bytes nén; 171,697,187,381 bytes tổng member. Không giải nén ra dataset root.
- Đã parse toàn bộ 18 file CBC EDR (16 attack + 2 benign), 1,857,763 record; 26 file Sysmon XML, 329,316 event; 0 lỗi parse.
- Các stream Security/NGAV/Firefox/DNS chỉ được đi qua để đọc archive; chưa kiểm toán field đầy đủ. Vì vậy “không có trong CBC/Sysmon” không có nghĩa chứng minh thiếu trong mọi nguồn ATLASv2.
- Presence ở đây loại null/chuỗi rỗng/list rỗng/dict rỗng, vẫn tính số 0 và false; chưa xác nhận mọi path/command/timestamp/endpoint đều hợp lệ. Không so sánh trực tiếp với tiêu chí bỏ N/A của THEIA như một thước đo chất lượng.

| CBC event type | Records | process_path có giá trị | process_cmdline có giá trị | process_username có giá trị |
|---|---:|---:|---:|---:|
| endpoint.event.crossproc | 11,804 | 11,804 | 11,804 | 11,804 |
| endpoint.event.filemod | 575,134 | 575,134 | 575,114 | 575,134 |
| endpoint.event.moduleload | 738,776 | 738,776 | 738,760 | 738,776 |
| endpoint.event.netconn | 29,744 | 29,744 | 29,729 | 29,744 |
| endpoint.event.procend | 65,896 | 65,896 | 65,896 | 65,896 |
| endpoint.event.procstart | 6,621 | 6,621 | 6,592 | 6,621 |
| endpoint.event.regmod | 402,658 | 402,658 | 401,526 | 402,658 |
| endpoint.event.scriptload | 27,130 | 27,130 | 27,130 | 27,130 |

| Field trên netconn | Present / tổng |
|---|---:|
| process_guid | 29,744 / 29,744 |
| process_path | 29,744 / 29,744 |
| device_name | 29,744 / 29,744 |
| device_timestamp | 29,744 / 29,744 |
| local_ip | 29,744 / 29,744 |
| local_port | 29,744 / 29,744 |
| remote_ip | 29,565 / 29,744 |
| remote_port | 29,744 / 29,744 |
| netconn_protocol | 29,744 / 29,744 |
| netconn_inbound | 29,744 / 29,744 |
| netconn_community_id | 28,412 / 29,744 |

Protocol values: {"PROTO_TCP": 28557, "PROTO_UDP": 1187}.
Network action values: {"ACTION_CONNECTION_CREATE": 28035, "ACTION_CONNECTION_ESTABLISHED": 1530, "ACTION_CONNECTION_LISTEN": 179}.
Không gọi số record netconn này là số connection/session duy nhất; cần xử lý LISTEN, CREATE/ESTABLISHED, lặp record và giới hạn thời gian.

Trên 6,621 procstart: process_guid=6,621, process_path=6,621, childproc_guid=6,621, childproc_name=6,621, target_cmdline=6,621.
Procstart action values: {"ACTION_CREATE_PROCESS": 5339, "ACTION_CREATE_PROCESS | ACTION_CREATE_PROCESS_EFFECTIVE": 56, "ACTION_PROCESS_DISCOVERED": 1226}.

Sysmon event IDs: {"5": 164509, "1": 164796, "4": 11}. Có Image/CommandLine/ParentImage/ParentCommandLine/ProcessGuid/ParentProcessGuid/User/UtcTime/Computer trên process-create; không mặc định bản cấu hình Sysmon này đã ghi NetworkConnect Event ID 3.

REAPr: 191/191 process UUID nối được vào process_guid hoặc childproc_guid trong đúng host/scenario của 16 file CBC attack. Đây là kiểm tra identity, chưa phải chứng nhận 191 process độc lập hoặc mỗi event của process là malicious. Gán nhãn process → event/flow/window cần chính sách riêng.

Evidence gồm census từng file/type, key presence, ví dụ raw, hash nguồn model, kiểm tra label theo scenario và source audit script: `optc_theia_atlasv2_field_mapping_2026-10-24.evidence.json`.
