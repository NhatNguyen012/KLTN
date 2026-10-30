# OpTC → ATLASv2: field audit và kế hoạch incremental learning

Ngày: 2026-10-30. Trạng thái: **DRAFT — chờ người dùng review trước khi code/chạy thử**.
Đây là kế hoạch và kết quả đọc source, không phải kết quả thực nghiệm IL.

## 1. Phạm vi và bằng chứng

- Bài toán đề xuất: domain-incremental binary detection, giữ nhãn benign/malicious. Dataset mới không tự động đồng nghĩa class mới; chưa cần mở rộng output head.
- Hai nhánh độc lập: LightGBM event-level và BiLSTM sequence-level. Không so trực tiếp F1 của hai đơn vị đánh giá và không thêm GraphSAGE/fusion vào lần này.
- Workspace thực tế đã chuyển sang `ML/code/`, `DL/`; root `code/` và `MENU.md` không tồn tại, cũng không tìm thấy `MENU.md` dưới ML. Dùng bảng vai trò trong `ML/code/README.md` để đối chiếu, không tạo lại pipeline cũ.
- Hướng dẫn phiên làm việc bảo vệ baseline seed02. README hiện mô tả `host_ml_parent_incoming_seed02`; coi đây là candidate checkpoint hiện có, không thay đổi designation hay artifact baseline nào. Bước P0 phải khóa chính xác bundle được dùng.
- Nguồn Host: `ML/code/preprocess/ecar_tokenizer.py`, `process_context_tracker.py`, `ML/code/README.md`.
- Nguồn DL: `DL/01_code/s1_join.py`, `s2_windows_split.py`, `s4_shards.py`, `DL/01_code/v2_common.py`; notebook cuối `DL/04_notebooks/06d_BiLSTM_Kaggle_v2_final.ipynb`, đặc biệt cells 7, 9.
- Đã đọc README ATLASv2, README ground truth REAPr và mẫu đầu một XML Security bên trong tar bằng streaming. **Chưa audit đầy đủ CBC/Sysmon, chưa thống kê coverage toàn corpus.**
- `IL/dataset_1-ATLASv2/` ban đầu trống. Không sửa nguồn dataset, paper, vocabulary/split/model OpTC.

## 2. Fields LightGBM thực sự sử dụng

LightGBM nhận vector sparse binary: mỗi token là một cột, không nhận trực tiếp chuỗi field và không có embedding.

| Nhóm / object | Raw fields được tokenizer đọc | Biểu diễn |
|---|---|---|
| Chung | `action`, `object`, `principal` | action/object, quan hệ action→object, bucket tài khoản; không lưu tên user literal |
| PROCESS | `properties.image_path`, `parent_image_path`, `command_line` | tên executable, nhóm đường dẫn, quan hệ cha-con, cấu trúc lệnh/switch/operand/AST an toàn |
| FILE | `properties.image_path`, `file_path`, `new_path` | ngữ nghĩa đường dẫn, file và rename |
| MODULE | `properties.image_path`, `module_path` | process/module và đường dẫn |
| REGISTRY | `properties.image_path`, `key`, `registry_key`, `registry_path` | root/category registry; không dùng nguyên văn key/value/data |
| TASK | `properties.image_path`, `path` | process/path |
| SHELL | `properties.image_path`, `payload` | payload có cấu trúc được tokenizer hỗ trợ; không thực thi |
| THREAD | `properties.image_path` | process/path |
| USER_SESSION, SERVICE, HOST | không có property allowlist | chỉ các nhóm chung phù hợp |

`FLOW` bị loại; property ngoài allowlist không tự thành feature. UUID/PID/IP/raw username không làm cột vocabulary.

Parent/incoming context còn đọc `hostname`, `timestamp`, `actorID`, `objectID`, `properties.tgt_pid_uuid` cùng metadata process. Chúng là **khóa nối và thời gian**, không phải raw categorical features. Features là snapshot process/parent, lineage, action history, status và age buckets. Incoming gồm `PROCESS OPEN` và `THREAD REMOTE_CREATE`, chỉ dùng bằng chứng sớm hơn query trên cùng host, không dùng nhãn tổ tiên.

Adapter phải giữ đúng semantics eCAR: trong PROCESS CREATE, actor là parent, object là child. Không gán Sysmon ProcessGuid vào actor của mọi loại event một cách máy móc. Không giả lập UUID từ PID đơn lẻ; nếu cần surrogate phải gắn host/session và thời điểm tạo process, ghi rõ độ tin cậy.

## 3. Fields BiLSTM cuối cùng thực sự sử dụng

| Feature active | Nguồn trong OpTC | Chuyển đổi |
|---|---|---|
| `app_family` | eCAR-Bro `properties.image_path` | basename lowercase; category ID → embedding |
| `image_dir_class` | cùng image_path | taxonomy đường dẫn trong preprocessing → embedding |
| `proto` | Bro conn `proto` | category ID → embedding |
| `resp_port_class` | Bro `id.resp_p` | port bucket theo preprocessing → embedding |
| `delta_t_log1p` | Bro `ts` | ln(1 + max(0, delta giây)); reset 0 ở đầu mỗi chunk |

Thứ tự categorical thực tế: `app_family`, `proto`, `resp_port_class`, `image_dir_class`.
`properties.bro_uid`/Bro `uid` phục vụ join; hostname/time phục vụ grouping/sorting; label dùng làm target.

- Group hiện tại là **(hostname, cửa sổ UTC cố định 900 giây)**, không phải mỗi process một chuỗi. Sort `(ts, uid)`, chia chunk tối đa 512 flow; chunk positive khi có ít nhất một flow positive.
- Không dùng `principal_class`, `service`, `conn_state`, 7 numeric Bro. `x_num` và missing numeric có 0 cột; `x_bin` vẫn có một cột hằng 0 để giữ kiến trúc. Các edge graph không được forward của BiLSTM dùng.
- Spec S3 chứa nhiều feature hơn notebook cuối; không lấy toàn bộ `active` trong spec cũ làm input model.
- Network metadata vẫn có nguồn Bro trong training OpTC. Việc OS telemetry có thể cung cấp protocol/port không biến nguồn training lịch sử thành Sysmon.
- Model: embeddings → event encoder → BiLSTM → classifier binary. Mặc định source có 1 LSTM layer; phải xác minh config checkpoint. BiLSTM đọc hai chiều trong chunk: đánh giá theo chunk hoàn tất, không tuyên bố causal alert cho từng event ở đầu chunk.

## 4. Mapping ATLASv2 cần xác minh trước khi huấn luyện

| Canonical field | Candidate Sysmon | Candidate CBC | Điều kiện |
|---|---|---|---|
| image/command/parent | Image, CommandLine, ParentImage, ParentProcessGuid | process_path, process_cmdline, parent_path và process/parent GUID | xác minh field thực, loại event và hướng parent/child |
| account | User | process_username | bucket semantic, không đưa literal account vào vocab |
| time/host | UtcTime hoặc System.TimeCreated, Computer | device_timestamp, device_name | xác minh đơn vị/timezone, timestamp event vs timestamp thu thập |
| file/module/registry | TargetFilename, ImageLoaded, TargetObject | filemod/modload/regmod fields | map theo event type, không gán mọi registry event thành cùng action |
| incoming process/thread | SourceProcessGUID, TargetProcessGUID ở ProcessAccess/CreateRemoteThread | tùy event schema | chỉ map khi semantics được chứng minh; missing không đồng nghĩa không xảy ra |
| network cho DL | Image, Protocol, DestinationPort, Initiated, UtcTime | process path, netconn protocol/port/direction/time | xác minh endpoint responder khi inbound; không coi remote port luôn là resp port |

Đây là candidate mapping, chưa phải schema đã đo. P1 sẽ tạo bảng observed/missing/unsupported và ví dụ có provenance cho từng trường.
Ưu tiên một nguồn canonical cho mỗi loại event; không nối thẳng CBC+Sysmon làm tăng gấp đôi số sự kiện. Audit duplicate, coverage, khả năng join nhãn trước khi chọn primary source.

Nhãn: thư mục `attack/` chứa cả benign activity, tuyệt đối không gán toàn bộ là 1. Dùng REAPr làm nguồn ground truth có version; kiểm tra grain process/node/edge và chuyển nhãn sang event/sequence bằng policy công khai. Không gán mọi event chưa match thành benign; có nhãn unknown/loại khỏi supervised metrics nếu coverage chưa đủ.
README REAPr cảnh báo remote IP bị implicate nhầm trong một số multi-host attacks: không propagate nhãn theo IP một cách mù quáng.

## 5. Áp dụng gợi ý freeze/unfreeze của thầy

### 5.1 BiLSTM: mở rộng hàng embedding, không tự thêm layer

1. Khóa ID/category cũ và reserved `<UNK>=0`, `<MISSING>=1`. Chỉ append giá trị mới tìm thấy trong TRAIN của round hiện tại, thứ tự deterministic; không fit bằng VAL/TEST hay round tương lai.
2. Resize số hàng embedding; giữ nguyên embedding width từ checkpoint. Source hiện tính width theo cardinality: không gọi lại công thức cho width cũ sau khi vocab lớn lên vì sẽ làm đổi event_encoder input shape.
3. Stage A: freeze hàng embedding cũ + event_encoder + LSTM; train hàng mới và classifier trên new TRAIN + replay.
4. Stage B: mở event_encoder và LSTM với learning rate nhỏ hơn head; vẫn khóa hàng embedding cũ.
5. Stage C (ablation có điều kiện): mở hàng embedding cũ với LR nhỏ; giữ replay, tùy chọn distillation. Quyết định chuyển stage bằng VAL cũ+mới và giới hạn forgetting, không nhìn TEST. Với 1 LSTM layer không thể mở nhiều tầng LSTM tuần tự; dùng thứ tự module như trên.
6. Không cần thêm hidden layer hay thêm output class chỉ vì có token/dataset mới.

Freeze hàng phải chống cả optimizer momentum và AdamW weight decay; mask gradient đơn thuần chưa đủ. Dùng tách parameter hoặc restore hàng/momentum đúng cách và test bitwise sau optimizer step. Checkpoint lưu stage, vocab IDs, dims, optimizer/scheduler, RNG, replay manifest và source hashes.

### 5.2 LightGBM: tách khỏi neural fine-tuning

- Freeze vocab = giữ column index và semantic contract. Không có embedding weight/token layer để freeze/unfreeze.
- Baseline IL thứ nhất: giữ không gian feature cũ, tiếp tục boosting bằng `init_model` trên new TRAIN + replay. Tree cũ giữ nguyên, tree mới học phần bổ sung. Phải kiểm tra runtime notebook hiện tại chọn checkpoint/iteration nào.
- `Booster.refit` cập nhật leaf outputs theo decay rate, không tự học split mới trên token mới; chỉ là ablation tùy chọn, không gọi là unfreeze neural layer.
- **Không giả định append cột rồi truyền thẳng checkpoint cũ vào init_model sẽ tương thích.** Cần compatibility test đúng LightGBM 4.6.0, feature order/count, save/reload và output equivalence.
- Đề xuất đường mở rộng an toàn để thí nghiệm: frozen base `f_old(x_old)` + residual booster `g(x_expanded)`, score cuối `sigmoid(f_old + g)`. Train g với raw margin base làm init_score; khi inference phải tính lại và cộng base (init_score không tự trở thành model inference). Cách ghép này là đề xuất engineering cần validate, không phải thuật toán đã được paper chứng minh trên ATLASv2.
- So sánh với refit/retrain trên new+replay; không sửa tay header model, không tắt shape checks để ép chạy. Có budget số cây/model size vì thêm tree mãi cũng làm tăng bộ nhớ.

## 6. Replay và protocol đánh giá

- Buffer OpTC chỉ lấy từ TRAIN theo frozen split từng nhánh; ML seed02 và DL window split seed1 là hai split khác nhau, không ép dùng chung membership.
- ML buffer chứa sparse features và semantic context snapshot đã tính causal; không dựng parent context từ các event replay rời rạc. Nếu representation thay đổi cần canonical record/context được version hóa để re-encode.
- DL buffer chứa nguyên sequence/chunk, length, mask, label; không sample flow rời rồi ghép thành sequence giả.
- Budget cố định theo byte và số event/token, ghi cả metadata/logits nếu dùng DER. Sampling phân tầng benign/malicious và domain, ưu tiên giữ positive hiếm; thử 1:1 new/replay trong minibatch trước, coi đây là hyperparameter cần VAL xác nhận. Báo cáo prior tự nhiên ở test.
- Sau round, chỉ cập nhật buffer từ TRAIN đã được phép sử dụng; reservoir/quota deterministic, không để dataset mới chiếm hết buffer.
- Kịch bản chính đề xuất: supervised domain adaptation. ATLAS TRAIN/VAL/TEST tách theo engagement/session/time blocks; giữ hai host cùng một multihost engagement trong cùng partition, không để chunk cùng window lọt sang split khác. Khóa manifest sau audit số nhóm/nhãn.
- ATLAS có attack chains rất trùng lặp theo chính REAPr. Group split/dedup chỉ giảm leakage, không chứng minh unseen-attack generalization. Báo cáo rõ familiar-pattern transfer; thêm protocol benign-only adaptation + replay OpTC, giữ attack ATLAS để test như một đối chứng riêng nếu đủ dữ liệu.
- Với nhiều round, sắp xếp theo thời gian/session thật khi khả dụng; epoch không phải incremental round. Sau mỗi round chỉ dùng train của các round đã đến. Một lần OpTC→ATLAS chỉ chứng minh một transition.
- Baselines: frozen OpTC; fine-tune/continue new-only; new+replay; new+replay+staged freeze; optional DER++; train-from-scratch new+buffer với cùng dữ liệu/budget để kiểm tra giá trị checkpoint. Joint full-data retraining là reference ngoài budget, không gọi cùng điều kiện IL.
- Đánh giá từng domain bằng PR-AUC/AP (nêu implementation), precision/recall/F1, FPR, confusion matrix, theo scenario và coverage. Giữ test cố định qua rounds, không dùng test chọn lịch mở layer/threshold.
- Báo cáo cả ngưỡng baseline cố định và ngưỡng chọn trên VAL cũ+mới. Forgetting: max kết quả domain cũ ở các round trước trừ kết quả hiện tại; BWT từ evaluation matrix. Hiệu năng sau adaptation không tự gọi là FWT: FWT cần đo trước khi học domain mới và reference rõ ràng.
- Chạy nhiều seed (dự kiến 3) cho sampling/training khi chạy chính thức; không thay frozen OpTC split. CI/bootstrap theo session/window phù hợp, không coi các event cùng chuỗi độc lập.

## 7. Các bước sau review và điều kiện nghiệm thu

| Bước | Công việc / artifact dự kiến | Điều kiện qua bước |
|---|---|---|
| P0 | inventory bundle; `baseline_manifest.json`, hash models/vocabs/spec/splits | chọn đúng LightGBM checkpoint bằng latest/metrics; có BiLSTM weights+config/category maps; inference baseline tái lập |
| P1 | stream inventory tar, bounded schema audit CBC/Sysmon/Security/ground truth; `field_mapping.json`, `coverage_report.json` | xác nhận field thực, label granularity, timestamp/direction, source primary; thống kê unsupported/unknown |
| P2 | adapter canonical và split/session manifest, audit duplicates | dataset read-only; deterministic; no split/window overlap; không gán attack-folder label |
| P3 | append-only vocab, replay builder, compatibility tests | IDs cũ bất biến; train-only; replay không chứa val/test; context causal |
| P4 | BiLSTM staged trainer và LightGBM fixed-schema/residual variants | reload đúng; frozen rows/trees đúng; expanded embedding giữ dims; residual inference cộng base |
| P5 | smoke test local trên fixture + subset có quota; ghi lỗi và sửa rồi chạy lại test liên quan | parser malformed cases, PID reuse, inbound port, ordering, label join, resume, no-write boundary đều qua; metrics không dùng để kết luận khoa học |
| P6 | package Kaggle, notebook/config/manifest/evaluation reports | training đầy đủ trên Kaggle; không launch full local training; ghi chi phí, forgetting, model size và giới hạn |

Source dự kiến dưới `IL/dataset_1-ATLASv2/{preprocess,model,test,notebook,docs}/`; output dưới `IL/dataset_1-ATLASv2/output/`. Mọi writer phải resolve path và reject dataset roots (bao gồm `DATASET/` và symlink trỏ vào đó). Atomic publish/resume và hash config/source/tokenizer. Không giải nén 160 GB vào dataset; ưu tiên streaming tar, chỉ staging có quota ngoài dataset nếu cần.

Các blocker đã xác định: chưa tìm thấy `.pt`/`.pth` dưới DL trong lần kiểm tra này; chưa xác nhận đầy đủ category maps/config của bundle checkpoint. Source có đường dẫn Windows hardcoded và notebook phụ thuộc package runtime; cần adapter/package riêng sau review. Hai model-slot LightGBM có sẵn, metrics trỏ slot-1, nhưng P0 vẫn phải đối chiếu latest và hash.

## 8. Paper nên đọc và sử dụng thế nào

Ưu tiên paper có nguồn xuất bản rõ. Không tự gán A*/Q1 khi chưa xác minh hệ thống xếp hạng, category và năm; venue dưới đây được đối chiếu trang proceedings/nguồn gốc. Rank của venue không thay thế tính phù hợp của protocol.

| Paper | Venue / nguồn | Vai trò |
|---|---|---|
| iCaRL (đã có local) | CVPR 2017 — https://openaccess.thecvf.com/content_cvpr_2017/html/Rebuffi_iCaRL_Incremental_Classifier_CVPR_2017_paper.html | exemplar memory và distillation; class-incremental, không bê nguyên nearest-mean classifier sang binary domain adaptation |
| End-to-End Incremental Learning (đã có local) | ECCV 2018 — https://openaccess.thecvf.com/content_ECCV_2018/html/Francisco_M._Castro_End-to-End_Incremental_Learning_ECCV_2018_paper.html | exemplar + distillation + balanced training; hỗ trợ ablation chống forgetting |
| Dark Experience for General Continual Learning (DER/DER++) | NeurIPS 2020 — https://proceedings.neurips.cc/paper/2020/hash/b704ea2c39778f07c617f6b7ce480e9e-Abstract.html | ưu tiên bổ sung: replay dữ liệu/logits; candidate baseline cho BiLSTM |
| Universal Language Model Fine-tuning for Text Classification | ACL 2018 — https://aclanthology.org/P18-1031/ | gradual unfreezing/discriminative fine-tuning, gần gợi ý của thầy; là transfer learning NLP, không tự chứng minh continual learning hay mở vocab telemetry |
| MalFSCIL (đã có local) | IEEE TIFS, Vol.20; PDF ghi online 12/2024, current version 03/2025 | related work security/few-shot class-incremental; khác event detection và domain-incremental đang làm |
| Adaptive Detection…Wazuh EDR Telemetry (đã có local) | IEEE Access 2025, DOI 10.1109/ACCESS.2025.3639270 — https://dspace.kmitl.ac.th/entities/publication/0388a646-4f53-41d2-96e6-5de365ed74a2 | related work APT/rehearsal; kiến trúc GNN, không thay bằng chứng cho LightGBM/BiLSTM |

ATLAS gốc: USENIX Security 2021, https://www.usenix.org/conference/usenixsecurity21/presentation/alsaheel . ATLASv2 là dataset description arXiv https://arxiv.org/abs/2401.01341 ; không gọi bản arXiv là paper hội nghị đã peer-review. Local README yêu cầu cite cả hai; ground-truth REAPr cần citation/version riêng khi P1 khóa labeling protocol.

API reference (không phải paper): LightGBM 4.6.0 `train(init_model=...)` https://lightgbm.readthedocs.io/en/v4.6.0/pythonapi/lightgbm.train.html và `Booster.refit` https://lightgbm.readthedocs.io/en/v4.6.0/pythonapi/lightgbm.Booster.html .

## 9. Nội dung cần review

Đề xuất duyệt: binary domain-incremental; BiLSTM staged unfreezing + replay là thí nghiệm chính; LightGBM continuation fixed schema và residual expanded schema là nhánh riêng; group/session split với giới hạn attack redundancy được công bố. Ngân sách replay/lịch LR cụ thể chốt sau P0–P1 theo kích thước dữ liệu và VAL, không chọn từ TEST.

Sau khi người dùng duyệt kế hoạch mới bắt đầu code → smoke test → sửa lỗi. Thiếu checkpoint BiLSTM không cản code adapter/test, nhưng phải có đúng checkpoint trước khi thực hiện fine-tuning thật.
