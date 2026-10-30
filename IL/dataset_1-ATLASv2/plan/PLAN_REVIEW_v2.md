# OpTC → ATLASv2 — PLAN REVIEW v2

Ngày 2026-10-30. **DRAFT v2 — chỉ cập nhật kế hoạch, chưa code, chưa chạy thực nghiệm/training.** Giữ nguyên `PLAN_REVIEW.md`. Các test, audit corpus, inference, bootstrap và training dưới đây là công việc tương lai, không phải kết quả đã chạy.

## 1. Phạm vi, bằng chứng mới và thứ tự thực hiện

Binary domain-incremental detection, hai nhánh LightGBM event-level và BiLSTM chunk-level. Làm LightGBM trước. Không mở rộng output classes, thêm GraphSAGE/fusion hay đổi tokenizer baseline. Nguồn primary ATLAS là **Sysmon**, phù hợp hướng testbed Windows 11; chỉ dùng CBC nếu không đủ nhãn liên kết với Sysmon, với provenance và đánh giá riêng. ATLASv2 ghi Windows 7: cùng sensor family không bảo đảm schema/distribution tương đương Windows 11; không kiểm chứng Linux/auditd.

Đã đọc trực tiếp, không sửa:

- `ML/code/output/host_ml_parent_incoming_seed02/vocab.json`: JSON object phẳng **string token → integer column index**, **10.317 entries**, IDs liên tục `0..10316`. Ví dụ `ctx::parent::recent_action=PROCESS_OPEN: 0`, `ctx::actor::recent_action=PROCESS_OPEN: 1`. SHA-256 `2e4a6239dc94f46cc05f1aff0b955e28fc271a4d5384bfcc20921ab7fdf4c913`, khớp `vocabulary_sha256` trong metrics LightGBM. README ghi 20.412 token không khớp file hiện tại; lấy artifact đã khóa hash làm contract. Không thấy `host_ml_seed02/vocab.json`; seed02 index/split vẫn được bảo vệ.
- `ML/code/output/host_ml_parent_incoming_seed02/kaggle_output/lgbm_kaggle_results/results/{lgbm_metrics.json,model/latest.json}` cùng trỏ `model-slot-1.txt`, 300 rounds, LightGBM 4.6.0. P0 còn phải đối chiếu hash model thực và inference; chưa làm trong lượt cập nhật này.
- **Checkpoint BiLSTM đã được người dùng xác nhận đúng và chọn làm baseline:** `DL/05_models/bilstm_v2_subsetB/best_model.pt`, SHA-256 `1304901f46c4a559b47f1e6892fe8f558f92f19e0b77755add6dcb440755da77`. Bundle có config/metrics/threshold/predictions/history; đường dẫn `v2_final/bilstm_v2` của lần kiểm tra trước không còn là bundle hiện tại.
- Đã đọc `bilstm_v2_subsetB/config.json`: **4 categorical + 0 numeric**, đúng thứ tự `[app_family, proto, resp_port_class, image_dir_class]`, cardinalities `[61,4,11,10]`, seed42, event_dim=64, hidden_dim=64, 1 LSTM layer, 78.698 trainable parameters. Config khớp feature subset B của notebook 06d. Preprocess fingerprint: `287b07a57dd1b1181249a0169f7882ab4bb04d854792201d21b3c8d451dc2617`. Đã kiểm tra file/hash/JSON metadata, **chưa deserialize tensor hoặc tái chạy inference**; các kiểm tra đó vẫn thuộc P0.
- Metrics subsetB ghi VAL 83 positive, TEST 82 positive; **threshold=0.99560546875**, không phải 1.0. VAL AP=1.0; TEST AP=0.9888476309163509, F1=0.9876543209876543 (TP80/FN2/FP0/TN34331), best_epoch=2. Đây là số đọc từ artifact, chưa tái đo. T=1.0 là thông tin bundle trước, không dùng để mô tả checkpoint hiện tại. Báo cáo lịch sử `DL/02_artifacts/22_v2_pipeline/S7_results/diagnostics.json` ghi luật powershell F1=0.9939; cần đối chiếu sample IDs trước khi so trực tiếp với subsetB. Split DL hiện hữu không host-disjoint.
- Đã đọc bảng vai trò `ML/code/README.md`; không có root `MENU.md` hoặc MENU dưới ML. Không thay baseline, README hay code để chữa tài liệu trong lượt này.
- Chưa audit corpus ATLAS: EID 3/8/10, parent GUID, label coverage, positive engagement groups, UNK-rate, delta time, eviction đều **chưa audit**.

### P0: làm rõ undersampling (B.12)

`vocab_metadata.json` ghi full TRAIN benign=6.046.892, malicious=201.551, tổng **6.248.443**. `lgbm_metrics.json` ghi sampled rows=6.248.110, positives=201.551 → sampled negatives=**6.046.559**, tức bỏ **333 negatives**, giữ toàn bộ positives theo metadata.

`host_training_runtime.py::sample_plan` dùng Bernoulli negative sampling với `keep_p=min(1, neg_per_pos*N_pos/N_neg)`; mặc định `neg_per_pos=30`. `fit_sample_model` tính weight bằng tỷ lệ **sau sampling** nếu balance_classes bật. Giá trị lưu **30.000143884178197** bằng `6.046.559 / 201.551`; tỷ lệ full `6.046.892 / 201.551` khoảng **30.001796**. Do đó có undersampling rất nhẹ theo receipts, không phải giữ nguyên toàn bộ TRAIN và không phải giảm mạnh negatives. README làm tròn 30.00 che mất khác biệt; tổng 6.248.110 không phải tổng hai số full counts trên.

Đây là đối chiếu số đếm/logic hiện có; tái dựng membership của 333 mẫu và kiểm chứng sample_id từ receipt/RNG vẫn thuộc P0, **chưa audit**. Không sửa README/baseline trong lượt này.

## 2. Feature contract và mapping

### LightGBM

| Object | Fields tokenizer cho phép |
|---|---|
| Chung | `action`, `object`, `principal` (semantic account buckets) |
| PROCESS | `properties.image_path`, `parent_image_path`, `command_line` |
| FILE | `properties.image_path`, `file_path`, `new_path` |
| MODULE | `properties.image_path`, `module_path` |
| REGISTRY | `properties.image_path`, `key`, `registry_key`, `registry_path` |
| TASK / SHELL / THREAD | image_path + tương ứng `path` / `payload` / không thêm field |
| USER_SESSION / SERVICE / HOST | chỉ nhóm chung theo allowlist |

FLOW bị loại; UUID/PID/IP/tên user literal không là feature. Parent/incoming tracker dùng hostname/time/actorID/objectID/tgt_pid_uuid làm join keys, giữ đúng CREATE actor=parent, object=child. Model dùng sparse binary presence, không có neural embedding/layer.

### BiLSTM dự kiến chuyển giao

Contract notebook rút gọn: categorical theo thứ tự `app_family`, `proto`, `resp_port_class`, `image_dir_class`; numeric duy nhất về nội dung là `delta_t_log1p`. Giữ x_bin một cột 0 và x_num/x_num_missing 0 cột theo kiến trúc. Không tái đưa conn_state/service/principal_class hay Bro volume metrics vào model mới để khớp nhầm checkpoint cũ.

OpTC dùng image_path eCAR-Bro cho app/path, Bro proto/resp_p/ts cho network/time. Group `(hostname, floor(ts/900))`, sort time/UID, chunk ≤512; delta reset 0 mỗi chunk; nhãn chunk positive nếu có flow positive theo policy baseline. BiLSTM nhìn hai chiều trong chunk hoàn tất. Sysmon EID3 candidate fields: Image, Protocol, DestinationPort, Initiated, UtcTime; xác minh hướng responder/initiator trước khi map port. Không coi remote port luôn là responder port.

Sysmon candidates cho ML: Image/CommandLine/ParentImage/ParentProcessGuid; User; TargetFilename/ImageLoaded/TargetObject; SourceProcessGUID/TargetProcessGUID của EID8/10. Tất cả coverage thực **chưa audit**. Không chế parent UUID từ PID tái sử dụng. Nếu phải fallback CBC vì thiếu nhãn Sysmon, ghi sensor, match rule, confidence; không ghép duplicate events hai sensor thành hai mẫu.

## 3. Vocab extend-only contract (A.1–A.8)

### A.1 — File gốc bất biến, format giữ nguyên

Baseline được chọn là file vocab 10.317 entries/hash ở mục 1. Không sửa, rename, prune hay ghi đè. Sau khi được phép triển khai, xuất `IL/dataset_1-ATLASv2/output/vocab_ext_round1.json`, rồi round2 tương tự, vẫn JSON object `token: integer`. Sidecar đặt riêng, không thêm wrapper/metadata keys vào vocab. Hiện **chưa tạo** artifact vocab mở rộng.

### A.2 — Prefix bất biến

Với round k: `old_size=len(vocab_{k-1})`; mọi cặp token/index cũ giữ nguyên; new IDs liên tục từ old_size. Kiểm tra source IDs unique, contiguous trước khi extend; nếu sai thì fail, không tự renumber. New tokens sort `(-TF_train_current_round, token)` với thứ tự chuỗi được định nghĩa và cố định. Prefix là thứ tự **theo column index**, không phụ thuộc JSON object key order hay whitespace. Không re-fit/reorder/prune/áp lại TF>=2 cho phần cũ.

### A.3 — TRAIN-only, TF đúng nghĩa gốc

Chỉ token chưa có ở vocab_{k-1}, được tokenizer frozen phát sinh trong TRAIN round k, TF>=2 mới đủ điều kiện. TF là tổng số lần token phát sinh theo logic counter gốc, không lẫn với DF hay binary presence lúc encode. Token cũ xuất hiện một lần vẫn dùng ID cũ; token cũ không xuất hiện vẫn giữ cột 0. Không tích lũy TF từ round tương lai hoặc VAL/TEST. Eligibility/allowlist của tokenizer giữ nguyên; không nhận raw properties ngoài policy chỉ vì dataset mới có trường đó.

### A.4 — Nối tiếp round và sidecar

`vocab_k[:old_size] == vocab_{k-1}` theo chỉ số. Sidecar lưu parent vocab SHA-256, extended SHA-256, split/round/dataset/source hashes, TF của round, first_seen_round trong TRAIN được phép quan sát, first_added_round (có thể muộn hơn first_seen nếu TF chưa đủ), dataset nguồn và policy version. Tokens baseline có round=0/dataset=OpTC; TF chỉ lấy metadata đã có, nếu không có per-token TF thì ghi unknown, không bịa. Không lấy TEST để tìm “lần đầu xuất hiện”.

### A.5 — Đóng băng tokenizer/mask/context engine

Hash thực đã đọc và khớp vocab_metadata:

| File | SHA-256 |
|---|---|
| ecar_tokenizer.py | dc9bc813eca6a60f910359651baa6f2accd01e8c4a9ddafef09d51d796a33170 |
| command_syntax.py | e625846e083df1ee1e7d908de60c3a997c51c67ff9b09cfda9d522ebb5661e89 |
| process_context_tracker.py | 00f0b2df596acfa7fc51dc6f634870f4c212ebce8e2f67d34af0862f87b1cf03 |

P0 đóng băng thêm config, dependency/code hashes và canonicalization rules. Cùng OpTC record + cùng causal context snapshot phải ra đúng tokens gốc. Adapter Sysmon là module ngoài; không sửa frozen tokenizer để nhận thêm field. B.1 availability tokens là **extension emitter riêng**, không làm đổi output frozen tokenizer. So sánh invariance chạy trước context dropout, vì dropout cố ý tạo training augmentation.

### A.6 — Category maps DL cũng append-only

Giữ format thực của category map trong đúng bundle được xác minh ở P0, không suy đoán file `vocab.json` ML dùng chung DL. Spec S3 hiện có là nested `categorical.fields[field].vocab` list với value/id/train_count; notebook đọc `network_category_maps.json` với `fields[field].mapping`. Chưa tìm thấy category-map export đó trong DL; phải đối chiếu trước khi publish.

Giữ nguyên từng value→ID cũ ở 4 fields, `<UNK>=0`, `<MISSING>=1`; new IDs liên tục riêng từng field, metadata riêng, không renumber theo frequency mới. Frozen path/port taxonomy không tự đổi để tạo category mới. Không cần extend nếu không có category mới hợp lệ.

Nguyên tắc append-only **áp dụng đầy đủ cho DL**. Tuy nhiên TF threshold của ML không tự là threshold gốc của DL: S3 ghi min_train_frequency=5 cho categorical. Đề xuất giữ threshold gốc từng field (train-only) và yêu cầu quyết định nếu thầy muốn TF>=2 thống nhất cả hai nhánh; không âm thầm đổi thành 2. Reserved IDs bất biến trong mọi trường hợp.

### A.7 — Nghiệm thu bắt buộc tại P3

1. Với mỗi old ID i, hash entry bằng SHA-256 của JSON UTF-8 canonical `[token,i]` (ensure_ascii=false, separators cố định); so sánh từng hash và toàn prefix digest ở vocab gốc, round1, round2. Kiểm tra không duplicate/gap, file baseline hash nguyên vẹn.
2. Chọn mẫu OpTC có provenance và vector gốc từ frozen shards, đủ các object/context cases. Re-tokenize bằng engine/context frozen rồi encode ext; **old-column projection phải khớp bitwise vector gốc**. Cùng model cũ, môi trường/threads/version/iteration cố định, raw margins và predictions trên old-column slice không đổi. Không đưa toàn extended matrix trực tiếp vào model cũ. Availability extension chỉ vào new columns; không bật dropout khi test invariance.
3. Token chỉ có ở VAL/TEST/future-round không được thêm. Fixture train TF=1 không thêm, TF=2 thêm; existing token TF=1/vắng mặt vẫn tồn tại. New token hợp lệ xuất hiện cả TRAIN và TEST vẫn được thêm từ TRAIN; việc có ở TEST không tự là leakage. Chứng minh bằng membership/provenance và perturb VAL/TEST mà vocab không đổi.
4. Lặp các kiểm tra ID/UNK/MISSING và train-only cho category maps, save/reload và resume nhiều round. Các test này **chưa chạy**.

### A.8 — LightGBM khi tăng số cột

Baseline `init_model` chỉ dùng schema cũ `X[:, :N0]`. Nhánh chính token mới dùng residual trên full schema mở rộng (mục 5.2). Compatibility tests bao gồm N0→N1→N2, old-column projection, old replay zero-padding/encode, save/reload, lỗi khi cố đưa sai shape trực tiếp vào old booster, và tổng margins base+residual. Không sửa model header hay tắt shape checks. Không dựa vào giả định init_model tự hỗ trợ thêm features.

## 4. P1 audit dữ liệu, context và nhãn

**Sysmon primary đã chốt.** Audit theo host/session/engagement: EID counts, EID8/10 có được collect không, GUID/parent-GUID parse rate, event ordering, timestamp resolution/timezone, EID3 direction/port/image coverage. Không thấy EID8/10 không chứng minh sensor tắt nếu không có bằng chứng cấu hình; phân biệt absent/unknown/unavailable.

Availability extension cho ML: `ctx_parent_avail=0/1/unknown`, `ctx_incoming_avail=0/1/unknown` là token mới (tên semantic columns ctx_parent_avail/ctx_incoming_avail). Incoming availability nghĩa sensor/schema/join đủ quan sát; không dùng “đã có tấn công/incoming event” làm availability. Parent availability dựa trên observation/join tại thời điểm query. Admission vẫn TRAIN TF>=2; không ép thêm token chỉ thấy ở VAL. Nếu một trạng thái chưa được admit, ghi vào audit sidecar, encode không có token đó; không sửa vocab cũ.

Chạy Parent Tracker trên toàn stream mỗi host theo thời gian trước khi phân chia feature rows; mỗi query snapshot lấy strictly-past, query trước update cùng timestamp, không đọc nhãn. Không dùng future events của chính host, không share state giữa độc lập session/reset VM. Group/session split phải ghi rõ protocol online past-context này; không mang state của held-out engagement sang training fold. Nếu một grouping gây test-history→train dependency xuyên fold, purge/reset theo session hoặc tách replay causal stream của fold, không dùng full-stream cache mù quáng. Tracker không fit vocab; vocab chỉ fit TRAIN sau split. Kiểm tra cap 10.000 processes/host, TTL24h, eviction/expired/missing/coverage theo host/EID/round; **chưa audit ATLAS**.

Context dropout: training-only, deterministic theo RNG/checkpoint, trên cả replay và new TRAIN. Mask nhóm parent/incoming, cập nhật availability là unavailable; không làm mất base event features. Rate đề xuất thử `{0,0.25,0.5}` trên VAL, chưa chốt. Tạo augmentation sau freeze vocab; không dùng augmentation để lách TF admission. Không tự thêm availability token từ OpTC replay nếu token không đạt TF trong TRAIN round hiện tại. Zero-shot old model trên OpTC và ATLAS: (i) context quan sát được, (ii) mask context; báo cáo coverage để không gọi cấu hình thiếu sensor là “full context”.

UNK-rate từng field/domain/split/round: trước và sau extend, tách UNK khỏi MISSING, denominator là số categorical observations; mở rộng chỉ theo TRAIN, encode VAL/TEST sau đó. Báo cả unseen token rate ML. Không fit từ thống kê VAL/TEST.

So sánh Bro-joined OpTC và Sysmon EID3 ATLAS: delta_t_log1p quantiles/histogram, zero/tied-timestamp fraction, time resolution, số events mỗi cửa sổ 900s và chunks/window, theo host/domain/split. Báo cả delta trước chunk và delta input đã reset ở chunk boundary; không lẫn các số 0 do reset với burst thực. Sample coverage/collection policy, duplicates và filtering được báo kèm. **Chưa audit**, không mặc định network connection event tương đương Bro flow.

Nhãn: không gán cả attack folder là positive. Kiểm chứng join REAPr process/node/edge→Sysmon event, thời gian hợp lệ của malicious process, match ambiguity và unknown. Không gán toàn bộ lifetime process là malicious nếu chỉ có node label mà chưa duyệt policy. CBC chỉ fallback khi Sysmon thiếu label linkage, không coi CBC có nhãn hoàn chỉnh mặc định. Báo counts và positive rate theo domain/round/split cho event, process, window/chunk; coverage=known-labeled/eligible, positive rate=positive/known-labeled; unknown tách riêng. OpTC red-team event/flow labels không đồng nghĩa ATLAS process-impact labels.

## 5. Thiết kế học tăng dần

### 5.1 BiLSTM, logit và critical path

P0 sử dụng **checkpoint subsetB đã có** tại `DL/05_models/bilstm_v2_subsetB/best_model.pt`; blocker thiếu/sai checkpoint được gỡ theo xác nhận người dùng và config4-field khớp notebook06d. Khóa hash weights/config/metrics, đối chiếu category maps/shards/fingerprint, tensor keys/shapes và inference bằng cơ chế load weights an toàn trước fine-tune. Không cần tìm checkpoint7-field hay chuyển đổi kiến trúc từ bundle cũ. Chưa kiểm tra tensor/inference trong lượt cập nhật tài liệu này.

**Không lập retrain/reproduced baseline làm bước mặc định nữa.** Dùng weights subsetB hiện có. Nếu P0 phát hiện lỗi integrity hoặc không khôi phục được đúng category mapping, báo lỗi cụ thể và xử lý bundle; không tự retrain thay thế. Category maps/shards vẫn cần đối chiếu độc lập vì có weights không bảo đảm đã đủ preprocessing assets. Giữ thứ tự LightGBM trước như kế hoạch đã chốt.

Mở rộng embedding: mỗi field có `emb_old` là registered buffer không train, `emb_new` là Parameter. Lookup old IDs vào buffer, new IDs remap `id-old_size`; giữ nguyên width từ checkpoint, không tính lại width theo cardinality mới. Giữ cả UNK/MISSING trong old buffer. Sang round sau, embeddings của vocab_{k-1} được snapshot thành old buffer; chỉ rows vừa thêm train theo stage A. Optimizer chỉ chứa trainable params; save/reload phải giữ mapping và stage.

Stage A train new rows+head, freeze event_encoder/LSTM; Stage B mở event_encoder/LSTM LR thấp hơn head, old rows vẫn buffer. Đề xuất v2 không mở old embedding rows, chỉ mở old neural modules; nếu muốn unfreeze rows cũ cần protocol riêng, không dùng buffer rồi tuyên bố đang train nó. Frozen module có BatchNorm phải eval() để không đổi running stats; controller áp lại eval sau model.train(), freeze dropout khi yêu cầu deterministic frozen module. Model source hiện dùng LayerNorm; không giả định có BatchNorm. Test old rows bitwise bất biến qua AdamW/momentum steps.

Lưu raw logits trực tiếp trước sigmoid. Chọn threshold trên logit bằng VAL theo policy khóa trước; không inverse-logit từ probability đã làm tròn/bão hòa. DER++ lưu logits teacher tại lúc vào buffer, loss logits-consistency + supervised replay/new; không distill trên saturated probability. CSV predictions subsetB lưu probability, không có cột logit; tái inference để thu raw logits ở P0 sau phê duyệt, không phục hồi giả từ CSV. Giữ threshold xác suất subsetB **0.99560546875** cho đối chiếu metric lịch sử; calibration logit mới báo riêng. Lý do dùng logits vẫn có hiệu lực cho distillation/ranking precision, nhưng không còn viện dẫn T=1.0 là threshold của checkpoint hiện tại.

### 5.2 LightGBM chính: residual với extended schema

Giữ f0 frozen (300 cây theo receipt). Round k dùng `F_k(x)=f0(x[:N0])+sum_{j=1..k} g_j(x[:Nj])` trên **raw margins**, probability=sigmoid(F_k). Init_score train g_k là F_{k-1} trên TRAIN+replay. VAL cần base margin tương ứng để early stopping dựa trên total margin, không chỉ residual score. Khi infer/save/reload phải cộng toàn chain; init_score không tự được lưu thành thành phần inference. Version bundle lưu từng vocab prefix length và checkpoint hash.

Recompute ratio negative/positive trên TRAIN domain mới từng round; đồng thời ghi tỷ lệ replay và mixture sau sampling. Đề xuất class/domain sample weights tường minh, hoặc scale_pos_weight theo mixture với đối chứng ratio domain mới; không áp chồng class weights hai lần. Chỉ dùng TRAIN counts, không bê 30.00 OpTC sang ATLAS. Trường hợp không có positives không chia 0: no-go cho supervised round hoặc protocol benign-only riêng.

Budget đề xuất trước audit: tối đa 100 residual trees/round, tổng thêm ≤200 cây cho hai round chính; early stopping patience20 trên VAL total-margin AP, learning rate khởi điểm0.05. Đây là proposal, chưa tune. Nếu thêm round phải phân bổ lại tổng budget, không tăng không giới hạn. Fixed-schema init_model baseline dùng cùng budget tăng cây; early stopping validation tương đương. Frozen f0 cũng có thể được tính trên view context-masked khi dropout training; phải cộng base/residual nhất quán cùng view, ghi augmentation/inference policy.

ATLAS-only from scratch: cùng vocab extended của round, cùng ATLAS TRAIN và label policy, không replay OpTC, không weights f0. Để “cùng ngân sách” rõ ràng: primary cap tổng inference trees bằng `300 + cumulative residual cap`, đồng thời báo new-training tree/CPU-time budget (khác IL được kế thừa 300 cây); thêm đối chứng scratch với chỉ new-tree cap nếu cần. DL scratch dùng cùng input/maps/architecture và optimizer-step cap, không warm start. Vocab có prefix OpTC nên đây là scratch **weights**, không phải hoàn toàn không dùng prior representation OpTC.

## 6. Replay, rounds, thống kê và go/no-go

Replay chỉ từ frozen OpTC TRAIN hoặc TRAIN round đã học; không lấy VAL/TEST, kể cả mẫu khó đã biết. Phân tầng domain × label × scenario SC1/2/3 (nếu có annotation hợp lệ) × app_family; multi-app chunk dùng signature/primary-app rule cố định, không duplicate vượt budget. Quota hiếm, reservoir deterministic và hard-sample quota giới hạn để không bỏ hết background. Hardness từ lỗi/logit/entropy của TRAIN model hoặc proxy contamination ở TRAIN, không từ held-out labels/predictions.

Giữ nguyên chunks/masks/delta cho DL, causal context snapshots cho ML. Cửa sổ firefox 1.800 flow và case REJ trong báo cáo là **TEST**, tuyệt đối không chuyển chúng vào replay. Chỉ ưu tiên mẫu TRAIN tương tự. REJ dùng audit-only metadata của OpTC khi có; không thêm conn_state vào DL active fields, không bịa REJ cho Sysmon. Buffer cố định byte+event/token cap, có tính logit/provenance storage; log mọi quota/ratio. Budget cụ thể cần quyết định ở cuối tài liệu.

Ít nhất **2 rounds ATLAS** tuần tự: R1, R2 theo thời gian engagement/session thật, chưa biết assignment vì chưa audit. Mỗi round chỉ mở vocab từ own TRAIN; giữ VAL/TEST độc lập, cả hai host của multihost engagement cùng group; windows/chunks không vượt split. Không dùng thứ tự tên file như chronology. Nếu chronological split không đủ nhóm: grouped CV/leave-one-engagement-out là phương án đánh giá thay thế, reset model/vocab/buffer từ OpTC mỗi fold; không nối các folds thành giả incremental rounds. Holdout TEST khóa, không chọn hyperparameters từ kết quả TEST.

### Gate sau P1 (B.3)

**Chưa có số liệu audit thật để chốt threshold dựa trên dữ liệu.** P1 phải xuất N_positive_engagements, số group độc lập sau gom attack chains gần trùng, positive windows/chunks từng split/round và class balance. Sau đó mới chốt gate; không khẳng định ATLAS đạt gate ở đây.

Đề xuất ngưỡng sàn để thầy review: VAL và TEST **mỗi tập ≥3 positive engagement groups**, mỗi TRAIN round ≥1 positive group, ≥30 positive chunks và ≥30 negative chunks trong mỗi tập đánh giá. Đây là proposal vận hành, **không là power analysis hay bảo đảm thống kê**; 3 groups vẫn quá ít cho CI đáng tin. Với 2 TRAIN rounds và holdout độc lập tối thiểu cần 8 positive groups không chồng; nếu gộp near-duplicate chains làm thiếu thì fail gate. Khi có audit: trình bảng tính khả thi; nếu fail, thử grouped CV nhưng các fold test chỉ 1 group vẫn không được coi vượt gate. Khi thiếu groups hoặc AP/CI không xác định, kết quả BiLSTM **chỉ mô tả**, không claim vượt baseline/không forgetting. Nếu muốn suy luận mạnh cần thêm independent engagements/dataset.

Metric chính chống forgetting: **AP (average precision, gọi rõ là quy ước PR-AUC ở đây) trên raw margins/logits**, kèm paired cluster-bootstrap 95% CI của AP và delta AP. Cùng resampled groups cho baseline/round, phân tầng hợp lý để giữ cả hai nhãn; ghi số lần bootstrap invalid/degenerate. ATLAS cluster ở engagement; OpTC báo host/session/window hierarchy và scenario-specific results, không coi 82 chunks là 82 engagements độc lập. Thực hiện cả **VAL OpTC** để chọn stage và TEST OpTC chỉ báo cáo; F1 là metric phụ, không dùng delta F1 định nghĩa forgetting.

Forgetting domain d ở round k: max AP các round trước − AP hiện tại, kèm paired CI với reference đã nêu; BWT từ AP matrix. Không lấy thay đổi prior giữa datasets làm forgetting. Ceiling AP=1 và bootstrap CI hẹp/degenerate không chứng minh tổng quát tốt. Gate retention đề xuất trên VAL: upper95%CI của AP_drop ≤0.01; nếu CI quá rộng/không xác định thì chưa đủ bằng chứng, không mặc định pass. Đây cũng là tolerance cần duyệt, không số liệu đo.

Baselines: frozen OpTC context-observed/masked; fixed-schema continue new-only/new+replay; extended residual+replay ±context dropout; DL fine-tune ±replay ±staged freeze, DER++; **ATLAS-only scratch**; scratch new+replay riêng. Rules ATLAS: có powershell; powershell hoặc TEMP_OR_APPDATA, khóa trước đánh giá và báo coverage/precision/recall/AP phù hợp binary score. Không chọn rule bằng TEST. So performance với rules cùng label/unit; không coi F1 lịch sử cao là chứng minh learned temporal behavior.

## 7. Threats to validity

1. **Label shift/semantics:** OpTC red-team events/flow criteria khác REAPr process/node/edge impact; node-to-event expansion có thể inflate positives. Báo policy, positive rate, known/unknown coverage, sensitivity analysis strict event vs process-propagated nếu làm được; không gộp AP hai domain thành một số che khác biệt.
2. **Sensor/domain shift:** Bro-joined flow vs Sysmon EID3 khác collection, duplicates, granularity/delta/window density; Windows7 ATLAS không kiểm chứng Windows11 hay Linux/auditd.
3. **Context availability:** không quan sát EID8/10/parent không đồng nghĩa hành vi không xảy ra. Availability tokens có thể trở thành domain shortcut; ablation/dropout và coverage bắt buộc.
4. **Dependence/attack redundancy:** ATLAS chains trùng, OpTC split không host-disjoint, positive ít, nhiều chunks cùng window. Group bootstrap không tạo thêm independent attacks; gate không được bypass bằng đếm chunks.
5. **Baseline identity:** checkpoint subsetB đã có và config khớp notebook4-field; vẫn phải khóa category maps/fingerprint/tensor shapes và tái inference ở P0. Không trộn metrics/threshold/diagnostics của bundle cũ với subsetB khi chưa đối chiếu sample IDs. Không cần reproduced baseline mặc định.
6. **Selection/calibration:** TF/UNK/weight fitting TRAIN-only, threshold và unfreeze VAL-only; test nhiều round để reporting, không dùng feedback test. Logit thay probability có thể thay ties/AP; báo baseline tái score cùng convention trước khi tính forgetting.
7. **Causal state/split:** full-stream tracker chỉ strictly-past, không nhãn; past observations xuyên partitions là online-context protocol, không phải fully independent offline samples. Ghi rõ reset/purge giữa engagements/folds, kiểm tra TTL/eviction.

## 8. Roadmap sau khi kế hoạch được duyệt

| Bước | Deliverable tương lai | Điều kiện nghiệm thu |
|---|---|---|
| P0 | baseline manifest/hashes; reconcile undersampling; khóa bundle BiLSTM subsetB đã có | LightGBM inference identity; DL shape/maps/config/fingerprint và inference nhất quán trước fine-tune |
| P1 | Sysmon/REAPr schema+label audit, EID8/10/GUID, UNK, delta/window distribution, tracker eviction, group counts | gate cụ thể từ audit thật; mọi missing/unknown minh bạch; nếu không đủ nhóm DL descriptive-only |
| P2 | Sysmon adapter, causal snapshots, group/time split + ≥2 round manifests | primary source/label grain cố định; no duplicates/window overlap/future state; dataset read-only |
| P3 | vocab/category extension, sidecars, replay | A.7: per-entry prefix hashes, OpTC bitwise old columns+old predictions, train-only/no-future; increased-column compatibility; baseline hashes nguyên vẹn |
| P4 | LightGBM residual trước; DL sau checkpoint gate | raw-margin composition/reload đúng, weights/class ratio/tree cap; emb_old buffer bất biến, emb_new train, freeze/eval đúng |
| P5 | smoke tests fixture/subset, lỗi→sửa→test lại | labels/direction/PID reuse/order/eviction, split leakage, logits/threshold, optimizer freeze, resume đều qua; không dùng smoke metrics làm kết luận |
| P6 | Kaggle package và ≥2-round hoặc grouped-evaluation report | AP+cluster CI/forgetting trên VAL/TEST từng domain, rules/scratch/context ablations, coverage/cost/budget, limitations |

Source tương lai: `IL/dataset_1-ATLASv2/{preprocess,model,test,notebook,docs}/`; mọi generated artifact dưới `IL/dataset_1-ATLASv2/output/`. Resolve/reject outputs trong DATASET và dataset roots/symlinks; streaming tar thay vì decompress in-place, quota staging, atomic publish/resume. Không full local training. Bản v2 chỉ là tài liệu, không tạo vocab/model/output experiment.

## 9. Tài liệu nền tảng

Giữ định hướng paper v1: iCaRL (CVPR2017), End-to-End Incremental Learning (ECCV2018) cho exemplar/distillation; DER/DER++ (NeurIPS2020) cho replay logits; ULMFiT (ACL2018) cho gradual unfreezing (không tự là bằng chứng continual learning); MalFSCIL/TIFS và Wazuh/IEEE Access là related work khác setting. Không tự gán rank A*/Q1 chưa xác minh. Liên kết nguồn đã đối chiếu ở v1:

- DER: https://proceedings.neurips.cc/paper/2020/hash/b704ea2c39778f07c617f6b7ce480e9e-Abstract.html
- ULMFiT: https://aclanthology.org/P18-1031/
- iCaRL: https://openaccess.thecvf.com/content_cvpr_2017/html/Rebuffi_iCaRL_Incremental_Classifier_CVPR_2017_paper.html
- End-to-End: https://openaccess.thecvf.com/content_ECCV_2018/html/Francisco_M._Castro_End-to-End_Incremental_Learning_ECCV_2018_paper.html
- Dataset/ground-truth interpretation: local `DATASET/ATLASv2/atlasv2/README.md`, `DATASET/ATLASv2/reapr-ground-truth/atlasv2/README.md`; ATLASv2 arXiv description không gọi là proceedings peer-reviewed.

## 10. Review checklist A/B

“Đã áp dụng” = đã đưa vào kế hoạch, không có nghĩa đã implement/test. “Cần thêm dữ liệu” = yêu cầu đã ghi nhưng kết luận phụ thuộc audit/artifact còn thiếu. Không bác bỏ ràng buộc append-only nào.

| Mục | Trạng thái | Ghi chú |
|---|---|---|
| A.1 | đã áp dụng | format thật token→index, 10.317; output mới |
| A.2 | đã áp dụng | prefix IDs, deterministic suffix, không prune |
| A.3 | đã áp dụng | new TRAIN TF>=2, phần cũ không refit |
| A.4 | đã áp dụng | round chain và sidecar provenance |
| A.5 | đã áp dụng | 3 source hashes khớp metadata; extension emitter riêng |
| A.6 | cần thêm dữ liệu | append-only DL đã chốt; thiếu category-map export đúng checkpoint, cần chốt TF5/TF2 |
| A.7 | đã áp dụng | 3 tests bắt buộc + multi-round/roundtrip ở P3 |
| A.8 | đã áp dụng | fixed schema baseline, residual expanded chính |
| B.1 | cần thêm dữ liệu | EID8/10/GUID chưa audit; availability/dropout/zero-shot đã lập |
| B.2 | đã áp dụng | rules, AP+CI kể cả VAL, logit threshold/DER++; không delta F1 |
| B.3 | cần thêm dữ liệu | ≥2 rounds/CV; threshold sàn là proposal, chưa có audit groups |
| B.4 | đã áp dụng | threats, label policy/positive rate/coverage; tỷ lệ ATLAS chưa audit |
| B.5 | đã áp dụng | checkpoint subsetB đúng đã có, config4+0 khớp; gỡ blocker thiếu weights và retrain mặc định; P0 còn validation bundle |
| B.6 | đã áp dụng | buffer/Parameter/remap, frozen eval, UNK-rate P1 |
| B.7 | đã áp dụng | SC/app/hard replay TRAIN-only; không lấy cases TEST |
| B.8 | đã áp dụng | ratios/tree budget/VAL, causal tracker/eviction audit; reset fold/session |
| B.9 | đã áp dụng | ATLAS-only scratch với representation/budget rõ |
| B.10 | đã áp dụng | Sysmon primary, CBC chỉ khi thiếu label linkage; Linux ngoài kiểm chứng |
| B.11 | đã áp dụng | delta/density comparison P1; số đo chưa audit |
| B.12 | đã áp dụng | receipts cho thấy bỏ333 negatives; weight tính sau sampling |

## 11. Câu hỏi cần người dùng/thầy quyết định

Checkpoint đã được giải quyết: dùng subsetB hiện có, không còn câu hỏi về tìm weights hoặc retrain mặc định.

1. Có chấp nhận gate tạm ≥3 positive engagements mỗi VAL/TEST, ≥30 positive/negative chunks, và retention upper95%CI(AP_drop)≤0.01 làm proposal để hiệu chỉnh sau P1; khi không đạt thì chỉ báo cáo DL mô tả không?
2. Với DL, giữ threshold categorical gốc (S3 min-frequency5) hay đổi threshold cho **new categories** thành TF>=2? Đề xuất giữ threshold gốc; old IDs luôn bất biến.
3. Ngân sách replay cố định tối đa mỗi nhánh là bao nhiêu GiB (và Kaggle resource/time budget)? Cần số này để chốt quota SC/app/hard và tính công bằng với scratch; không tự chọn từ test.

Chưa cần hỏi EID coverage, nhãn match rate hay group counts từ người dùng: đó là trách nhiệm audit P1 sau khi được phép triển khai. Không yêu cầu duyệt lại các ràng buộc đã chốt.
