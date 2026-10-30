# OpTC → ATLASv2 — PLAN REVIEW v3

Ngày 2026-10-30. **DRAFT v3 — cập nhật quyết định review, chưa code, chưa chạy thực nghiệm/training.** Giữ nguyên `PLAN_REVIEW.md` và `PLAN_REVIEW_v2.md`. Các test, audit corpus, inference, bootstrap và training dưới đây là công việc tương lai, không phải kết quả đã chạy.

## Thay đổi so với v2

- Khóa gate vào manifest trước mọi ATLAS VAL/TEST model scoring; áp dụng cả ML/DL, pass→confirmatory, fail→descriptive-only. Margin retention tạm ML=0.002, DL=0.01; hiệu chỉnh trước lock bằng self-bootstrap baseline OpTC, không ATLAS.
- VAL/TEST ATLAS cố định xuyên round; chỉ TRAIN chia ≥2 round. Tối thiểu8 positive groups =3 VAL+3 TEST+1 TRAIN R1+1 TRAIN R2, giả sử tất cả độc lập/không trùng.
- ML new-token TF≥2; DL new-category TF≥5 đã chốt. Đã đọc source: train_count tính theo flow; threshold lịch sử theo field khác nhau, ghi rõ bên dưới. TF2 DL chỉ là ablation VAL tùy chọn.
- Replay phải có raw record + causal context (ML), raw category values + sequence (DL), để re-encode mỗi vocab_k; không zero-pad/giữ UNK cho token mới khi raw evidence thực có token đó.
- Availability whitelist là ngoại lệ admission theo policy, không TF; **chờ thầy xác nhận**. Prefix cũ vẫn bất biến.
- Giữ Stage C mở old embedding rows như ablation riêng, mặc định tắt.
- Replay cap theo event/chunk, 3 mức sensitivity sau P0 đo storage và positive counts; medium chính. Không tự điền cấu hình Kaggle còn thiếu.
- Tách cốt lõi/tùy chọn có activation gates; thêm matched-data scratch new+buffer, giữ ATLAS-only scratch riêng.
- Tạo `README_CORRECTIONS_PROPOSED.md`; không sửa README thật. Mọi thống kê corpus/storage/bootstrap chưa đo đều ghi **chưa audit**.

## 1. Phạm vi, bằng chứng mới và thứ tự thực hiện

Binary domain-incremental detection, hai nhánh LightGBM event-level và BiLSTM chunk-level. Làm LightGBM trước. Không mở rộng output classes, thêm GraphSAGE/fusion hay đổi tokenizer baseline. Nguồn primary ATLAS là **Sysmon**, phù hợp hướng testbed Windows 11; CBC là fallback **tùy chọn**, chỉ kích hoạt nếu Sysmon thiếu label linkage và đã xác nhận CBC có thể khắc phục, với provenance và đánh giá riêng. ATLASv2 ghi Windows 7: cùng sensor family không bảo đảm schema/distribution tương đương Windows 11; không kiểm chứng Linux/auditd.

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

Với round k: `old_size=len(vocab_{k-1})`; mọi cặp token/index cũ giữ nguyên; new IDs liên tục từ old_size. Kiểm tra source IDs unique, contiguous trước khi extend; nếu sai thì fail, không tự renumber. New data-derived tokens sort `(-TF_train_current_round, token)` với thứ tự chuỗi được định nghĩa và cố định. Nếu whitelist policy được duyệt: append policy tokens còn thiếu trước theo lexicographic order, rồi data-derived tokens; ghi rõ admission_source và không duplicate. Prefix là thứ tự **theo column index**, không phụ thuộc JSON object key order hay whitespace. Không re-fit/reorder/prune/áp lại TF>=2 cho phần cũ.

### A.3 — TRAIN-only, TF đúng nghĩa gốc

Với data-derived tokens, chỉ token chưa có ở vocab_{k-1}, được tokenizer frozen phát sinh trong TRAIN round k, TF>=2 mới đủ điều kiện. Ngoại lệ duy nhất đang xin xác nhận là availability whitelist policy ở mục A.9; không phải nới rule cho token bất kỳ. TF là tổng số lần token phát sinh theo logic counter gốc, không lẫn với DF hay binary presence lúc encode. Token cũ xuất hiện một lần vẫn dùng ID cũ; token cũ không xuất hiện vẫn giữ cột 0. Không tích lũy TF từ round tương lai hoặc VAL/TEST. Eligibility/allowlist của tokenizer giữ nguyên; không nhận raw properties ngoài policy chỉ vì dataset mới có trường đó.

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

Nguyên tắc append-only **áp dụng đầy đủ cho DL**. Quyết định chính v3: **new categories của cả bốn fields dùng TF≥5 trong TRAIN round hiện tại**, ML vẫn TF≥2. Old IDs và `<UNK>=0`, `<MISSING>=1` không đổi, không lọc lại old categories, không refit taxonomy. Category hiếm như executable basename ngẫu nhiên giữ UNK để hạn chế memorization; đây là động cơ thiết kế, chưa chứng minh cải thiện tổng quát hóa trên ATLAS.

Đã đọc `DL/01_code/s3_preprocess.py:40–66`: view tr là flows join TRAIN windows; `count(*) GROUP BY category` tạo train_count. **Đơn vị source là flow, không chunk/window**. Source dùng min-frequency theo field: app_family/service=5, fields khác mặc định1; MIN_SUPPORT=5 để xét feature active là rule khác admission. Do đó “S3 gốc tất cả fields TF5” không chính xác. V3 theo quyết định người dùng áp TF5 cho **suffix DL mới**, giữ nguyên mọi prefix cũ; sidecar ghi thay đổi admission cho các field vốn threshold1. P0 còn đối chiếu source/spec/export đúng fingerprint và audit duplicate join; chưa tái đếm shards. ATLAS đếm canonical EID3 connection events sau dedup trước chunking, không số lần xuất hiện do replay minibatches.

TF≥2 cho new DL categories chỉ là sensitivity ablation riêng, đánh giá/chọn trên VAL, không dùng TEST lựa chọn. Mỗi ablation có vocab lineage riêng từ cùng prefix; không prune/reorder suffix của nhánh chính để chạy ablation. Điều kiện bật ghi ở mục8.

### A.7 — Nghiệm thu bắt buộc tại P3

1. Với mỗi old ID i, hash entry bằng SHA-256 của JSON UTF-8 canonical `[token,i]` (ensure_ascii=false, separators cố định); so sánh từng hash và toàn prefix digest ở vocab gốc, round1, round2. Kiểm tra không duplicate/gap, file baseline hash nguyên vẹn.
2. Chọn mẫu OpTC có provenance và vector gốc từ frozen shards, đủ các object/context cases. Re-tokenize bằng engine/context frozen rồi encode ext; **old-column projection phải khớp bitwise vector gốc**. Cùng model cũ, môi trường/threads/version/iteration cố định, raw margins và predictions trên old-column slice không đổi. Không đưa toàn extended matrix trực tiếp vào model cũ. Availability extension chỉ vào new columns; không bật dropout khi test invariance.
3. Token chỉ có ở VAL/TEST/future-round không được thêm. Fixture train TF=1 không thêm, TF=2 thêm; existing token TF=1/vắng mặt vẫn tồn tại. New token hợp lệ xuất hiện cả TRAIN và TEST vẫn được thêm từ TRAIN; việc có ở TEST không tự là leakage. Chứng minh bằng membership/provenance và perturb VAL/TEST mà vocab không đổi.
4. Lặp các kiểm tra ID/UNK/MISSING và train-only cho category maps, save/reload và resume nhiều round. Các test này **chưa chạy**.

### A.8 — LightGBM khi tăng số cột

Baseline `init_model` chỉ dùng schema cũ `X[:, :N0]`. Nhánh chính token mới dùng residual trên full schema mở rộng (mục 5.2). Compatibility tests bao gồm N0→N1→N2, old-column projection, old replay raw re-encoding (không zero-padding mù quáng), save/reload, lỗi khi cố đưa sai shape trực tiếp vào old booster, và tổng margins base+residual. Không sửa model header hay tắt shape checks. Không dựa vào giả định init_model tự hỗ trợ thêm features.

### A.9 — Ngoại lệ availability admission theo POLICY — cần thầy xác nhận

Whitelist cố định sáu tokens: `ctx_parent_avail=0`, `ctx_parent_avail=1`, `ctx_parent_avail=unknown`, `ctx_incoming_avail=0`, `ctx_incoming_avail=1`, `ctx_incoming_avail=unknown`. Nếu được duyệt, append ở round1 theo quy tắc A.2, dù TF=0; rounds sau reuse IDs. Whitelist được khóa/version/hash trước khi fit/scoring, không dựa trên nhãn, VAL/TEST, future rounds hay event inventory. Emitter ngoài tokenizer frozen, dùng cùng semantics trên mọi domain. Không nhét metadata vào vocab.

Đây là **ngoại lệ có chủ đích đối với TF/TRAIN admission**, không ngoại lệ prefix bất biến hay read-only baseline. Sidecar ghi `admission_source=policy`, policy_version/hash, first_added_round, TF_observed riêng, first_seen_round=null nếu chưa quan sát; không bịa dataset nguồn/TF≥2. Cho phép context dropout phát token0 dù TRAIN tự nhiên chỉ có context đầy đủ. Test whitelist đúng sáu tokens, không bị dữ liệu/label perturb làm đổi, unknown phân biệt unavailable; unapproved policy phải fail publication, không tự bật. Nếu thầy không duyệt, cần sửa protocol availability/dropout công khai trước triển khai; không ngầm quay về TF rule thiếu token0.

### A.10 — Re-encode replay theo vocab_k (bổ sung A của review v3)

ML buffer lưu raw canonical event có source reference/hash và causal context snapshot đủ tái tạo **mọi token** từ frozen tracker/emitter, không chỉ tokens đã lọc bởi vocab cũ. DL buffer lưu ordered raw category values của bốn fields (trước map IDs), thời gian/delta/chunk boundary/mask, label và provenance. Source pointers chỉ bổ sung; không coi ID0/old sparse vector là raw data. Nếu snapshot cũ thiếu raw context thì P0/P2 phải khôi phục bằng chronological replay frozen, không tự suy đoán từ vector.

Mỗi round sau khi admit suffix từ ATLAS TRAIN, re-encode cả OpTC và previous-round buffer bằng vocab_k/maps_k. Dữ liệu replay không tham gia admit data-derived suffix của round hiện tại, nhưng **được kích hoạt new column/new ID khi raw value đủ khớp token đã admit**. Không zero-pad mặc định các dòng OpTC; caches có vocab/tokenizer/context hashes và phải invalidate khi vocab đổi. Giữ old vector chỉ làm reference kiểm chứng, không là representation duy nhất. P0 đo cả raw replay payload; kích thước sparse shard không đại diện đủ cho buffer này.

Test P3 bắt buộc: fixture token/category xuất hiện ở raw OpTC nhưng từng bị OOV, nay được ATLAS TRAIN admit; re-encode OpTC bằng vocab_k phải có đúng new column/ID theo frozen tokenizer/raw value. Old-column projection vẫn bitwise vector gốc; old category IDs không đổi (raw value trước đây UNK được phép sang new ID — không yêu cầu giữ UNK). Kiểm tra snapshot strictly-past, same record→same tokens, policy tokens có provenance riêng; test qua rounds, reload/cache invalidation, và không dùng VAL/TEST để admit token. Không dùng OpTC TEST diagnostic case làm replay fixture dữ liệu huấn luyện.

## 4. P1 audit dữ liệu, context và nhãn

**Sysmon primary đã chốt.** Audit theo host/session/engagement: EID counts, EID8/10 có được collect không, GUID/parent-GUID parse rate, event ordering, timestamp resolution/timezone, EID3 direction/port/image coverage. Không thấy EID8/10 không chứng minh sensor tắt nếu không có bằng chứng cấu hình; phân biệt absent/unknown/unavailable.

Availability extension cho ML dùng whitelist A.9 (**chờ thầy xác nhận**). Incoming availability nghĩa sensor/schema/join đủ quan sát; không dùng “đã có tấn công/incoming event” làm availability. Parent availability dựa trên observation/join tại query. `unknown` khác `0=unavailable`; nếu available nhưng không có incoming event thì availability vẫn1. Các tokens0 được bảo đảm tồn tại nhờ policy khi dropout, không cần giả tạo TF từ augmentation.

Chạy Parent Tracker trên toàn stream mỗi host theo thời gian trước khi phân chia feature rows; mỗi query snapshot lấy strictly-past, query trước update cùng timestamp, không đọc nhãn. Không dùng future events của chính host, không share state giữa độc lập session/reset VM. Group/session split phải ghi rõ protocol online past-context này; không mang state của held-out engagement sang training fold. Nếu một grouping gây test-history→train dependency xuyên fold, purge/reset theo session hoặc tách replay causal stream của fold, không dùng full-stream cache mù quáng. Tracker không fit vocab; vocab chỉ fit TRAIN sau split. Kiểm tra cap 10.000 processes/host, TTL24h, eviction/expired/missing/coverage theo host/EID/round; **chưa audit ATLAS**.

Context dropout: training-only trên replay và new TRAIN, deterministic theo RNG/checkpoint; mask nhóm parent/incoming, set availability0, giữ base event features. Core dùng một rate cố định được khóa trước run (proposal0.25, chỉ có hiệu lực khi whitelist được duyệt); grid `{0,0.25,0.5}` là tùy chọn sau core. Không dùng augmentation để lách TF của data-derived tokens. Zero-shot frozen model trên OpTC và ATLAS gồm context-observed và context-masked; phải khóa gate manifest **trước** cả zero-shot ATLAS VAL/TEST. Báo coverage, không gọi thiếu sensor là full context.

UNK-rate từng field/domain/split/round: trước và sau extend, tách UNK khỏi MISSING, denominator là số categorical observations; mở rộng chỉ theo TRAIN, encode VAL/TEST sau đó. Báo cả unseen token rate ML. Không fit từ thống kê VAL/TEST.

So sánh Bro-joined OpTC và Sysmon EID3 ATLAS: delta_t_log1p quantiles/histogram, zero/tied-timestamp fraction, time resolution, số events mỗi cửa sổ 900s và chunks/window, theo host/domain/split. Báo cả delta trước chunk và delta input đã reset ở chunk boundary; không lẫn các số 0 do reset với burst thực. Sample coverage/collection policy, duplicates và filtering được báo kèm. **Chưa audit**, không mặc định network connection event tương đương Bro flow.

Nhãn: không gán cả attack folder là positive. Kiểm chứng join REAPr process/node/edge→Sysmon event, thời gian hợp lệ của malicious process, match ambiguity và unknown. Không gán toàn bộ lifetime process là malicious nếu chỉ có node label mà chưa duyệt policy. CBC chỉ fallback khi Sysmon thiếu label linkage, không coi CBC có nhãn hoàn chỉnh mặc định. Báo counts và positive rate theo domain/round/split cho event, process, window/chunk; coverage=known-labeled/eligible, positive rate=positive/known-labeled; unknown tách riêng. OpTC red-team event/flow labels không đồng nghĩa ATLAS process-impact labels.

## 5. Thiết kế học tăng dần

### 5.1 BiLSTM, logit và critical path

P0 sử dụng **checkpoint subsetB đã có** tại `DL/05_models/bilstm_v2_subsetB/best_model.pt`; blocker thiếu/sai checkpoint được gỡ theo xác nhận người dùng và config4-field khớp notebook06d. Khóa hash weights/config/metrics, đối chiếu category maps/shards/fingerprint, tensor keys/shapes và inference bằng cơ chế load weights an toàn trước fine-tune. Không cần tìm checkpoint7-field hay chuyển đổi kiến trúc từ bundle cũ. Chưa kiểm tra tensor/inference trong lượt cập nhật tài liệu này.

**Không lập retrain/reproduced baseline làm bước mặc định nữa.** Dùng weights subsetB hiện có. Nếu P0 phát hiện lỗi integrity hoặc không khôi phục được đúng category mapping, báo lỗi cụ thể và xử lý bundle; không tự retrain thay thế. Category maps/shards vẫn cần đối chiếu độc lập vì có weights không bảo đảm đã đủ preprocessing assets. Giữ thứ tự LightGBM trước như kế hoạch đã chốt.

Mở rộng embedding: mỗi field có `emb_old` là registered buffer không train, `emb_new` là Parameter. Lookup old IDs vào buffer, new IDs remap `id-old_size`; giữ nguyên width từ checkpoint, không tính lại width theo cardinality mới. Giữ cả UNK/MISSING trong old buffer. Sang round sau, embeddings của vocab_{k-1} được snapshot thành old buffer; chỉ rows vừa thêm train theo stage A. Optimizer chỉ chứa trainable params; save/reload phải giữ mapping và stage.

Stage A train new rows+head, freeze event_encoder/LSTM; Stage B mở event_encoder/LSTM LR thấp hơn head, old rows vẫn buffer. Mặc định không mở old embedding rows, chỉ mở old neural modules. Frozen module có BatchNorm phải eval() để không đổi running stats; controller áp lại eval sau model.train(), freeze dropout khi yêu cầu deterministic frozen module. Model source hiện dùng LayerNorm; không giả định có BatchNorm. Test old rows bitwise bất biến qua AdamW/momentum steps.

**Stage C tùy chọn:** kiểm tra semantic drift của token quen thuộc (ví dụ powershell) bằng ablation mở old rows; không mặc định drift đã xảy ra. Chuyển emb_old từ frozen buffer sang Parameter bằng copy chính xác, IDs/width không đổi; optimizer param group riêng LR rất nhỏ (proposal1e-5 và thấp hơn Stage B), weight decay0 cho old rows, reset/record optimizer state khi chuyển stage. Checkpoint ghi stage/config/LR/RNG; test A/B old rows bất biến, C old rows chỉ thay khi explicitly enabled và nhận gradient. Reserved rows có freeze mask riêng mặc định. Chọn Stage C bằng retention VAL đã khóa, không TEST; giữ kết quả A/B làm main, báo ablation riêng. Điều kiện bật: core hoàn tất, tài nguyên đủ, protocol được khóa trước scoring ablation; không dùng Stage C để đổi prefix vocabulary.

Lưu raw logits trực tiếp trước sigmoid. Chọn threshold trên logit bằng VAL theo policy khóa trước; không inverse-logit từ probability đã làm tròn/bão hòa. DER++ lưu logits teacher tại lúc vào buffer, loss logits-consistency + supervised replay/new; không distill trên saturated probability. CSV predictions subsetB lưu probability, không có cột logit; tái inference để thu raw logits ở P0 sau phê duyệt, không phục hồi giả từ CSV. Giữ threshold xác suất subsetB **0.99560546875** cho đối chiếu metric lịch sử; calibration logit mới báo riêng. Lý do dùng logits vẫn có hiệu lực cho distillation/ranking precision, nhưng không còn viện dẫn T=1.0 là threshold của checkpoint hiện tại.

### 5.2 LightGBM chính: residual với extended schema

Giữ f0 frozen (300 cây theo receipt). Round k dùng `F_k(x)=f0(x[:N0])+sum_{j=1..k} g_j(x[:Nj])` trên **raw margins**, probability=sigmoid(F_k). Init_score train g_k là F_{k-1} trên TRAIN+replay. VAL cần base margin tương ứng để early stopping dựa trên total margin, không chỉ residual score. Khi infer/save/reload phải cộng toàn chain; init_score không tự được lưu thành thành phần inference. Version bundle lưu từng vocab prefix length và checkpoint hash.

Recompute ratio negative/positive trên TRAIN domain mới từng round; đồng thời ghi tỷ lệ replay và mixture sau sampling. Đề xuất class/domain sample weights tường minh, hoặc scale_pos_weight theo mixture với đối chứng ratio domain mới; không áp chồng class weights hai lần. Chỉ dùng TRAIN counts, không bê 30.00 OpTC sang ATLAS. Trường hợp không có positives không chia 0: no-go cho supervised round hoặc protocol benign-only riêng.

Budget đề xuất trước audit: tối đa 100 residual trees/round, tổng thêm ≤200 cây cho hai round chính; early stopping patience20 trên VAL total-margin AP, learning rate khởi điểm0.05. Đây là proposal, chưa tune. Nếu thêm round phải phân bổ lại tổng budget, không tăng không giới hạn. Fixed-schema init_model baseline dùng cùng budget tăng cây; early stopping validation tương đương. Frozen f0 cũng có thể được tính trên view context-masked khi dropout training; phải cộng base/residual nhất quán cùng view, ghi augmentation/inference policy.

Hai scratch controls khác nhau, không dùng cùng tên:

- **ATLAS-only scratch (core):** cùng extended vocab và ATLAS TRAIN, không OpTC replay, không pretrained weights. Đây là control thiếu prior examples, không gọi là matched-data với IL.
- **Scratch new TRAIN + buffer (core matched-data):** đúng sample IDs/multiplicity/weights của new TRAIN và buffer tại round k như IL, cùng vocab_k, không pretrained weights. Cùng model-size cap và training compute/step budget đã khai báo; không cấp toàn bộ lịch sử OpTC/ATLAS ngoài buffer. Reset scratch ở mỗi round, không warm-start rồi gọi scratch.

Cùng budget phải ghi hai trục: inference/model-size cap (ML gồm300 cây inherited+residual cap), training wall-time/optimizer steps/newly trained trees. Với ML không thể đồng thời coi300 cây pretrained là miễn phí compute và nói compute y hệt scratch: cap compute bằng nhau, báo số cây thực đạt và inherited cost riêng. Nếu tree-count cap và time cap không đồng thời đạt thì công bố, không claim exact equivalence. DL dùng architecture/maps/step cap và dữ liệu giống matched control; input có vocab prefix OpTC nên scratch weights không đồng nghĩa không dùng prior representation.

## 6. Replay, rounds, thống kê và go/no-go

Replay chỉ từ frozen OpTC TRAIN hoặc TRAIN round đã học; không lấy VAL/TEST, kể cả mẫu khó đã biết. Phân tầng domain × label × scenario SC1/2/3 (nếu có annotation hợp lệ) × app_family; multi-app chunk dùng signature/primary-app rule cố định, không duplicate vượt budget. Quota hiếm, reservoir deterministic và hard-sample quota giới hạn để không bỏ hết background. Hardness từ lỗi/logit/entropy của TRAIN model hoặc proxy contamination ở TRAIN, không từ held-out labels/predictions.

Giữ nguyên chunks/masks/delta cho DL, causal context snapshots cho ML. Cửa sổ firefox 1.800 flow và case REJ trong báo cáo là **TEST**, tuyệt đối không chuyển chúng vào replay. Chỉ ưu tiên mẫu TRAIN tương tự. REJ dùng audit-only metadata của OpTC khi có; không thêm conn_state vào DL active fields, không bịa REJ cho Sysmon. Buffer cap chính theo số events (ML)/chunks (DL), secondary byte/token caps; raw replay theo A.10 bắt buộc. Không thể chỉ giữ ID/vector cũ. Log quota/ratio và kích thước raw+context+provenance/logits.

### Replay budgets và quota positives

P0 chỉ đọc shards/index: đo compressed bytes/event ML và bytes/chunk DL theo shard/label/scenario, overhead metadata, quantiles; đồng thời đo/ước lượng có xác minh raw+context/raw-category replay payload và peak decoded RAM trên bounded sample khi được phép. Báo hai con số riêng, không lấy compressed shard bytes làm resident RAM hoặc re-encodable buffer bytes. Đếm **số positive TRAIN OpTC thật** của từng nhánh, số unique windows/SC/app; chưa audit, không suy từ train_pos_weight hay TEST82.

Sau số đo, đề xuất ba caps nhỏ/vừa/lớn theo N_event/N_chunk và secondary GiB/output/peak RAM; medium là main, nhỏ/lớn là sensitivity theo ngân sách. Chưa gán số cụ thể khi chưa đo. Khóa caps/quota trong run manifest trước training; giữ cap qua rounds. Positive quota riêng giữ phần lớn positives, DL có thể gần hết positive TRAIN nếu cap cho phép; negatives chịu phần lớn reduction. Nếu không đủ cap thì stratified positive sampling có receipt, không vượt budget ngầm. SC/app/domain/hard sampling vẫn TRAIN-only; không trộn sample khó TEST vào buffer. Test báo prior tự nhiên; không balance/oversample holdout. Các levels có cùng chính sách, nested memberships khi khả thi; logits phụ DER++ được tính vào cap nếu bật.

### Rounds và split cố định

Ít nhất2 round **chỉ chia phần TRAIN ATLAS** thành R1, R2 theo thời gian/engagement thật. Một VAL_ATLAS và một TEST_ATLAS cố định qua tất cả rounds; khóa sample/group IDs và hash. Mỗi group (cả hai host multihost) chỉ thuộc một partition; near-duplicate attack chains gom trước split. Không dùng thứ tự tên file giả chronology. Fit vocab_k chỉ từ TRAIN_Rk; transform holdouts bằng vocab_k được phép, nhưng không lấy thống kê holdout để admit tokens. Model selection dùng cùng VAL đã quy định; TEST chỉ reporting, không quyết định lịch/stage/hyperparams. Ghi việc tái dùng VAL có thể gây adaptive overfitting và giới hạn search budget.

Nếu không đủ independent groups cho split này thì descriptive-only; grouped CV/LOEO là tùy chọn phân tích bổ sung, reset model/vocab/buffer mỗi fold. Không nối folds thành incremental rounds, không bỏ gate chỉ vì CV. Baseline/model scoring trên holdout (kể cả rules/zero-shot) chỉ sau gate lock.

### Gate cho cả hai nhánh và manifest trước scoring

P1 audit label/group counts trước scoring; P0 self-bootstrap **chỉ baseline OpTC**, không dùng ATLAS, để xem độ dao động AP và đề xuất margin cuối. Khóa `evaluation_gate_manifest.json` (artifact tương lai) trước **bất kỳ model nào** trên ATLAS VAL/TEST: split/group hashes, round definitions, group/chunk floors, counting unit, AP estimator, bootstrap clusters/repeats/seed, confidence level, retention margin mỗi nhánh, baseline identity, handling degenerate CI, search budget và policy pass/fail. Timestamp/version/hash; sửa sau lock phải ghi lý do, before/after, model/score exposure và nhãn **post-hoc**. Không trình kết quả post-hoc như confirmatory của protocol gốc.

Proposal đã được chấp nhận tạm: mỗi VAL và TEST ≥3 positive independent engagement groups; mỗi TRAIN round ≥1 positive group; mỗi holdout ≥30 positive và ≥30 negative chunks DL. **Cả LightGBM và BiLSTM** phải qua gate group độc lập; ML báo thêm counts event/label theo fixed host×900s blocks và ≥30 positive/negative blocks để tránh coi hàng triệu events là evidence độc lập. Chunk512 là đơn vị DL; không tạo sequence ML giả rồi gọi là ML training unit. Quy ước block/chunk của từng branch và floors được khóa trước scoring. Đếm groups sau label/coverage eligibility của từng nhánh, không mượn group có nhãn ở sensor khác để đủ gate. Đây là gate vận hành, không power analysis; 3 groups vẫn ít, cần nêu giới hạn.

**8 groups tối thiểu** =3 VAL cố định +3 TEST cố định +1 TRAIN_R1 +1 TRAIN_R2, không phải3+3 ở mỗi round. Tất cả8 là positive groups độc lập, mutually disjoint; không đếm hai host cùng engagement hay hai attack chains near-duplicate thành hai nhóm. Với r rounds mỗi round có ≥1 positive group, sàn là6+r. Sàn nhóm không tự bảo đảm đủ chunks, coverage hay CI. Group counts thực **chưa audit**.

Phân loại evidence cho từng branch: pass gate đã khóa→**confirmatory** trong phạm vi giả thuyết/protocol đăng ký; fail/không xác định→**descriptive-only**. Group insufficiency áp dụng cho cả ML lẫn DL, không được cứu ML bằng event count lớn. Retention pass/fail là **kết quả giả thuyết**, không được hạ kết quả retention fail thành descriptive để che một confirmatory negative result: run đủ evidence vẫn báo confirmatory, retention không đạt. Nếu CI không ước lượng đáng tin hoặc điều kiện evidence fail thì descriptive-only. Manifest tách `evidence_gate_status` và `retention_outcome` rõ ràng.

Retention proposals: DL upper95%CI(AP_drop)≤0.01; ML≤0.002. P0 self-bootstrap baseline trên OpTC VAL: resample độc lập theo cluster hợp lệ, xem phân phối AP_b và |AP_b−AP_baseline|, không so cùng predictions trên cùng bootstrap samples rồi lấy delta0 làm noise estimate. Không ATLAS, không incremental models. Baseline VAL AP=1 có thể cho degenerate bootstrap; báo limitation, không suy ra variance0 ngoài sample. Nếu không đủ bằng chứng, giữ margins tạm kèm giới hạn hoặc xin xác nhận trước lock, không dùng ATLAS để nới margin. ML historical PR-AUC≈0.9993 là binned estimate, phải tính AP baseline cùng estimator trước so retention; không coi hai estimator bằng nhau. Quyết định final margin lưu rationale/noise summary; **self-bootstrap chưa chạy, margins chưa chốt theo số đo**.

Metric chính chống forgetting: **AP (average precision, gọi rõ là quy ước PR-AUC ở đây) trên raw margins/logits**, kèm paired cluster-bootstrap 95% CI của AP và delta AP. Cùng resampled groups cho baseline/round, phân tầng hợp lý để giữ cả hai nhãn; ghi số lần bootstrap invalid/degenerate. ATLAS cluster ở engagement; OpTC báo host/session/window hierarchy và scenario-specific results, không coi 82 chunks là 82 engagements độc lập. Thực hiện cả **VAL OpTC** để chọn stage và TEST OpTC chỉ báo cáo; F1 là metric phụ, không dùng delta F1 định nghĩa forgetting.

Forgetting domain d ở round k: max AP các round trước − AP hiện tại, kèm paired CI với reference đã nêu; BWT từ AP matrix. Không lấy thay đổi prior giữa datasets làm forgetting. Ceiling AP=1 và bootstrap CI hẹp/degenerate không chứng minh tổng quát tốt. Retention trên OpTC VAL dùng margin theo nhánh đã khóa (proposal DL0.01, ML0.002); TEST OpTC dùng để báo cáo, không chọn model. CI rộng/không xác định không mặc định pass; cần tách evidence insufficiency khỏi model retention failure như gate ở trên.

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
| P0 | baseline manifest/hashes, S3 count unit, bytes/event/chunk/raw replay, positive TRAIN counts, baseline-only self-bootstrap | thống nhất maps/inference; đề xuất3 replay caps và final branch margins trước ATLAS scoring |
| P1 | Sysmon/REAPr audit, EID8/10/GUID, UNK, delta/density, eviction, independent groups | evidence gate cả ML/DL; lock gate manifest trước mọi ATLAS VAL/TEST scoring |
| P2 | Sysmon adapter, causal snapshots, VAL/TEST cố định, TRAIN group/time split + ≥2 round manifests | primary source/label grain cố định; no duplicates/window overlap/future state; dataset read-only |
| P3 | vocab/category extension, sidecars, replay | A.7: per-entry prefix hashes, OpTC bitwise old columns+old predictions, train-only/no-future; raw replay re-encode new tokens/IDs đúng; policy exception tests; increased-column compatibility; baseline hashes nguyên vẹn |
| P4 | LightGBM residual trước; DL sau checkpoint gate | raw-margin composition/reload đúng, weights/class ratio/tree cap; emb_old buffer bất biến, emb_new train, freeze/eval đúng |
| P5 | smoke tests fixture/subset, lỗi→sửa→test lại | labels/direction/PID reuse/order/eviction, split leakage, logits/threshold, optimizer freeze, resume đều qua; không dùng smoke metrics làm kết luận |
| P6 | Kaggle package và ≥2-round hoặc grouped-evaluation report | AP+cluster CI/forgetting trên VAL/TEST từng domain, rules/scratch/context ablations, coverage/cost/budget, limitations |

Source tương lai: `IL/dataset_1-ATLASv2/{preprocess,model,test,notebook,docs}/`; mọi generated artifact dưới `IL/dataset_1-ATLASv2/output/`. Resolve/reject outputs trong DATASET và dataset roots/symlinks; streaming tar thay vì decompress in-place, quota staging, atomic publish/resume. Không full local training. Bản v3 chỉ là tài liệu, không tạo vocab/model/output experiment.

### CỐT LÕI — lộ trình tối thiểu

1. P0, P1 Sysmon và label/coverage/evidence gates; khóa manifest, resource caps, whitelist chỉ nếu đã duyệt.
2. P2/P3 causal snapshots, fixed holdouts/≥2 TRAIN rounds, append-only vocab/maps, re-encodable replay và tests.
3. LightGBM residual+replay, rồi BiLSTM Stage A/B+replay; medium buffer chính, một seed tái lập, frozen-row protocol mặc định. Context dropout một rate cố định nếu policy whitelist được duyệt; không chờ grid tuning.
4. Controls tối thiểu: frozen (context-observed/masked khi áp dụng), new-only (cùng adaptation architecture nhưng không replay), ATLAS-only scratch, matched-data scratch(new TRAIN+buffer), luật powershell/temp theo đơn vị đánh giá từng nhánh. Không dùng luật chunk làm event-level ML metric nếu chưa định nghĩa aggregation/labels; ML rules dựa event/causal evidence tại query, DL rules trên completed chunk.
5. P5/P6 resume/smoke và báo cáo AP/CI/retention/coverage/cost từng round; fail evidence gate vẫn có descriptive report, không claim confirmatory.

### TÙY CHỌN — không chặn hoàn thành core

| Mục | Điều kiện kích hoạt / giới hạn |
|---|---|
| Replay small/large sensitivity | P0 đã đo, medium core chạy được, quota đủ; giữ split/gate, chỉ thay cap, báo không chạy nếu thiếu tài nguyên |
| Grid context dropout | whitelist duyệt, core hoàn tất, VAL search budget định trước và còn compute; không chọn bằng TEST |
| DER++ | core xong, raw logits teacher đúng, storage/compute cho logits đủ; thêm distillation ablation, threshold vẫn logit |
| Stage C old-row unfreeze | protocol riêng mục5.1 khóa trước ablation, core xong, đủ compute; gate retention giữ nguyên |
| TF2 DL sensitivity | TF5 main đã khóa; suffix lineage riêng; chỉ VAL chọn, không sửa prefix/main vocab |
| Nhiều seed | seed chính hoàn tất và quota đủ; giữ split/vocab policy, không chọn seed tốt nhất từ TEST |
| Scratch phụ / fixed-schema init_model / refit | core controls xong, compute đủ; ngân sách và giả thuyết ablation khai báo; fixed-schema vẫn là baseline compatibility P3 dù chưa chạy full training |
| CBC fallback | P1 chứng minh thiếu Sysmon label linkage, CBC khắc phục được, protocol mapping/coverage được duyệt; namespace/split/gate version riêng, không trộn sensor để lấp gate |
| Grouped CV/LOEO | single fixed-split evidence yếu, có quota và independent grouping khả thi; supplementary, không thay ≥2-round core bằng fold sequence giả |

### Kaggle resource envelope và resume

Thông tin người dùng để placeholder, **chưa có dữ liệu**: GPU=T4x2/P100 chưa chọn; quota giờ/tuần, giờ/phiên, output GB chưa điền. Không tự giả định có2 GPU hay tổng VRAM gộp. Khóa sau P0 profile: max_session_hours, remaining_weekly_hours, max_output_bytes, memory/headroom và replay caps. Single-GPU baseline trước; multi-GPU tùy tài nguyên/verification, không bắt buộc.

Chia job theo preprocessing shards/round/stage/boosting batches; admission kiểm tra runtime ước lượng+checkpoint safety reserve < session limit và output<quota trước launch. Checkpoint atomic định kỳ và trước deadline, lưu vocab/maps, replay membership/raw references, optimizer/scheduler/stage/RNG, booster chain, progress và hashes. Resume không refit vocab từ VAL hay lặp samples ngoài policy; verify full-run vs interrupted-run theo tolerance đã định. Ưu tiên medium/core, hoãn optionals khi quota thiếu. Có thể một experiment gồm nhiều phiên resume, nhưng **mỗi invocation** phải nằm trong session cap. Chưa đo throughput/bytes nên chưa cam kết số phút/GiB hoặc chạy vừa quota cụ thể.

## 9. Tài liệu nền tảng

Giữ định hướng paper v1: iCaRL (CVPR2017), End-to-End Incremental Learning (ECCV2018) cho exemplar/distillation; DER/DER++ (NeurIPS2020) cho replay logits; ULMFiT (ACL2018) cho gradual unfreezing (không tự là bằng chứng continual learning); MalFSCIL/TIFS và Wazuh/IEEE Access là related work khác setting. Không tự gán rank A*/Q1 chưa xác minh. Liên kết nguồn đã đối chiếu ở v1:

- DER: https://proceedings.neurips.cc/paper/2020/hash/b704ea2c39778f07c617f6b7ce480e9e-Abstract.html
- ULMFiT: https://aclanthology.org/P18-1031/
- iCaRL: https://openaccess.thecvf.com/content_cvpr_2017/html/Rebuffi_iCaRL_Incremental_Classifier_CVPR_2017_paper.html
- End-to-End: https://openaccess.thecvf.com/content_ECCV_2018/html/Francisco_M._Castro_End-to-End_Incremental_Learning_ECCV_2018_paper.html
- Dataset/ground-truth interpretation: local `DATASET/ATLASv2/atlasv2/README.md`, `DATASET/ATLASv2/reapr-ground-truth/atlasv2/README.md`; ATLASv2 arXiv description không gọi là proceedings peer-reviewed.

## 10. Trạng thái quyết định review v3

“Đã áp dụng” là cập nhật kế hoạch, không phải đã chạy. Mọi audit/test tương lai chưa thực hiện.

| Mục | Trạng thái | Ghi chú |
|---|---|---|
| Gate1a: lock/post-hoc | đã áp dụng | manifest trước mọi ATLAS VAL/TEST scoring |
| Gate1b: hai nhánh | đã áp dụng | evidence confirmatory/descriptive-only cả ML/DL; retention outcome riêng |
| Gate1c: branch margins | cần thêm dữ liệu | DL0.01/ML0.002 tạm, baseline-only self-bootstrap chưa audit |
| Fixed holdouts /8 groups | đã áp dụng |3+3+1+1, chỉ TRAIN chia round |
| Category2 | đã áp dụng | new DL TF5, ML TF2; flow-count source đã đọc, artifact recount chưa audit; TF2 option |
| Replay3: caps/positives | cần thêm dữ liệu | bytes/event/chunk/raw payload và positive TRAIN counts chưa audit; medium main |
| Replay3: scratch | đã áp dụng | matched new+buffer core, ATLAS-only riêng |
| Replay3: Kaggle | cần thêm dữ liệu | các placeholders chưa có giá trị; runtime admission/resume đã thiết kế |
| A: re-encode | đã áp dụng | raw+context/raw categories, P3 new-column/old-column tests |
| B: policy whitelist | cần thêm dữ liệu | đã thiết kế ngoại lệ explicit, chờ thầy xác nhận, chưa bật |
| C: Stage C | đã áp dụng | optional Parameter old rows, LR nhỏ, mặc định tắt |
| D: core/optional | đã áp dụng | activation conditions từng option |
| E: README proposals | đã áp dụng | file riêng vị trí/câu thay thế, không sửa README |

Không bác bỏ quyết định nào; làm rõ hai điểm kỹ thuật: S3 historical threshold không đồng nhất mọi field, và ATLAS-only không thể đồng thời là scratch có replay. Hai controls được tách để đáp ứng cả hai yêu cầu.

## 11. Câu hỏi mở còn lại (tối đa3)

1. Thầy có xác nhận ngoại lệ whitelist sáu availability tokens theo policy (mụcA.9), bỏ điều kiện TF nhưng giữ prefix bất biến, không dùng nhãn/VAL/TEST không?
2. Kaggle thực tế dùng T4x2 hay P100, còn bao nhiêu giờ/tuần, tối đa bao nhiêu giờ/phiên và output bao nhiêu GB? Cần đủ bốn giá trị trước chốt resource manifest/chạy.

Không hỏi lại gate tạm, TF5 hay GiB cứng đã quyết định. Bytes/counts/group coverage/self-bootstrap là nhiệm vụ P0/P1 **chưa audit**, chưa cần người dùng tự cung cấp. Giữ nguyên v1/v2, baseline, README; chỉ tạo hai tài liệu v3 và corrections proposed.
