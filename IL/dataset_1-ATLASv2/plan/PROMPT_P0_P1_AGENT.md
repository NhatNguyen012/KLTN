# Prompt giao AI Agent triển khai P0/P1 — dừng trước P2

Bạn là AI Agent triển khai audit trong workspace `/mnt/SSD_Data/optc`. Người dùng đã duyệt plan; một assistant khác sẽ review báo cáo, code diff và bằng chứng của bạn. **Hãy triển khai và thực hiện phần được phép, không chỉ đề xuất cách làm.** Không cần xin lại phép cho P0/P1 trong phạm vi này; cần dừng nếu bước phụ thuộc thiếu thông tin không thể suy ra an toàn.

## 1. Nguồn chỉ dẫn và phạm vi

Đọc `AGENTS.md`, rồi:

1. `IL/dataset_1-ATLASv2/plan/PLAN_REVIEW_v3.md` — plan chính thức.
2. `IL/dataset_1-ATLASv2/plan/PLAN_ADDENDUM_v3_1.md` — phê duyệt mới, ưu tiên khi khác v3.
3. `ML/code/README.md`, `DL/README.md`, code/metadata liên quan; README có sai lệch đã ghi trong `plan/README_CORRECTIONS_PROPOSED.md`, không sửa chúng. Root `MENU.md` từng không tồn tại; tìm map hiện hữu phù hợp thay vì coi đường dẫn lịch sử là hiện hành.

Thực hiện **P0 và P1**, chỉ đọc inputs. Được viết audit code/tests và kết quả mới **chỉ dưới OUTPUT_ROOT**. Không sửa source baseline hoặc plan chính thức. Không training/fine-tune, không tạo bộ model input huấn luyện mới, không publish extended vocab/category maps, không tạo split chính thức, không bắt đầu P2/P3. Không score model/rule nào trên ATLAS (đặc biệt VAL/TEST); baseline inference chỉ OpTC. Không tự khởi chạy notebook/Kaggle, upload hoặc liên hệ bên ngoài.

## 2. Ranh giới I/O bắt buộc

OUTPUT_ROOT=`/mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/output/`.

- Trước writer đầu tiên, resolve absolute paths và kiểm tra toàn bộ parent chain/output root. Reject destination trỏ ra ngoài OUTPUT_ROOT hoặc qua symlink vào dataset/baseline/README/source. Existing output symlink phải được kiểm tra; không overwrite file người dùng đã có. Input symlink có thể đọc sau resolve và ghi provenance, không biến thành writable output.
- Không ghi bất cứ thứ gì vào `DATASET/`, các read-only roots trong AGENTS, `ML/code/output/`, `DL/05_models/`, OpTC shards, source/README/paper. Không chmod/touch/decompress in-place. Hash trước/sau các protected artifacts được sử dụng; không quét hash toàn corpus nhiều TB nếu không cần. Ghi rõ mức coverage của integrity check, không tuyên bố đã hash toàn dataset.
- Redirect cả Python bytecode, temp, matplotlib/torch caches và tool logs vào output run directory; tránh import side effects ghi vào source. Không tự cài package vào workspace/system; kiểm tra môi trường, dùng thư viện sẵn có hoặc báo blocker. Không dùng credential/account data ngoài nhu cầu này.
- Tar ATLAS dùng streaming; không extractall. Staging nếu thật cần: chỉ regular files cần thiết, reject absolute/traversal paths, tar links/devices; quota cap khai báo, không bung toàn corpus. Có manifest ownership để cleanup chỉ files do run này tạo.
- Gợi ý layout: `output/p0_p1_audit/<run_id>/{audit_code,tests,manifests,reports,logs,staging,cache}`. Output session cap đề xuất20.000.000.000 bytes, lưu safety reserve; monitor bytes và disk free trước/giữa các batch. Không xóa unrelated files để đủ chỗ.
- Code deterministic, bounded, không thực thi telemetry commands/decoded payloads. JSON/XML parsing không external entity resolution. REAPr graph pickle không được unpickle tùy tiện: ưu tiên text labels/metadata; nếu chỉ có serialized executable format, báo blocker hoặc dùng cơ chế an toàn đã được kiểm chứng, không bypass mặc định.
- Atomic publication/checkpoint, validate resume bằng source/config/code hashes, progress offset/member identity. Update tiến độ ngắn khi scan lâu; không launch daemon không có ownership/stop mechanism.

## 3. P0 — baseline identity, replay measurements, uncertainty

### 3.1 Inventory và LightGBM OpTC-only inference

Candidate active baseline:

- `ML/code/output/host_ml_parent_incoming_seed02/vocab.json`: JSON token→column,10.317 entries, SHA-256 `2e4a6239dc94f46cc05f1aff0b955e28fc271a4d5384bfcc20921ab7fdf4c913`.
- `.../kaggle_output/lgbm_kaggle_results/results/model/latest.json` và `lgbm_metrics.json` trỏ `model-slot-1.txt`; library4.6.0,300 rounds. Đọc receipt và kiểm tra hash file thực, feature count/order, best_iteration/score convention.
- Frozen split seed02 ở `ML/code/output/host_ml_seed02/split/`; không rebuild. Model sampling seed1 là riêng split seed2.

Lập manifest paths thực/hashes/shapes/version/config/split/sample IDs, tồn tại/missing, source identity. Trước inference phải hiểu runtime preprocessing, sampling và checkpoint selection. Inference trên OpTC shard/sample có membership xác minh; nếu có predictions gốc ghép đúng row IDs để so sánh. Nếu chỉ aggregate metrics, không gọi aggregate agreement là bitwise identity: báo mức bằng chứng, tolerance, CPU threads/version và binned-vs-exact AP khác biệt. Không ghi đè predictions cũ. Không nhầm tokenizer tokens với dense ordinal features.

Đối chiếu receipt undersampling: full TRAIN6.248.443, sampled6.248.110, positives201.551, negatives giảm333; weight30.000143884178197 tính sau sampling. Nếu source mới khác hãy báo discrepancy, không sửa artifact cho khớp số. Membership333 chưa kiểm chứng không được coi đã xác nhận chỉ bằng số tổng.

### 3.2 BiLSTM safe checkpoint inspection

Baseline người dùng xác nhận:

`DL/05_models/bilstm_v2_subsetB/best_model.pt`, SHA-256 `1304901f46c4a559b47f1e6892fe8f558f92f19e0b77755add6dcb440755da77`.

Config4 fields: app_family/proto/resp_port_class/image_dir_class, cardinalities61/4/11/10, numeric0, seed42, event_dim64, hidden_dim64,1 LSTM layer. Threshold probability0.99560546875; không phải1.0. Đọc config/threshold/metrics/fingerprint, không suy đúng chỉ từ tên file.

Load bằng `torch.load(..., map_location='cpu', weights_only=True)` khi runtime hỗ trợ; không fallback `weights_only=False`, không auto allowlist arbitrary classes. Nếu safe load không được, ghi lỗi và dừng phần phụ thuộc. Báo tensor keys/shapes/dtypes, embedding widths, encoder input shape, architecture fit. Không train/optimizer step.

Đối chiếu category map export và S3 spec/source với đúng fingerprint, giữ reserved IDs. S3 source count(*) trên TRAIN flows: train_count đơn vị flow, app_family/service threshold5, others default1; v3 policy new categories tất cả4 active fields TF5, old IDs không sửa. Phải xác minh asset thực trước encode/inference; không tự refit maps. Nếu cần model wrapper cho OpTC inference, viết bản audit riêng dưới output, không execute toàn notebook (notebook có training/mutations).

### 3.3 Replay/storage measurement

- Đọc shard manifests và payload schema, xác minh số rows/labels với checksums/sample/full coverage công bố. ML bytes/event, DL bytes/chunk: compressed disk, metadata overhead, decoded memory riêng; báo phân phối theo shard và class/group nếu có thể, không lấy file-size trung bình làm peak RAM.
- Đếm positive TRAIN OpTC thật từng nhánh, SC1/2/3 và app_family, unique windows/chunks/events; không suy positive TRAIN từ test82 hoặc train_pos_weight. Nếu thiếu data, báo manifest counts vs payload-verified counts riêng.
- Replay phải re-encodable: ML raw record+causal context snapshot; DL raw category values+order/time/chunk boundaries/masks. Chỉ đọc để đo/kiểm tra khả năng khôi phục trên bounded sample; chưa build production replay buffer. Nếu raw context không tồn tại, báo effort/blocked recovery; vector/UNK cũ không đủ để xác định new token presence.
- Đề xuất3 caps nhỏ/vừa/lớn theo count events/chunks sau đo, medium main; secondary byte/RAM caps có tính raw/context/provenance/logits optional. Positive quota riêng giữ phần lớn, DL gần hết positives nếu đo thấy khả thi; negatives giảm nhiều hơn, SC/app/hard strata. Báo assumptions và bytes estimate confidence; không tự chốt budget chính thức.

### 3.4 Self-bootstrap baseline OpTC

Không dùng ATLAS, không incremental model. Chỉ baseline OpTC VAL để calibration margins; TEST chỉ baseline reporting nếu cần, không chọn margins bằng TEST. Thu raw margins/logits qua inference khi predictions cũ bị sigmoid saturation hoặc không đủ precision; thiếu maps/shards thì báo blocked, không dùng inverse-logit của probability1 để tạo logits giả.

AP estimator nhất quán, không trộn binned PR-AUC≈0.9993 với exact AP. Cluster unit hợp lệ theo host/session/window và dependence đã mô tả; lưu seed, replicate count, cluster counts, stratification, invalid replicates và bootstrap method. Đo AP_b variability / |AP_b−AP_base|; so cùng predictions trên cùng resample rồi ra delta0 không phải noise estimate. AP=1 degenerate bootstrap phải báo, không khẳng định generalization uncertainty0.

Đề xuất margin cuối mỗi nhánh dựa uncertainty + practical tolerance và giới hạn của self-bootstrap; proposal ban đầu DL0.01/ML0.002. Không tự khóa final gate hoặc nới margin theo ATLAS scores. Bootstrap không đủ dữ liệu thì giữ tạm/không kết luận, ghi “chưa audit” phần thiếu.

## 4. P1 — Sysmon/REAPr/ATLAS chỉ audit, không scoring

### 4.1 Inventory, coverage, semantics

Stream `DATASET/ATLASv2/atlasv2.tar.gz`, đọc README/REAPr labels và text attack descriptions. Inventory members/bytes/sensor/host/session/time ranges. Report full-scan hoặc sample coverage rõ ràng. Lập audit mapping, không tạo adapter/pipeline P2 production.

- Sysmon primary: EID3/8/10 counts theo host/engagement; parent/source/target process GUID presence, parse validity, linkability, chronological resolution và denominators. Phân biệt unavailable, unknown, available-but-no-event; không suy sensor disabled chỉ từ zero observed EID.
- UTC/time resolution, event ordering, PID reuse, session/reset boundaries; EID3 protocol/port/direction/Image availability, duplicates. Không gán remote port luôn responder port. EID8/10 parent/incoming semantics phải đúng.
- Tracker audit: frozen code/config cap10.000 processes/host, TTL24h; chạy audit-only causal replay trên stream phù hợp nếu nguồn đủ, query-before-update và strictly-past, không labels/future evidence. Snapshot/profiling tạm dưới output, không publish features P2. Giữa independent sessions/folds reset state; không train contamination từ held-out state. Báo eviction/TTL/missing và effects theo branch/host. Nếu mapping chưa đủ chính xác chỉ báo potential coverage, không giả danh tracker measurement.
- Label mapping REAPr process/node/edge→event/flow/window: known positive/negative/unknown, timestamp bounds, ambiguity, granularity. Attack folder có benign; unmatched không mặc định negative. IP bị implicate nhầm không tự propagate labels. Báo coverage và positive rates từng domain/branch/unit với denominator.
- Compare OpTC Bro-joined với ATLAS EID3: delta_t_log1p quantiles/histograms, tied/zero timestamps, raw-vs-chunk-reset zeros, events/900s window, chunks/window và source coverage. UNK/MISSING theo4 fields/domain, baseline maps read-only; extended-map effect chỉ candidate projection, không publish/refit maps hoặc lấy holdout vào admission.

### 4.2 Groups, fixed holdouts và gate feasibility

Independent group không đồng nghĩa tên scenario/file: dùng attack descriptions/causal chains/shared episodes để gom near-duplicates, giữ cả2 hosts multihost cùng group. Báo grouping rule, membership, evidence, uncertain assignments và sensitivity conservative grouping; không gộp/tách để đủ8 groups. Count trước/sau gộp và sau label eligibility **riêng ML/DL**.

P2 chưa được phép. Nếu chưa có split/round manifest được duyệt, **không gọi split audit proposal là TRAIN/VAL/TEST chính thức**. Có thể tạo audit-only membership proposal dưới reports với status provisional, không publish vào pipeline, không fit artifacts. Ghi fixed VAL/TEST, chỉ TRAIN partition chia≥2 rounds theo thời gian; provenance/no-overlap, label eligibility và temporal availability. Nếu không đủ dữ liệu để đề xuất, ghi chưa audit; không tự chọn record assignments bằng model scores.

Với mỗi proposal, bảng branch×partition×round: independent positive groups, negative groups nếu định nghĩa được, known/unknown events, positive/negative windows, DL chunks≤512, ML host×900s blocks; nêu chunk-label policy/proxy nếu event labels chưa được xác nhận. Proposed fixed holdouts không nhân số groups qua rounds. Sàn6+r: r=2 cần3VAL+3TEST+1TRAIN_R1+1TRAIN_R2=8 mutually independent positive groups; số groups không thay bằng event count.

Kết luận gate dự kiến mỗi nhánh: **qua / có nguy cơ / không qua**, kèm reason/unknowns. “Qua” mới là structural feasibility, không chứng nhận confirmatory hay retention pass vì gate manifest chưa khóa và chưa model ATLAS scoring. Missing evidence không được coi pass. Floors v3: ≥3 positive groups mỗi holdout, ≥1 mỗi TRAIN round, ≥30 positive/negative DL chunks hoặc ML blocks theo definition đã nêu; report uncertainty của nhóm độc lập quá ít.

### 4.3 Candidate token/category diversity — bổ sung bắt buộc

Chỉ trên TRAIN membership đã xác định; nếu membership audit-only thì mọi số ghi rõ **conditional on proposal_id**, chưa là TRAIN chính thức. Không dùng holdout/future rounds để tính TF hoặc distinct support. Không dùng toàn corpus làm TRAIN tạm.

ML dùng frozen tokenizer + causal snapshot và so baseline vocab; DL raw canonical values4 fields so old maps. TF ML2, new DL5 (flow/event occurrences, không chunks); không đổi rule vì diversity thấp. Whitelist6 tokens đã duyệt là policy-origin, báo tách data-derived candidates, không đưa vào thống kê singleton memorization như learned tokens.

Sidecar per candidate: branch/field/token-or-value, old-vocab membership, current proposed round, TF/DF nếu phù hợp, **distinct_hosts, distinct_windows, distinct_engagements**, admission eligibility, source/membership hashes, normalization policy. ML event window=floor(UTCseconds/900) cùng host; distinct engagement theo IDs có provenance, báo cả raw IDs và independent-group support khi grouping hợp nhất. Unknown engagement không tính như một group đã xác minh.

Báo số/tỷ lệ new candidates và admission-eligible candidates chỉ ở **một engagement**, số chỉ ở một independent group sau gộp, TF-weighted share và examples đã mask dynamic/private literals theo policy. Không tự prune/token-filter bằng host/window/engagement support; đây là diagnostic. Không publish `vocab_ext_round*.json` hay category-map suffix. Thiếu raw records/context/TRAIN membership thì báo chưa audit và lý do, không dựng candidates từ old sparse columns.

## 5. Resource constraints và validation audit code

T4x2,60 giờ/tuần đã xác nhận cho thiết kế Kaggle; mặc định1 GPU, không gộp VRAM. ML CPU; GPU chỉ DL nếu inference được phép và môi trường có sẵn. Chưa được launch training. Phiên9h/output20GB là **giả định**, không quota account đã xác minh. P0/P1 local scan cũng phải bounded/resumable theo envelope được khai báo, không tự dùng hết9h mà không cập nhật người dùng. Không download Kaggle assets/account nếu chưa có access/task authorization cụ thể; báo thiếu asset.

Viết focused tests cho audit implementation dưới output: path/symlink boundary, tar traversal, malformed parsing, safe-load behavior, train-only candidate counters, distinct support counts, causal snapshot, grouping no-overlap, resume identity và bootstrap sanity. Dùng synthetic fixtures, không training. Chạy tests liên quan rồi audit; ghi exact commands/versions/exit status. Không sửa baseline code để tests pass, không fabricate metric từ fixture. Nếu scan dài, checkpoint/resume với coverage và unfinished work rõ ràng.

## 6. Handoff bắt buộc cho reviewer và điểm dừng

Các artifacts đề xuất trong run directory (tên có thể tương đương nhưng phải index được):

- `manifests/run_manifest.json`: scope, authorization, input identities, code hashes, versions, seed, limits, timestamps, statuses.
- `manifests/baseline_manifest.json`, protected hash before/after và boundary report.
- `reports/P0_BASELINE_AUDIT.md`, tensor-shapes table, inference identity comparison, shard/replay measurements, positive TRAIN counts, bootstrap config/results/margin proposal.
- `reports/P1_ATLAS_AUDIT.md`, inventory/coverage/EID/GUID/label tables, grouping membership/evidence, provisional split/round feasibility tables, candidate support sidecar, delta/UNK reports.
- `reports/P0_P1_REVIEW_HANDOFF.md`: exact commands, code files/diffs, test outputs, full vs sample coverage, assumptions, blockers/unknowns, source links/line/member offsets để reviewer tái kiểm tra.
- `reports/DECISIONS_REQUIRED.md`: những quyết định thực sự còn cần, không hỏi lại whitelist hoặc TF5 đã chốt.

Final response phải có:

1. Bảng group/window/chunk/block theo branch/split/round và gate dự kiến qua/có nguy cơ/không qua; phân biệt confirmed vs conditional/provisional.
2. EID8/10 và GUID/parent coverage với numerators/denominators.
3. Replay measured bytes/counts, positive quota và3 caps đề xuất nhỏ/vừa/lớn, medium main, RAM/disk assumptions.
4. Margin ML/DL đề xuất từ self-bootstrap chỉ baseline OpTC; uncertainty/degenerate CI nếu có.
5. Issues, chưa audit, tests passed/failed, artifact links và statement không score ATLAS/không training/không P2.

**DỪNG SAU P1.** Không tự sửa plan v3, README, model/split/vocab; không tự approve gate/P2. Nếu thiếu inputs chỉ hoàn thành phần độc lập trong P0/P1 rồi bàn giao blocker, không bịa báo cáo đầy đủ. Reviewer sẽ kiểm tra bằng chứng, người dùng quyết định bước tiếp theo.
