# Review implementation parent context — 2026-10-26

**Kết luận: chưa đủ điều kiện chạy full preprocessing.** Hướng actor + parent và giữ frozen seed02 đúng mục tiêu, nhưng CLI đang lỗi runtime và causal replay/state/artifact contracts chưa đáp ứng policy. Review này không sửa production implementation; lưu các ca tái hiện để agent triển khai sửa đúng nguyên nhân. Không chạy full preprocessing/training và không ghi vào raw data hoặc baseline.

## Phạm vi và bằng chứng

Reviewed working tree trên HEAD `32aab38`, gồm các thay đổi build_vocab, build_model_input, stratified_pipeline, pipeline_contract, tracker mới và test mới. Đọc AGENTS.md và MENU.md. Snapshot hash các file reviewed lưu tại `code/output/parent_context_code_review_20261026/reviewed_files.json`.

- Chạy lại 9 suites liên quan với PYTHONPATH đúng namespace: **98 tests pass**, gồm12 tests mới. Đây không phải toàn bộ test suite của repository.
- Các test hiện tại không chứng minh đủ12 yêu cầu: test12 gọi cùng một tracker bằng tay, không chạy hai worker/file; test11 chỉ kiểm tra root cũ, không kiểm tra relocated symlink; test09 chỉ roundtrip state rất nhỏ, không kiểm tra config/source/code compatibility.
- Ca tái hiện bổ sung: `code/output/parent_context_code_review_20261026/reproduce.py`; kết quả `findings.json`. Script chỉ tạo fixture tạm và JSON bằng chứng; kiểm tra output guard chỉ resolve/validate đường dẫn, tuyệt đối không thử ghi dataset.
- Kiểm tra 30.000 dòng đầu SysClient0201 ngày23/09: 0 lần timestamp giảm, **16.373 cặp dòng liên tiếp cùng timestamp**. Không suy rộng thành toàn corpus đã có thứ tự.
- Lệnh tái hiện: `PYTHONPATH=/mnt/SSD_Data/optc python3 ML/code/output/parent_context_code_review_20261026/reproduce.py`.

## Các lỗi phải sửa

### R1 — P1: cấu hình CLI không khởi tạo được tracker

`stratified_pipeline.py:483` và `build_model_input.py:154` thêm `field_ownership` vào context_config, sau đó worker truyền toàn dict vào ProcessContextConfig. Dataclass không có field này.

Tái hiện bằng policy thực sự sinh từ vocab_main dry-run: `TypeError: ProcessContextConfig.__init__() got an unexpected keyword argument 'field_ownership'`. Dry-run trả về trước khi khởi tạo worker nên không phát hiện; tests truyền dict đơn giản chỉ có enabled.

Sửa: tách runtime config và metadata description, dùng một builder/validator policy dùng chung; thêm test CLI thực sự build vocab rồi shards trên fixture, không chỉ dry-run.

### R2 — P1: guard chưa bảo vệ dataset ở đường dẫn hiện hành

`pipeline_contract.py:65` chỉ lấy PROJECT_ROOT/name. Các root hiện hành là PROJECT_ROOT/DATASET/DARPA-OPTC/name; host-begnin resolve sang `/mnt/HDD_Data/host-begnin`. Cả4 đường dẫn hiện hành đều được validator chấp nhận trong probe.

Đây là thiếu sót relocation có từ trước patch, nhưng implementation mới tiếp tục dùng guard này và bàn giao tuyên bố đã bảo vệ đầy đủ. Các input_roots bổ sung không bao phủ mọi root/symlink/callsite, ví dụ save_checkpoint trực tiếp.

Sửa: bảo vệ cả root lịch sử và root hiện hành sau resolve, test bằng temp symlink và validator-only trên root thực; kiểm tra mọi writer/checkpoint trước mkdir/open. Không thử ghi thật vào dataset để test.

### R3 — P1: chưa có causal batch/replay theo timestamp

`stratified_pipeline.py:403–426` gọi observe ngay từng dòng, kể cả code0; không batch timestamp, không kiểm tra hoặc xử lý thời gian giảm. So sánh metadata_t < query_t không đủ: bounded recent_actions/capacity/conflict state vẫn bị event cùng timestamp hoặc tương lai thay đổi.

Probe: history READ ởt1; queryt2 có READ; observe WRITE ởt2 làm đầy deque; queryt2 sau đó mất READ. Với config mặc định cũng tái hiện bằng8 update cùng timestamp. Probe khác: conflict ởt3 làm queryt2 có parent_conflict, vì boolean conflict không có timestamp.

Sửa: tạo feature của toàn batcht trên state trước batch, rồi mới observe; đảm bảo policy eviction cũng không phụ thuộc thứ tự query/selected split. Với dữ liệu mất thứ tự cần bounded external replay/merge hoặc reject rõ ràng trước publish; không nuốt lỗi thứ tự trong nhánh code0. Bảo toàn source_line/event identity khi replay theo thời gian. Test permutation cùng timestamp và out-of-order qua production iterator.

### R4 — P1: context bị reset ở mỗi source file

`stratified_pipeline.py:447–450` và `build_model_input.py:83–86` tạo tracker mới trong mỗi task file. Không truyền state giữa hai ngày của cùng host. Probe hai file cùng host: ngày21 có CREATE; ngày22 có FILE READ trong TTL; vocab_file thứ hai trả actor_metadata_missing và parent_missing.

Sửa: đơn vị công việc theo host với các nguồn được replay có thứ tự, hoặc causal context cache riêng có identity rõ ràng. Parallelize giữa host, không độc lập các ngày cùng host nếu cần carry state. Vocab và shards phải dùng cùng replay semantics. Resume phải khôi phục state/offset hoặc deterministic replay prefix; ghi rõ cold start, source scope và day boundaries.

### R5 — P1: policy/code identity vocab và shards không được ràng buộc

`build_model_input.py:150–175` cho bật context với baseline vocabulary, hoặc override TTL/capacity khác policy lúc fit. Token ctx vắng trong baseline vocab sẽ bị bỏ, nhưng manifest vẫn có thể ghi context enabled sau khi R1 được sửa. `load_vocabulary` chỉ kiểm tra tokenizer cũ; không xác nhận implementation hash của context. `builder_identity():27` chỉ hash3 file builder/shards/storage, bỏ tracker và stratified_pipeline.

Hệ quả: đổi tracker có thể reuse receipt/run cũ, hoặc tạo shards bằng semantics khác vocabulary đã fit.

Sửa: policy canonical và hash toàn dependency ảnh hưởng feature/replay; yêu cầu exact agreement với vocabulary metadata, reject baseline vocabulary khi bật context; reject override không tương thích trước write. Thêm test code/config mismatch và stale receipt, không chỉ checksum file vocab.

### R6 — P1: conflict vẫn được dùng làm parent context

`process_context_tracker.py:349–357` phát parent_conflict nhưng vẫn đi vào nhánh lấy metadata của parent đã lưu và tạo lineage/has_parent. Probe xác nhận cùng lúc có parent_conflict và parent::exe=explorer.exe.

Sửa: giữ actor context nhưng suppress parent-derived features khi identity chưa xác định; timestamp conflict phải causal. Không mô tả đây là đã giải quyết UUID/PPID mismatch thực tế: code chỉ so hai CREATE cùng child UUID khác parent, không đối chiếu case PPID2540/UUID khác nhau trong báo cáo first-label.

### R7 — P2: TTL và bounded-state chưa đúng tuyên bố

Prune chỉ chạy sau observe (`process_context_tracker.py:603`), không trước query. Probe TTL1s, query sau2s vẫn có full actor/parent context. Event đến muộn còn có thể refresh last_seen trước prune và giữ metadata đã hết hạn.

Raw command_line/image/principal được lưu không giới hạn; probe giữ nguyên chuỗi command1.000.000 ký tự. Giới hạn node count không phải giới hạn memory. Mỗi observe scan toàn bộ process của host để TTL; capacity eviction sort toàn bộ state. Benchmark nhỏ không chứng minh chi phí ở10.000 process/host. Host map và PID map cũng chưa có global bound/cleanup đầy đủ.

Sửa: expire trước query/update theo causal clock, validate cấu hình dương/hữu hạn, bound metadata/token/host state, chọn cấu trúc eviction phù hợp, benchmark khi gần capacity và báo peak RSS thật. Không dùng timestamp tương lai để expire quá khứ.

### R8 — P2: checkpoint và PID fallback chưa hoàn chỉnh

`save_checkpoint/load_checkpoint:605–654` không validate config đã lưu, không code/source/offset identity; load chấp nhận checkpoint TTL86400 vào tracker TTL1. Không serialize/restore pid_tracker; sau load có thể thiếu host key trong PID tracking. Các method này chưa được production workers dùng cho mid-source resume; workers chỉ cache hoàn tất file và rescan file dang dở.

PID đọc từ properties.pid (`:556`) nhưng eCAR thật dùng top-level pid. Test05 dùng schema giả properties.pid, nên pass không chứng minh PID reuse của dữ liệu thật. get_context_tokens không có lookup fallback khi actorID thiếu, dù CLI gọi đây là fallback.

Sửa: mặc định giữ strict UUID; bỏ/reject flag PID fallback cho tới khi có implementation lifecycle được test. Checkpoint phải validate full config/schema/code và bind source/offset tại orchestration; test interrupted production run, changed source/config, boundary cùng timestamp và eviction. Nếu chọn replay lại prefix thay checkpoint state, ghi đúng contract và đo chi phí.

### R9 — P2: lệnh storage và protection chưa cách ly thí nghiệm

Lệnh bàn giao vẫn dùng `code/others/model_input_volumes.json`, SSD path trong file này là namespace lịch sử `.../code/output/host_ml_seed02/model_input/volumes/ssd`, không phải namespace context mới. Đổi --output-dir không đổi nơi chứa payload shards. Run-id subdirectory làm giảm nguy cơ đè shard cũ, nhưng không đáp ứng yêu cầu namespace độc lập và có thể tạo output vào đường dẫn lỗi thời.

Vocab output guard chỉ bảo vệ thư mục split, không chặn ghi vocab context lên baseline vocab. Cần storage config riêng trong namespace context, bảo vệ baseline artifacts và xác minh resolved output/volume paths trước chạy. Không thay storage config baseline tại chỗ.

## Tài liệu và feature semantics cần chỉnh

- Bàn giao ghi same-timestamp batching, cross-day continuity và fallback đã hoàn thành nhưng code chưa làm; phải sửa các khẳng định này.
- `principal` trên CREATE được gán cho child: cần xác minh field ownership bằng schema/dữ liệu, không tự gọi đây là identity của child nếu chỉ chứng minh được initiator. Generic non-CREATE PROCESS OPEN/TERMINATE cũng cần ownership evidence riêng, không suy từ FILE.
- Non-CREATE command_line không được observe lưu dù bảng bàn giao nói có. Context command tokens hiện chỉ lấy family/switch/launcher/cmd mode; operand type/operators phần lớn bị bỏ. Cần thống nhất whitelist semantic với mục tiêu và test cụ thể.
- `same_principal` hiện so principal bucket, không so account identity; đổi tên thành same_principal_class hoặc ghi semantics rõ để tránh hiểu sai.
- `canonical_host` cắt domain; phù hợp cohort chỉ khi xác nhận host stem không trùng. Không coi đây là cách ly mọi FQDN trong triển khai tổng quát.
- Coverage has_actor_metadata hiện tính cả recent_action/created_t, không nhất thiết có image/command. Tách counters có metadata thực, có edge và có parent metadata.
- Báo cáo 51k events/s từ30k raw events với phần lớn FLOW chưa phải throughput tokenize mọi target hay full pipeline. RSS cuối lượt không phải peak RSS. Không chứng minh near-real-time hoặc F1 tăng.
- Test TRAIN-only hiện kiểm tra switch trên target events; cần thêm case context chỉ ở held-out target không fit, và case held-out telemetry quá khứ xuất hiện trong context của TRAIN target được phép dùng (unlabeled history), phân biệt với leakage.

## Thứ tự sửa và tiêu chí chấp nhận

1. Guard raw/baseline/output volumes và config runtime (R1,R2,R9).
2. Replay theo thời gian, batch đồng timestamp, carry state theo host, conflict fail-closed (R3,R4,R6).
3. Policy/hash compatibility và resume toàn pipeline (R5,R8).
4. TTL/bounded memory và field semantics (R7, các điểm tài liệu).
5. Test end-to-end nhỏ: frozen mask chứa code0/1/2/3, hai ngày cùng host, timestamp ties, nguồn mất thứ tự, interrupted run; so row identity/label/split, tokens và shards với continuous run. Không cần tạo lại seed02 hay full training.
6. Chạy lại suites liên quan và benchmark có scope rõ; cập nhật README/MENU/field table, lệnh dùng namespace riêng. Chỉ sau review lại mới xem xét full preprocessing.

Giữ nguyên baseline/split seed02. Không cần quay lại mô hình GraphSAGE để sửa các lỗi này.
