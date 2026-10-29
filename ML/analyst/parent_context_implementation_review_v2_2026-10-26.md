# Review vòng 2 — Parent context, 2026-10-26

**Kết luận: đã cải thiện đáng kể, nhưng chưa sẵn sàng chạy full preprocessing.** Có lỗi resume làm thay đổi feature và shard so với chạy liên tục. Lượt review này không sửa production code, không chạy full corpus/training và không ghi raw/baseline.

## Đã xác nhận sửa

- R1: ProcessContextConfig nhận policy CLI; test build vocabulary → shards thực sự chạy được.
- R2: validator chặn cả4 dataset root hiện hành sau resolve, gồm symlink host-begnin.
- R3: production split_rows batch theo timestamp trong mỗi file, query trước observe; từ chối timestamp giảm trong file. Đây là cải thiện thực, không còn chỉ kiểm tra metadata timestamp.
- R4: vocab_host/process_host dùng cùng tracker qua các file của host khi chạy liên tục.
- R6: parent_edges có timestamp; nhiều parent hợp lệ trước query tạo conflict và suppress parent features.
- R5 một phần: chặn bật/tắt context không khớp vocabulary và TTL/capacity mismatch; builder_identity đã thêm tracker/replay dependencies.
- R7 một phần: giới hạn command4096/image1024 ký tự và query TTL trực tiếp.
- R9 một phần: có volume config riêng; context control/volumes được kiểm tra baseline protection.

Chạy lại9 suites: **99 tests pass**, gồm13 parent-context tests. Đây không chứng minh mọi yêu cầu đã hoàn thành. Bằng chứng tại `code/output/parent_context_code_review_v2_20261026/{tests.json,findings.json,compat_findings.json,reviewed_files.json}`. Các probe dùng fixture nhỏ trong tempfile, không dùng output baseline.

## Lỗi còn mở, theo ưu tiên

### V2-1 — P1: resume mất state của các file đã cache, làm thay đổi dữ liệu học

Vị trí: `stratified_pipeline.py:465–469`, `build_model_input.py:73–77`; host orchestration `vocab_host` và `process_host`.

Các worker trả về cache/receipt ngay, không phục hồi tracker của file đã bỏ qua. Host orchestration luôn truyền tracker mới vào worker, nên nhánh load checkpoint chỉ chạy khi tracker=None cũng không giúp được.

**Tái hiện thực tế qua cả hai host workers:** fixture ngày21 có CREATE (code0), ngày22 có FILE READ (TRAIN), trong TTL. Chạy liên tục có actor cmd.exe + parent explorer.exe. Chạy ngày21 xong, khởi động lại với cả hai ngày: cache ngày21 được dùng nhưng ngày22 chỉ có actor_metadata_missing/parent_missing. Vocabulary TF khác; SHA256 shard ngày22 khác:

- continuous: `0b4682aaf66d286b5fdd1b059a5cc4aba948cc273762b91e7cc2fecab9f06ed7`
- resumed: `64eccd1b16c4145bd6a6bd40f9f293daaafcf05f6bff838d44b28dbe5788ad08`

Các hash trên chỉ thuộc fixture probe, không phải baseline.

**Sửa:** receipt của file phải bind state-after-file đã publish thành công bằng checksum, config/code/source-prefix identity; cache hit phải restore state trước file kế. Nếu state thiếu/hỏng, replay prefix hoặc invalidate đoạn suffix phụ thuộc; không skip rồi chạy với state rỗng. Không nuốt lỗi save/load checkpoint bằng `except: pass`. Test interruption sau từng file, cache hole, checkpoint missing/corrupt và so decoded rows/features lẫn shard bytes với continuous run.

### V2-2 — P1: vocabulary context từ implementation khác vẫn được chấp nhận

Vị trí: `build_model_input.py:202–228` và `pipeline_contract.load_vocabulary`.

Builder hash hiện tại đổi run_id là đúng, nhưng không so context implementation lúc fit vocabulary với context implementation khi transform. Probe tạo vocabulary checksum hợp lệ, tokenizer hash hiện tại, metadata implementation tracker=`stale-context-code`; builder dry-run vẫn trả0. Do đó semantic change của tracker có thể dùng vocabulary cũ mà không báo.

**Sửa:** canonical context feature/replay contract hash lưu trong vocab metadata và validate trước write; hash các dependency thật sự ảnh hưởng feature. Phân biệt hash builder để resume với hash feature contract để vocab/transform tương thích. Test thay tracker hash trong metadata và thiếu identity đều phải reject.

### V2-3 — P2: TTL chỉ ẩn state ở query, observe làm sống lại metadata đã hết hạn

Vị trí: `process_context_tracker.py:304` và `observe:494–628`.

Probe TTL1s, CREATEt1; queryt2s báo actor_expired. Observe FILE READt2s không có image/command refresh last_seen của node cũ trước prune. Query tiếp theo lại có cmd.exe và created_t cũ. TTL bị vượt qua khi actor hoạt động trở lại.

**Sửa:** expire state trước update/query bằng cùng causal clock, không refresh node hết hạn trước eviction. Event mới chỉ tái tạo metadata có bằng chứng mới. Test expiry→event thiếu metadata→query tiếp theo; parent edge cũ cũng không được phục hồi ngầm.

### V2-4 — P1: checkpoint chưa xác thực code và toàn bộ policy

Vị trí: `process_context_tracker.py:630–680`.

save_checkpoint lưu `code_hashes()` mặc định chỉ tokenizer, không tracker; load_checkpoint không so code_hashes. Chỉ so5 config fields, bỏ max_recent_actions, field_ownership, PID policy; field config thiếu cũng được bỏ qua. Không bind source prefix/offset/host ordering.

Probe sửa code_hashes thành bogus và restore checkpoint max_recent_actions8 bằng tracker max_recent_actions1: vẫn accepted.

**Sửa:** schema bắt buộc, full canonical config equality, context implementation hash, source-prefix/offset identity ở orchestrator; thiếu hoặc khác phải reject/replay. Không tin checkpoint chỉ dựa tên host/ngày. Tích hợp với V2-1; không chỉ test roundtrip đơn giản.

### V2-5 — P2: PID flag chưa fail-closed như bàn giao

ProcessContextConfig(enable_pid_fallback=True) vẫn accepted; CLI builder nhận --enable-pid-fallback nhưng không so với metadata, lấy nguyên vp. Probe bật flag với vocab policy mặc địnhfalse vẫn dry-run thành công. get_context_tokens không có lookup fallback khi actorID thiếu; PID map không persist/restore đầy đủ.

**Sửa:** vì scope mặc định strict UUID, reject flag True ở cả vocab/shard/config cho tới khi có implementation lifecycle thật; không giữ flag với help hứa chức năng chưa có. Test negative CLI.

### V2-6 — P2: bounded state còn thiếu

- parent_edges append mỗi CREATE, không deduplicate/cap; probe1000 CREATE cùng child/parent giữ1000 edges.
- principal không giới hạn: probe giữ1.000.000 ký tự; action/identity string cũng chưa được bound rõ.
- timestamp batch giữ toàn bộ raw record trong list không giới hạn; cần spill/cap-fail rõ trước publish cho batch rất lớn.
- TTL vẫn scan toàn bộ process mỗi observe; benchmark trước không đo trạng thái gần10k entries.

**Sửa:** ancestry state chỉ cần số bằng chứng tối thiểu có timestamp để xác định parent/conflict dưới monotonic replay; bound mọi field/state/batch, validate finite TTL và positive recent-actions. Báo memory/throughput ở gần capacity trước tuyên bố near-real-time.

## Các điểm integration/tài liệu bổ sung

1. `last_t` reset mỗi file; sort theo day không validate timestamp boundary giữa các file. Cần kiểm tra monotonic host stream và xử lý timestamp tie xuyên boundary nếu có. Reject nguồn không có thứ tự là policy an toàn, nhưng cần preflight trước chạy lớn; không tuyên bố đã hỗ trợ arbitrary out-of-order replay.
2. tracker.stats là cumulative qua ngày, nhưng vocab_main cộng stats của từng ngày nên double-count. Shard manifest chưa tổng hợp tracker coverage. Cần per-file delta hoặc final-per-host aggregate.
3. Checkpoint-dir của vocab chưa dùng protect_baseline=True, dù output/meta đã có. Cần bảo vệ mọi writer và test validator-only với đường dẫn baseline, không thử ghi baseline.
4. Volume config mới chọn `/mnt/HDD_Data/optc_model_input_parent_context` và `/home/nguyen/optc_model_input_parent_context`, là sibling ngoài output roots đã được AGENTS cho phép. Dùng subdirectory trong `/mnt/HDD_Data/optc_model_input/parent_context_seed02` và `/home/nguyen/optc_model_input/parent_context_seed02` (giữ quota chung/reserve), hoặc dùng SSD workspace cho bước nhỏ. Không tự chạy các path mới ngoài quyền ghi.
5. Test13 có3 ngày và tạo split synthetic seed01; điều này không sửa frozen seed02, nhưng không phải bằng chứng riêng cho frozen seed02. Nó kiểm tra tổng60 rows và có token context, chưa so feature cross-day của một row cụ thể, resume, timestamp ties và missing checkpoint. Giữ fixture nhỏ nhưng thêm seed02 và assert identity/token theo row.
6. Các điểm field ownership/semantic trong review1 (CREATE principal, PROCESS OPEN/TERMINATE image ownership, same_principal thực chất bucket, context operand/operator whitelist) chưa được giải quyết bằng evidence/test mới.
7. Không claim same-timestamp direct tracker API tự an toàn: correctness hiện dựa vào batch iterator. Các caller tokenize_record_with_context(update_tracker=True) cần tuân thủ replay contract hoặc dùng public batch API.

## Giao lại agent

Ưu tiên V2-1/V2-4 cùng nhau, sau đó V2-2, TTL và reject PID flag. Thêm integration test interruption→resume với cùng host và code0 history, xác nhận cả vocabulary counters và decoded sparse rows tương đương; giữ frozen mask/labels/row identity. Hoàn thiện bounds/path/stats rồi cập nhật bàn giao theo đúng phần đã kiểm chứng. Chưa chạy full preprocessing hoặc training.

Lệnh probe độc lập:

```bash
PYTHONPATH=/mnt/SSD_Data/optc python3 ML/code/output/parent_context_code_review_v2_20261026/probe.py
PYTHONPATH=/mnt/SSD_Data/optc python3 ML/code/output/parent_context_code_review_v2_20261026/compat_probe.py
```
