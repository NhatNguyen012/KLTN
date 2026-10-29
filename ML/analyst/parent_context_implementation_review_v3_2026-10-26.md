# Review vòng 3 — 2026-10-26

## Kết luận

Các lỗi chính V2-1 đến V2-5 đã được sửa trong những ca tái hiện độc lập bên dưới. V2-6 đã bổ sung các bound cụ thể. Chưa nên tuyên bố hoàn thành toàn bộ policy: còn thiếu kiểm tra temporal boundary của host stream giữa các file. Có thể tiếp tục smoke test nhỏ; chưa chạy full preprocessing/training ở lượt review này. Production code, raw data và frozen seed02 không bị sửa bởi reviewer.

## Kiểm chứng thực chạy

Bằng chứng riêng, không ghi đè kết quả review trước: `code/output/parent_context_code_review_v3_20261026/`.

- `probe.py` / `findings.json`: continuous vs resume, vocabulary TF bằng nhau; SHA256 shard ngày2 giống nhau. Xóa checkpoint ngày1 rồi resume, hoặc làm hỏng JSON checkpoint ngày1 rồi resume, vẫn cho cùng TF/shard với continuous. Chỉ thao tác fixture tempfile.
- TTL1s: event mới không chứa metadata không hồi sinh image/parent cũ; token recent_action mới vẫn hợp lệ.
- Checkpoint code mismatch bị reject.
- 1000 CREATE lặp lại chỉ giữ1 parent edge; principal dài bị cắt256 ký tự.
- Strict UUID: enable_pid_fallback=True bị reject; cả4 relocated dataset roots bị validator từ chối, không thử ghi dataset.
- `compat_probe.py` đã TÁCH hai negative cases: stale implementation với PID flag tắt bị reject do implementation; implementation hiện tại + PID flag bật bị reject do PID. Probe cũ dùng đồng thời hai lỗi và một ValueError chung không chứng minh riêng từng contract.
- Chạy12 test scripts, tất cả exit0: **105 unittest cases** trong11 unittest suites, cộng `test_rng.py` là standalone script, không phải unittest case. Có14 parent-context tests. Trong11 scripts thuộc danh sách bàn giao (không gồm notebook), thực tế95 unittest cases + RNG script pass. Danh sách số lượng từng suite trong bàn giao sai: contextual split4, matrix3, pilot3, vocabulary review2; không phải10/6/4/1.
- Số105 bao gồm thêm10 tests notebook post-sweep. Log đầy đủ: `tests.json`.

## Điểm còn phải sửa trước full run

### V3-1 — P1: thiếu temporal watermark xuyên source boundary

`stratified_pipeline.py:402` khởi tạo last_t=None và batch rỗng cho mỗi lần split_rows. `vocab_host`/`process_host` giữ tracker nhưng không giữ last timestamp hoặc pending batch; sort theo day của filename không chứng minh thứ tự event timestamp.

Probe mới: file1 có CREATE tại2019-09-22T12:00; file2 có READ tại11:00 cùng ngày. Mỗi file tự nó có thứ tự; host worker vẫn accepted thay vì reject. Fixture cố ý không khớp ngày filename để kiểm tra nguồn không đáp ứng assumption; đây KHÔNG phải khẳng định dữ liệu thật đã có lỗi này.

Với nguồn chồng lấn, TTL/capacity/recent_actions đã chịu tác động của evidence muộn có thể làm context của event sớm sai dù từng metadata có kiểm tra <t. Timestamp ties xuyên file cũng cần cùng batch hoặc reject rõ, không xử lý hai batch độc lập rồi coi như tương đương.

Sửa tối thiểu cho scope hiện tại: host-level watermark được giữ/restore cùng checkpoint, validate min timestamp nguồn kế tiếp > last timestamp nguồn trước; reject overlap/tie nếu chưa có merge/batch xuyên file. Không bắt buộc viết external sort cho phiên bản đầu. Nếu muốn cho phép equality phải thực sự giữ batch qua boundary. Thêm tests host worker cho regression, equality, normal progression và resume tại boundary.

## Hoàn thiện tài liệu/contract

- Add `command_syntax.py` vào checkpoint context code hash vì tracker gọi parser này. Vocab/build run identity hiện có hash parser; standalone checkpoint identity nên đầy đủ tương tự.
- Validate TTL hữu hạn (`math.isfinite`) ngoài >0; NaN/Infinity hiện không bị chặn ngay config.
- Batch cap là50000 record, code từ chối record thứ50001; không phải từ chối ngay khi đủ50000 như bàn giao. Bound số record chưa phải bound bytes của batch; cần giới hạn raw record/byte buffer hoặc ghi rõ giới hạn này.
- Bound và TTL đã cải thiện nhưng chưa đo chi phí khi tracker gần10k process; không dùng benchmark nhỏ trước đây làm bằng chứng near-real-time ở capacity tối đa.
- Coverage has_actor_metadata vẫn có thể chỉ là recent_action, không nhất thiết image/command. Shard tracker_stats là cumulative per-file và chưa được tổng hợp thành coverage manifest; báo đúng semantics.
- Các điểm semantic field ownership, same_principal bucket và command operand/operator từ các review trước vẫn cần bảng mô tả/ablation, không nên tuyên bố đã giải quyết chỉ vì tests pass.
- Test frozen seed02: fixture synthetic không thay baseline nhưng chưa phải toàn bộ verification với approved manifest. Trước run lớn, dùng đúng manifest seed02, namespace mới, storage config riêng và kiểm tra dry-run paths. Không rebuild split.

## Phạm vi chấp nhận

Chấp nhận kết quả sửa các lỗi resume/TTL/compatibility đã kiểm chứng, không lặp lại chúng như lỗi còn mở. Yêu cầu cuối về causal correctness là V3-1 và test đi kèm. Sau đó có thể đánh giá pilot dữ liệu thật giới hạn, đo coverage/state/RSS/throughput, rồi mới quyết định full run. Không cần quay lại GraphSAGE.
