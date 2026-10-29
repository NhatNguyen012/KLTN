# Review vòng 4 — 2026-10-26

## Kết luận

**Đã xác nhận đóng lỗi V3-1 trong các ca kiểm chứng; có thể chuyển sang pilot dữ liệu thật giới hạn.** Không còn điểm chặn đã tái hiện trong các probe causal/resume/compatibility của các vòng trước. Đây không phải xác nhận toàn corpus đã chạy được, hiệu năng endhost đạt yêu cầu hoặc F1 cải thiện. Chưa chạy full preprocess/training và chưa sửa production code trong lượt review này.

## Kiểm chứng độc lập

Bằng chứng được lưu riêng tại `code/output/parent_context_code_review_v4_20261026/`, gồm probe.py, compat_probe.py, findings.json, compat_findings.json, tests.json và reviewed_files.json.

- 11 unittest suites: **108 tests pass**, gồm17 parent-context tests; RNG script exit0.
- Cross-file timestamp regression bị từ chối; các regression tests kiểm tra boundary equality, watermark độc lập giữa host và phục hồi watermark khi resume.
- Continuous/resume vocabulary TF và SHA256 shard khớp. Thiếu/hỏng checkpoint của file đầu được replay và vẫn khớp.
- TTL không hồi sinh metadata cũ; code/config checkpoint mismatch bị từ chối.
- Stale vocabulary context implementation và PID fallback bị từ chối bằng hai probe độc lập, không gộp hai nguyên nhân.
- Dataset-root validator vẫn từ chối4 relocated roots, không thử ghi vào dataset.
- command_syntax.py nằm trong checkpoint hash; TTL NaN/Inf/0/âm bị reject; batch50001 records bị reject.

## Một chỉnh sửa nhỏ còn nên làm

`stratified_pipeline.split_rows` đang dùng `line_len = len(line)` trên text đã decode UTF-8. Đây là số Unicode code points, **không phải byte UTF-8**, nên diễn đạt cap50MiB byte là chưa chính xác với dữ liệu non-ASCII.

Sửa thành `len(line.encode('utf-8'))` hoặc đọc binary và đo trước decode; bổ sung test byte cap độc lập với record-count cap, có non-ASCII. Không gọi đây là giới hạn tổng RAM50MiB vì parsed dict/list và Python object overhead còn chiếm thêm; một record rất lớn cũng được đọc/parse trước cap hiện tại. Điểm này không mở lại lỗi causal/resume đã đóng và không chặn pilot có scope kiểm soát.

## Bước tiếp theo đề xuất

Pilot giới hạn host/ngày/dòng với scope khai báo rõ, ghi artifacts riêng, sử dụng assignment/event identity từ frozen seed02 thay vì tạo split mới. Kiểm tra source ordering/boundaries, coverage actor/parent (tách metadata thực khỏi chỉ recent_action), missing/conflict/expired, token counts, OOV và row/label/split parity. Đo peak RSS, throughput và state size, bao gồm tình huống gần capacity. Lặp interruption/resume trên pilot.

Cần preflight đường dẫn/volume và metadata trước pilot; không tự mở rộng thành full-corpus scan hoặc training. Chưa có đo đạc đủ để kết luận near-real-time hoặc F1 tăng. Các field semantics/ablation đã ghi ở review trước vẫn là giới hạn cần mô tả, không tự động được chứng minh bởi tests.

Baseline/frozen seed02/raw inputs không được sửa trong review. Chỉ thêm bằng chứng và tài liệu, cập nhật MENU.
