# Nội dung ghi chú để dán vào todolist (cột Note) — task của Lâm, 2026-10-12

Số liệu lấy từ artifact trong repo; mục nào chưa làm xong thì ghi rõ "đang làm / chưa". Dán nguyên văn từng khối vào ô tương ứng.

## Dòng 23 — Xây dựng cơ chế chuẩn hóa & kết nối eCAR-Bro (khóa tương quan, timestamp, 5-tuple)  [đã tick hoàn thành]
```
Hoàn thành cơ chế chuẩn hóa và nối eCAR-Bro với Bro conn:
- Khóa tương quan: eCAR-Bro properties.bro_uid = Bro conn.uid (exact join, 92,045,755 flow, 743 host; join rate 99.972% trên uid duy nhất; khử 26,347 uid trùng; 0 xung đột hostname). Khóa ghép host-network: (hostname chữ thường bỏ đuôi domain, cửa sổ 15 phút)
- Timestamp: eCAR dùng EDT (UTC-4), Bro dùng epoch UTC; chuẩn hóa về UTC, cửa sổ = floor(ts/900)*900 (trùng giữa 2 nguồn vì 4 giờ là bội của 15 phút)
- 5-tuple (orig_h/p, resp_h/p, proto) lấy từ Bro; eCAR-Bro giữ l4protocol để đối chiếu (chưa đối chiếu IP/port giữa hai nguồn)
=> Hạn chế: chỉ giữ flow có eCAR-Bro nên mất 4,590/29,311 flow độc hại (DC1 4,190; sysclient0051 325/488 flow REJ); eCAR-Bro không có command_line/parent nên nối flow -> process cha cần actorID + log host (chưa đo tỉ lệ)
Lớp đọc được của pipeline: 02_artifacts/14_readable_pipeline_v1
```

## Dòng 24 — Thiết kế cơ chế Context-aware Fusion (Gating/Cross-attention) + Source mask  [ĐANG LÀM, chưa nên tick]
```
Đã có bản nháp thiết kế (02_artifacts/20_fusion_design_v1/STEP_20_FUSION_DESIGN.md), chờ GVHD review:
- Fusion mức cửa sổ (hostname, 15 phút); encoder network giữ nguyên (BiLSTM/Mixed-Type, d=64), chỉ thêm đầu fusion
- Gating: z = g*h_host + (1-g)*h_net, g = sigmoid(W[h_host; h_net; m_host; m_net]); Source mask m=[m_host, m_net]: nguồn thiếu thì thay bằng embedding null và ép g về nguồn còn lại
- Huấn luyện với missing-source dropout 10/20/30%; đầu ra nhị phân + multi-label 5 nhóm tactic (STEP 12B, mask cửa sổ chưa có nhãn giai đoạn); baseline: host-only, network-only, fusion đơn giản, context-aware
=> Lý do: fusion mức điểm (STEP 17) chỉ cải thiện 2/1,103 cửa sổ; SC3 host chấm cao nhưng gộp event -> cửa sổ làm mất 4 cửa sổ
=> Vướng: chưa có đặc trưng host cho cửa sổ TRAIN (host-disjoint), cần quét lại eCAR thô (cỡ STEP 17a), chờ xác nhận
```

## Dòng 25 — Hoàn thiện đặc tả kiến trúc fusion (so sánh Gating vs Cross-attention)  [ĐANG LÀM, chưa nên tick]
```
Đã soạn bảng so sánh trong STEP_20 (d=64):
- Gating: ~8.3 nghìn tham số cổng; host vào dạng vector theo cửa sổ (dùng được ngay điểm host STEP 17 + 4 đặc trưng hành vi STEP 12C); xử lý nguồn thiếu bằng mask; giải thích được qua g
- Cross-attention: >=16.4 nghìn tham số mỗi chiều attention; cần token host cấp event (phải quét lại eCAR); chi phí O(512x64)/cửa sổ; khó giải thích; dễ overfit (541 cửa sổ dương mạng, chỉ 90 cửa sổ có tactic ngoài C2)
=> Đề xuất: Gating làm chính, Cross-attention chỉ làm ablation nếu Gating cho thấy host bổ sung thông tin
=> Còn thiếu: chốt kích thước vector BiLSTM, lịch chạy ablation (missing 10/20/30%, bỏ app_family, beacon lạ) và duyệt của GVHD (14-16/10)
```

## Dòng 21 (phần của Lâm) — nếu muốn thêm tiến độ vào ô note hiện có  [tùy chọn]
```
Tiến độ phần Lâm (chưa kiểm thử mô hình):
- Đã phân tích 3 dataset thầy gợi ý (SAGA, Windows-APT 2025, skrghosh): chỉ có host, không có network nên không kiểm thử được mô hình network của OpTC
- Ứng viên có flow mạng: Unraveled (đã tải và sửa lỗi CSV: 6,877,157 flow, 89 cột, nhãn theo giai đoạn APT, bán tổng hợp); skrghosh có event FLOW (src/dest ip, port, giao thức, size, image_path) ở 3/5 chiến dịch nhưng không có conn_state/service/duration như Bro
=> Còn thiếu: dataset Linux và dataset trong nghiên cứu gần đây; cần ánh xạ cột sang feature của model (proto, service, conn_state, port, duration, bytes, pkts, delta_t) trước khi kiểm thử
```
