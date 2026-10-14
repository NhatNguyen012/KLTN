# STEP 20 — Thiết kế Context-aware Fusion (Gating vs Cross-attention) + Source mask — BẢN NHÁP v0

Ngày: 2026-10-12. Trạng thái: **bản nháp để GVHD review (14–16/10)**, chưa cài đặt, chưa huấn luyện, chưa chạy job nào. Không đổi kiến trúc hai encoder đã train (BiLSTM, Mixed-Type); chỉ thêm đầu fusion.

## 1. Vì sao cần fusion học được (số liệu đã có)
- Fusion mức điểm (STEP 17, LightGBM + Mixed-Type bỏ `app_family`): cải thiện chỉ 2 / 1,103 cửa sổ; chênh lệch giữa các cách ghép 0–2 cửa sổ trên 81 cửa sổ dương của một host.
- SC3 `sysclient0051`: host chấm event rất cao ở 4 cửa sổ tấn công, network chấm 0.0; cách gộp event → cửa sổ (`max`, `count`) không được chọn hợp lệ trên VAL (STEP 17E). Đây là chỗ một cổng học được theo ngữ cảnh có thể có giá trị, nhưng **chưa có bằng chứng** nó hơn mức điểm.
- Positive mạng gần như toàn beacon (530 / 541 cửa sổ); bất kỳ fusion nào cũng phải báo kèm ablation bỏ `app_family` và đối chiếu mức "beacon lạ".

## 2. Đơn vị và dữ liệu vào
- **Đơn vị:** cửa sổ (hostname, 15 phút), khóa đã chuẩn hóa ở STEP 14/S9; host dùng cửa sổ 30 phút thì gộp hai cửa sổ 15 phút.
- **Nhánh network:** chuỗi ≤ 512 flow → encoder đã train (đông cứng) → vector `h_net` (Mixed-Type `d_model` = 64; BiLSTM lấy vector gộp trước lớp phân loại, cần kiểm kích thước). Cửa sổ không có flow: `m_net = 0`, `h_net` = embedding null học được.
- **Nhánh host (hai mức, làm lần lượt):**
  - Mức 1 (rẻ, dùng dữ liệu đã có): vector điểm từ mô hình host của STEP 17 (logit xác suất lớn nhất, p99, số event vượt ngưỡng, tỉ lệ vượt ngưỡng) + 4 đặc trưng hành vi của STEP 12C (`n_proc_writable`, `n_parent_lsass`, `n_cmd_susp`, `n_novel_pairs`).
  - Mức 2 (nặng): vector hành vi đầy đủ theo cửa sổ (đếm theo (object, action), cặp cha→con chưa từng thấy trong TRAIN, tỉ lệ process từ thư mục ghi được…), chuẩn hóa chỉ fit trên TRAIN.
  - Máy không có log host (123 máy chỉ có mạng): `m_host = 0`.
- **Source mask:** `m = [m_host, m_net] ∈ {0,1}²`. Không bao giờ để cả hai bằng 0 khi huấn luyện.

## 3. Hai phương án
### A. Gating (đề xuất làm chính)
```
h_host' = P_h(h_host), h_net' = P_n(h_net)           # chiếu về cùng d = 64
h_x'    = m_x · h_x' + (1 − m_x) · e_null,x           # nguồn thiếu → embedding null
s       = W_g · [h_host'; h_net'; m_host; m_net] + b
g       = σ(s);  nếu m_net = 0 thì g = 1;  nếu m_host = 0 thì g = 0
z       = g ⊙ h_host' + (1 − g) ⊙ h_net'
ŷ       = σ(W_o · z)                                   # đầu nhị phân + đầu multi-label 5 nhóm (G1..G5, STEP 12B)
```
`g` là một vector cổng theo chiều đặc trưng (hoặc một số vô hướng mỗi cửa sổ nếu cần dễ giải thích); có thể báo `g` trung bình theo scenario để minh họa "ngữ cảnh nào cậy vào nguồn nào".

### B. Cross-attention (làm ablation, chỉ khi còn thời gian)
- Token network: trạng thái ẩn từng flow (≤ 512 × d). Token host: ≤ 64 token (nhóm (object, action), cặp cha→con lạ, process từ thư mục ghi được…) + embedding loại nguồn.
- `h_net` làm query trên token host; `h_host` làm query trên token network; key-padding mask theo `m`. Một đầu hoặc 4 đầu, d = 64.
- Chi phí mỗi cửa sổ O(512 × 64); cần token host **cấp event**, nên phải quét lại eCAR thô.

## 4. So sánh (d = 64)
| Tiêu chí | Gating | Cross-attention |
|---|---|---|
| Số tham số thêm (ước tính) | ~ (2d+2)·d ≈ 8.3 nghìn cho cổng, + chiếu và đầu ra | ≥ 4·d² ≈ 16.4 nghìn mỗi chiều attention (≈ 33 nghìn hai chiều), 1 đầu |
| Đầu vào host | Vector theo cửa sổ (mức 1 dùng được ngay) | Token cấp event (bắt buộc quét eCAR) |
| Nguồn thiếu | Mask + embedding null + ép `g`: đơn giản | Key-padding mask: được, nhưng khi mất host thì không còn gì để attend |
| Giải thích | `g` theo từng cửa sổ | Trọng số attention, khó đọc hơn |
| Rủi ro dữ liệu ít | Thấp–trung bình | Cao (541 cửa sổ dương mạng; 788 cửa sổ có nhãn tactic, chỉ 90 cửa sổ có tactic ngoài C2) |
| Khớp đề cương | Có (cổng + source mask + missing 10/20/30%) | Có (đề cương nêu cả hai) |
**Kết luận tạm:** làm Gating trước; Cross-attention chỉ thêm khi Gating cho thấy host có bổ sung thông tin ở mức cửa sổ.

## 5. Huấn luyện và đánh giá (đúng quy tắc CLAUDE.md)
- Split theo hostname, host-disjoint (seed_1: 434 / 93 / 93 máy); preprocessing chỉ fit trên TRAIN; ngưỡng chọn trên VAL; TEST chạy đúng một lần.
- Loss: BCE có `pos_weight`; đầu multi-label chỉ tính trên cửa sổ có nhãn giai đoạn (mask cửa sổ chưa có nhãn, STEP 12B).
- **Missing-source dropout** khi train: bỏ ngẫu nhiên một nguồn với p = 10 / 20 / 30%; khi test đánh giá cả ba mức.
- **Baseline bắt buộc (ablation):** chỉ host; chỉ network; fusion đơn giản (OR / trung bình / stacking, đã có STEP 17); context-aware (Gating). Cộng mức "bỏ `app_family`" và mức "beacon chưa từng thấy" (STEP 10H).
- Báo cáo SC3 theo từng cửa sổ (điểm network, host, fusion, nhãn), không báo F1 kèm khoảng tin cậy (chỉ 2 máy SC3, 6 cửa sổ dương).
- Chỉ báo "tốt hơn" khi chênh lệch vượt độ dao động giữa 3 seed.

## 6. Vướng mắc đã biết và việc cần xác nhận
1. **Chưa có đặc trưng host cho cửa sổ TRAIN host-disjoint.** STEP 17c chỉ chấm 1,103 cửa sổ VAL/TEST (VAL 594, TEST 509); điểm host trên TRAIN là in-sample nên không dùng để học cổng. Hệ quả: mức 1 chỉ có thể học cổng trên VAL (594 cửa sổ: 39 dương theo nhãn mạng, 126 theo nhãn host) bằng CV theo máy, rất ít dữ liệu.
2. **Mức 2 cần quét lại eCAR thô** (4,685 file, ổ E:, cỡ công việc của 17a: hàng chục giờ đọc đĩa, chưa đo lại). Cần báo ước lượng và chờ xác nhận trước khi chạy.
3. **Benign trong tập cửa sổ chỉ là mẫu** (2 cửa sổ mỗi máy-ngày) nên FP mức cửa sổ lạc quan; cần tập benign đầy đủ hơn (việc C).
4. **Nối cấp flow (flow → process → cha) chưa khả thi** như phân tích ở `PHAN_TICH_OPTC_SC3_BEACON_VA_FIELD_HOST.docx`: thiếu bản ghi eCAR-Bro ở một phần flow độc hại, pid/actorID có thể sai; tỉ lệ ánh xạ chưa đo.
5. **Thầy yêu cầu mới (10/10):** kiểm thử mô hình đã train bằng OpTC trên 3 dataset mới (không cần nhãn). Phần network chỉ áp dụng được cho dataset có flow; các dataset đã phân tích (SAGA, Windows-APT) không có network.

## 7. Bước tiếp theo đề xuất
1. GVHD review bản nháp này (14–16/10); chốt Gating là phương án chính.
2. Làm "Gating trên điểm" (mức 1) bằng dữ liệu đã có: nhẹ, chạy local, chỉ để kiểm tra khung huấn luyện (mask, dropout, ablation), kèm cảnh báo cỡ mẫu.
3. Nếu GVHD đồng ý: báo ước lượng và xin xác nhận quét eCAR cho mức 2 (đặc trưng host cho cửa sổ TRAIN).
