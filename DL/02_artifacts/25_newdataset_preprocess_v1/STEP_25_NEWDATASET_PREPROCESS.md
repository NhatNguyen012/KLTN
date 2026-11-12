# STEP 25 — Tiền xử lý skrghosh và AIT sang định dạng shards của mô hình OpTC v2

Ngày: 2026-10-22. Mã: `01_code/pipeline_v2/s10_skrghosh_flows.py`, `s10_ait_flows.py`, `s10_shards.py`. Dữ liệu nguồn ở `E:\NEWDATASET` chỉ đọc. Không đụng artifact cũ. Chưa chạy mô hình nào trên các bộ này.

## Mục đích và nguyên tắc
Tạo hai **bộ đánh giá** (không phải bộ train) mà mô hình OpTC phương án B (STEP 24) đọc được bằng đúng bộ nạp dữ liệu của notebook 06e/07e. Mã hóa dùng **nguyên văn `preprocess_spec.json` của OpTC** (từ điển category, mean/std): không fit lại gì trên dữ liệu mới, nên không có rò rỉ. Cột mà dataset không có (Bro, tiến trình, tài khoản) được mã hóa là `<MISSING>` (id 1) hoặc numeric 0 kèm cờ thiếu; mô hình B đã bỏ các cột Bro và `principal_class` nên không ảnh hưởng. Sample = (máy, cửa sổ 15 phút), chunk ≤ 512 flow, nhãn sample = có ≥ 1 flow dương; toàn bộ xếp vào split `test` (giữ thứ tự thời gian) để dùng lại bộ nạp.

## skrghosh (`skrghosh/`)
Nguồn: sự kiện `object=FLOW` của eCAR; nhãn từng sự kiện từ script KLTN (`labeled/*.labels.csv`), không phải của tác giả skrghosh.
| Kịch bản | Sự kiện FLOW | Object | Flow (sau gộp) | Flow dương | Cửa sổ (dương) |
|---|---:|---:|---:|---:|---:|
| FIN6 | 435,313 | 17,850 | 13,092 | 6 | 45 (2) |
| APT29 | 705,218 | 12,228 | 10,625 | 3 | 77 (2) |
| menuPass | 1,429,132 | 30,420 | 22,929 | 273 | 59 (4) |
| OilRig, Wizard Spider | 0 | – | – | – | **không có FLOW, bỏ qua** |
| **Tổng** | | | **46,646** | **282** | **181 (8)** |
Kết quả shards: 196 sample, **8 sample dương**, 3 máy (`skr_fin6`, `skr_apt29`, `skr_menupass`), PASS.

Quy tắc ánh xạ (mỗi quy tắc là một quyết định có thể sai, cần ghi rõ khi báo cáo):
- **Gộp object thành kết nối:** mỗi kết nối thường có 2 object FLOW (outbound và inbound, địa chỉ không đảo). Gộp theo (cổng hai đầu, giao thức, phiên cách nhau ≤ 120 giây) để giống 1 dòng conn của Bro. FIN6: 17,850 object → 13,092 flow. Ngưỡng 120 giây là lựa chọn của mình, chưa kiểm độ nhạy.
- **Đầu phản hồi (`resp_h/resp_p`)** = đầu không phải máy cục bộ; máy cục bộ = `192.168.1.139` (src_ip phổ biến nhất của object outbound, cả 3 kịch bản).
- **`app_family`** = tên file của `image_path`, chữ thường (cùng công thức S1 của OpTC); `image_dir_class` dùng luật Windows của OpTC. `principal` rỗng nên không có.
- **`proto`:** `6→tcp`, `17→udp`, và giá trị `4` (chỉ có ở FIN6, đi kèm cổng 443 (6,154 flow), 80, 8888) được **đoán là TCP**. Đây là suy luận từ cổng, không có tài liệu xác nhận.
- **Thời gian:** chuyển về UTC (dữ liệu ghi offset −07:00). Mỗi file là một máy (`hostname` gốc luôn `localhost`).
- Dòng cuối của `oilrig.json` bị cắt dở (không ảnh hưởng vì không có FLOW).

Đo mức khác biệt với từ điển OpTC (trên toàn bộ flow): **`app_family` thành `<UNK>` ở 74.5% flow** (như `msedge.exe` 19,666 flow, `python3.11.exe` 14,316 flow không có trong từ điển OpTC), `resp_port_class` UNK 5.9%, `image_dir_class` và `proto` không UNK. Các tiến trình dương nổi bật: `nbtscan.exe` 254/254 flow dương, `svchost.exe` 14 dương trên 10,060, còn lại `splunkd.exe`, `powershell.exe`.

## AIT (`ait/`)
Nguồn: Suricata `eve.json` (event_type `flow`), 7 máy × 2 kịch bản (fox, harrison), `mail` có thêm `eve.json.1`. AIT **không có nhãn cho `eve.json`**, nên nhãn là **nhãn suy ra**:
- Flow dương nếu (`src_ip` hoặc `dest_ip` thuộc tập IP kẻ tấn công) và `flow.start` nằm trong [`vpn_connect`, `vpn_disconnect`] của `attacker_0/logs/attacks.log`.
- Tập IP kẻ tấn công = IP khách ở các dòng apache access và openvpn mà AIT đã gán nhãn dương: fox `172.17.130.196` (410,831 dòng apache), `192.168.130.77` (VPN); harrison `10.237.1.238`, `172.28.192.242`. Cửa sổ tấn công: fox 2022-01-18 11:59:00–13:14:51 UTC, harrison 2022-02-08 07:07:00–08:37:25 UTC.
| | Flow | Flow dương | Sample | Sample dương | Cửa sổ dương |
|---|---:|---:|---:|---:|---:|
| fox + harrison (14 log) | 884,697 | 133,773 (15.1%) | 8,259 | 302 | 54 / 7,895 |
Phần lớn flow dương nằm ở máy `vpn` (fox 44,241; harrison 72,685), nơi kẻ tấn công kết nối VPN.

Ánh xạ: `proto` = chữ thường của `proto` Suricata (`tcp`, `udp`, `ipv6-icmp`); `resp_p` = `dest_port`; `ts` = `flow.start`; **mọi field tiến trình để trống** (`app_family` và `image_dir_class` = MISSING cho 100% flow). `proto` UNK 3.9% (ICMP), `resp_port_class` UNK 3.7%.

Hạn chế của nhãn AIT (quan trọng):
1. Cùng IP NAT `172.17.130.196` cũng xuất hiện ở traffic benign (ví dụ yêu cầu HTTP lúc 08:02 trước cuộc tấn công) nên flow benign trong cửa sổ có thể bị gán dương nhầm; trong cửa sổ không có cách tách theo từng flow.
2. Pha `dnsteal` (rò rỉ DNS, nhiều ngày trước, từ máy `10.35.33.111` ở fox) **không được gán nhãn** ở mức flow, nên flow tấn công ngoài cửa sổ VPN sẽ bị coi là benign.
3. Không có field tiến trình nên mô hình B chỉ còn `proto`, `resp_port_class`, `delta_t`; kết quả trên bộ này không cho biết gì về khả năng dùng ngữ cảnh tiến trình.

## Kiểm tra
Mỗi bộ: số flow trong shards = số flow trong parquet; số flow dương bảo toàn; số sample = số cửa sổ×chunk; `sample_id` duy nhất; chunk ≤ 512; **mã hóa lại 300 flow ngẫu nhiên bằng Python thuần từ spec khớp 100% với shard** (0 sai). Xem `skrghosh/checks.json`, `ait/checks.json`.

## Hạn chế khi phát biểu
- skrghosh chỉ có **8 sample dương** (282 flow dương); AIT có 302 sample dương nhưng nhãn suy ra, dương gần như toàn là quét/duyệt web của một kẻ tấn công. Kết quả trên hai bộ này chỉ mang tính tham khảo, không đủ để kết luận khả năng tổng quát hóa.
- Nhãn skrghosh do script lan nhãn theo cây tiến trình `splunkd.exe`, mô hình lại dùng tên tiến trình, nên có nguy cơ tuần hoàn.
- Từ điển `app_family` của OpTC chưa có tên tiến trình mới; muốn học từ dataset mới phải mở rộng từ điển (nối thêm, giữ id cũ).

## Bước tiếp theo (chưa làm)
Chạy suy luận CPU (vài phút, không cần Kaggle) mô hình B đã train (`05_models/v2_subsetB/`) trên hai bộ này, ngưỡng lấy nguyên từ VAL của OpTC; ghi `STEP_26`. Việc fine-tune và chia train/val/test cho dataset mới chưa bắt đầu.
