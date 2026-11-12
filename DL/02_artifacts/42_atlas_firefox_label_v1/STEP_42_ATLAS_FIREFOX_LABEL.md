# STEP 42 — Vì sao `firefox.exe` của ATLASv2 được gán nhãn "độc" (sự kiện file/module/registry/crossproc/procstart + nút gốc/tác động)

Ngày: 2026-10-30. Tiếp STEP 40. Chỉ đọc `atlasv2.tar.gz` (một lượt streaming, ~10 phút) và `reapr-ground-truth/atlasv2/*.labels|*.seeds`; không train. Mã: `01_code/pipeline_v2/s31_atlas_firefox_events.py`, `s32_why_atlas_firefox.py`, `s33_atlas_firefox_seed_time.py`, `s34_atlas_ip_check.py`. Dữ liệu: `firefox_procs.json` (377 tiến trình: 215 `firefox.exe` + mọi tiến trình có nhãn), `summary.txt`.

## 0. Kết luận
Nhãn `firefox.exe` dương **không đến từ nội dung flow** mà từ hai cơ chế của REAPr (chọn nút gốc `root_cause`/tác động `impact` từ mô tả tấn công, rồi lan nhãn qua đồ thị tiến trình):
1. **18/26 tiến trình `firefox` dương đã kết nối tới một nút `root_cause`** (trong `.seeds`): 11 tiến trình chạm IP máy tấn công (`10.193.66.115:8080` 5, `10.193.242.113:9997` 6) và 7 tiến trình chỉ chạm IP công cộng `34.107.221.82:80` hoặc `142.250.191.225:443` mà `.seeds` cũng ghi `root_cause`. README của REAPr thừa nhận có "remote host bị gán nhầm" do hoạt động nền của người thí nghiệm thứ hai.
2. **8/26 còn lại là tiến trình con** của `firefox` đã có nhãn (cả 8 đều `parent_label = 1`, mỗi tiến trình chỉ 3 netconn, không seed, không sự kiện khác): nhãn **thừa kế từ cha**.
3. Hệ quả: trong 7,696 flow dương của `firefox`, chỉ **56 flow (0.7%)** tới một nút `root_cause` (trong đó 10 flow tới `10.193.66.115`, IP máy tấn công gần như sạch; 12 flow tới `10.193.242.113` là IP có cả traffic benign, xem mục 2). 99% flow dương là duyệt web thường của tiến trình bị gán nhãn; ví dụ 3,039 flow của các tiến trình dương nằm **trước** lần chạm đầu IP tấn công, và 2,056 flow thuộc tiến trình chưa từng chạm IP tấn công.

## 1. So sánh ba nhóm tiến trình `firefox.exe`
| | dương (26) | tệp attack, không nhãn (63) | tệp benign (126) |
|---|---|---|---|
| có netconn | 26 | 60 | 93 |
| chạm nút `root_cause` | **18** | 0 | 0 |
| tiến trình có ≥ 100 netconn | 14 | 0 | 13 |
| có sự kiện registry | 17 | 1 | 21 |
| có crossproc (mở handle `explorer.exe`) | 5 | 1 | 11 |
| có procstart (sinh tiến trình con) | 18 | 11 | 21 |
| ghi `.exe` vào thư mục người dùng/Temp | 6 | 0 | 4 |
| cha có nhãn | 20 | 43 | 0 |

- **Ít tách được**: số netconn lớn (tiến trình chính, dùng lâu) không phân biệt, vì tệp benign cũng có 13 tiến trình ≥ 100 netconn; registry, crossproc, procstart, ghi `.exe` đều xuất hiện ở benign (tỷ lệ gần).
- **Tách được ở mức tiến trình**: có kết nối tới nút `root_cause` (18/26 so với 0/189) và cha có nhãn (nhưng cha có nhãn cũng có ở 43/63 tiến trình tệp attack không nhãn → nhãn của cha **không** kéo con thành dương một cách nhất quán; REAPr chỉ lan qua tiến trình theo quy tắc ngược/xuôi nên không phải mọi con đều dương).
- Tiến trình tệp attack không nhãn có 7/63 tiến trình có ≥ 20 netconn: hầu hết là tiến trình phụ ngắn (trung vị 3 netconn).

## 2. IP: tách được hay không
- `10.193.66.115` (máy tấn công): flow tới đây dương 67 (firefox 10, payload 16, winword 17, mshta 8, powershell 8, regsvr32 5, plugin-container 5, python 3), benign 5 (`python.exe` 4 + `svchost.exe` 1 trong tệp attack không nhãn; `python.exe` 4 trong tệp benign). Gần sạch nhưng không tuyệt đối.
- `10.193.242.113:9997`: dương 12 (firefox) nhưng **23 flow benign của firefox** (22 ở h2:9997 trong tệp benign) → IP này cũng là dịch vụ bình thường; không dùng làm tín hiệu độc.
- `34.107.221.82:80`, `142.250.191.225:443`: IP công cộng phổ biến, bị gán `root_cause` do hoạt động nền (theo README), tức nhãn dương bị lan nhầm.

## 3. Hệ quả cho thiết kế (đề xuất, chưa làm)
1. Với `firefox` ở ATLASv2, **không có field nào trong một flow** tách được dương/benign; mô hình bản B chỉ học được tên chương trình (nên "firefox = benign" từ OpTC xung đột, đúng như thầy nói).
2. Thứ có tín hiệu: **lịch sử của tiến trình** (đã từng kết nối tới IP không thuộc dải web thường như `10.193.66.115` trước thời điểm `t`) và **quan hệ cha–con** (con của tiến trình đã chạm IP tấn công). Đây là loại "block/graph tương tác" thầy gợi ý; tính được bằng sự kiện trước `t` (nhân quả). Hạn chế: chỉ 11/26 tiến trình dương chạm IP tấn công thật, nên bao phủ tối đa khoảng 2,601 / 7,696 flow dương sau lần chạm đầu (34%).
3. Phần nhãn do lan nhầm (7 tiến trình chạm IP công cộng gán `root_cause`, 8 tiến trình con) là **nhiễu nhãn**: không có tín hiệu thật nào để học; điểm cao trên ATLASv2 nếu có phải nêu rõ không đo phát hiện hành vi tấn công.
4. Chia trộn theo cửa sổ vẫn rò rỉ (10 cuộc tấn công gần giống nhau: cùng IP `10.193.66.115` lặp lại ở nhiều kịch bản).

## 4. Hạn chế của phân tích này
- 26 tiến trình `firefox` dương, 18/26 chạm seed; số mẫu nhỏ, chỉ mô tả, không kiểm định.
- Số liệu "ghi `.exe`" dùng regex đường dẫn người dùng/Temp; đã gồm tệp profile `.js` của Firefox ở một bước tách (đã loại ở bảng bằng điều kiện `.exe`, nhưng `n_dropped` trong `summary.txt` còn lẫn `prefs-1.js`; dùng cột bảng này, không dùng `n_dropped`).
- Không đọc cơ chế lan nhãn trong mã REAPr; kết luận về "root_cause → lan" dựa trên README, `.seeds` và quan sát dữ liệu, không phải mã.
- Chưa phân tích file `FileObject` mở/ghi của `payload.exe` hay moduleload bất thường (moduleload: dương 124.5 trung vị so với 68–74.5 nhưng chưa xem tên module).
