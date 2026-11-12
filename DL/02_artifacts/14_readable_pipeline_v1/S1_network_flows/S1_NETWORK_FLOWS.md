# S1 — Bảng flow đã ghép (một dòng = một flow)

## Mục đích
Ghép thông tin **mạng** (Bro `conn`) với thông tin **tiến trình** (eCAR-Bro) để mỗi flow biết "tiến trình nào tạo ra nó". Đây là bảng gốc cho nhánh network.

## Đầu vào
- Bro `conn.log` (S0): `uid, ts, 5-tuple, bytes, pkts, conn_state, label, ...`
- eCAR-Bro (S0): `bro_uid, image_path (tên tiến trình), direction, l4protocol, ...`

## Cách làm (STEP 02, đã chạy trước đó)
1. Ghép theo `Bro conn.uid = eCAR-Bro bro_uid`.
2. Giữ một dòng mỗi `uid` (khử trùng); đếm số lần xuất hiện ở `ecar_occurrence_count`.
3. Từ `image_path` lấy `app_family` (tên file thực thi, chữ thường).
4. Ghi ra parquet chia theo `split` (gốc STEP 02) và `date` (UTC).

## Đầu ra
Bảng đầy đủ nằm ở `02_artifacts/02_network_joined_v1/joined/` (parquet, **không** mở được bằng Excel). Ở đây có bản đọc được:

| File | Nội dung |
|---|---|
| `fields_flow.csv` | 34 trường của một flow: vai trò (đặc trưng, nhãn, chỉ để ghép...), kiểu, nguồn, ý nghĩa, ví dụ |
| `flows_sample.csv` | 2,000 flow ngẫu nhiên (seed 42): 1,000 flow tấn công + 1,000 flow bình thường; có cột `ts_utc` đọc được |
| `flows_overview_by_date_split.csv` | Số flow, số flow tấn công, số host theo ngày (UTC) và tập `split` gốc |
| `sample_flow.json` | Hai flow thật: một beacon C2 của `sysclient0618` và một flow Firefox bình thường |

Ví dụ một flow tấn công (rút gọn từ `sample_flow.json`): `hostname=sysclient0618`, `app_family=powershell.exe`, `resp_h=202.6.172.98`, `resp_p=443`, `service=ssl`, `orig_bytes=667`, `resp_bytes=2277`, `label=1`.

## Con số đã kiểm chứng (đếm trực tiếp từ parquet)
- **92,045,755 flow**, **24,721 flow tấn công**, **743 host**.

## Phát hiện quan trọng: một phần flow độc hại bị loại khỏi bảng này
Nhãn mạng của A New Hope (`labelling/network`, file `conn-*.log`) có **29,311** flow độc hại; bảng đã ghép chỉ có **24,721**. Chênh 4,590 flow, tập trung ở:
| Host | Flow độc hại trong Bro (A New Hope) | Có trong bảng đã ghép |
|---|---:|---:|
| `dc1` | 4,190 | 0 (không có trong dữ liệu eCAR-Bro của pipeline) |
| `sysclient0051` (SC3) | 488 | 163 |
| `sysclient0351` (SC3) | 67 | 26 |
| `sysclient0501` (SC2) | 972 | 944 |

Với `sysclient0051`, 325 flow thiếu **hoàn toàn không có mặt trong bảng đã ghép** (kể cả với nhãn 0). Trong đó 317 flow có `conn_state = REJ` và 320 tới cổng 8080, đúng loại flow bị từ chối của SC3. Nghi ngờ nguyên nhân là bước ghép cần bản ghi eCAR-Bro (flow không có tiến trình tạo ra, ví dụ kết nối bị từ chối ngay, bị loại), **nhưng chưa kiểm chứng**. Hệ quả: nhánh network của STEP 10 không bao giờ thấy khoảng 2/3 flow độc hại của SC3, và đây là một lý do SC3 khó bắt. Cần cân nhắc một biến thể ghép kiểu left join (giữ flow không có eCAR-Bro, `app_family = <MISSING>`) ở thí nghiệm sau; **không làm ở bước này** vì sẽ phá tính so sánh của 12 run hiện có.

## Phát hiện thứ hai: độ phủ eCAR-Bro rất khác nhau giữa các ngày
Bảng đã ghép chỉ gồm flow **có bản ghi eCAR-Bro**. Độ phủ này không đều (số liệu từ `flows_overview_by_date_split.csv` và `02_artifacts/11_dataset_overview_v1/network_by_day_edt.csv`):
| Ngày (UTC) | Flow đã ghép | Flow tấn công | Ghi chú |
|---|---:|---:|---|
| 17–22/9 | 0.7–17.8 triệu mỗi ngày | 0 | benign; ~99.7–99.9% là `firefox.exe` |
| 23/9 | 12,653,852 | 9,030 | SC1 |
| 24/9 | 4,264,024 | 5,525 | SC2 |
| 25/9 | **15,738** | 10,166 | SC2 (đêm), SC3; chỉ 0.04% là firefox |
Một ngày Bro `conn.log` có hàng chục triệu dòng (đếm trực tiếp ngày 25/9 UTC: **23,135,463**), nhưng bảng đã ghép chỉ giữ 15,738. Hai hệ quả cần nhớ:
1. **Dữ liệu benign trong bảng gần như chỉ là flow Firefox** (99.7–99.9% các ngày 17–24/9). Đây là gốc của "đường tắt `app_family`": benign = firefox, tấn công = tiến trình khác. Đây là đặc điểm của cách thu thập eCAR-Bro, không phải lỗi của pipeline, nhưng nó làm bài toán dễ hơn thực tế.
2. **Ngày 25/9 (SC3) gần như không có flow benign** trong bảng; benign của host SC3 chủ yếu đến từ các ngày trước.
Biến thể left join (giữ mọi flow Bro, `app_family = <MISSING>` khi không có eCAR-Bro) sẽ tăng số dòng lên hàng trăm triệu và đổi bản chất dữ liệu benign; vì vậy cần một lần đo quy mô riêng trước khi chạy.

## Đầu ra này đi đâu tiếp
- Cột `label` → S2 (nhãn).
- `hostname` → S3 (chia split).
- Các cột đặc trưng → S4 (mã hóa), rồi S5 (gom thành cửa sổ).

## Hạn chế
- `flows_sample.csv` là mẫu cân bằng, **không** phản ánh tỉ lệ thật (flow tấn công chỉ 0.027% tổng).
- `split_step02_original` là split gốc của STEP 02; split dùng để train (3 seed ngẫu nhiên) nằm ở S3.
