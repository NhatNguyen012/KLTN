# STEP 11C — Schema field của network event (file pipeline thực sự đọc)

## Trạng thái

**HOÀN TẤT và đã kiểm chứng.** File schema được code đọc trực tiếp; dùng nó thay cho danh sách hard-code cho kết quả **byte-identical** với artifact cũ.

## 1. Vấn đề

- Log eCAR thô tự mô tả: mỗi event đọc được ngay (tên field, giá trị chữ).
- Sau bước join, mỗi flow là một dòng parquet đọc được, nhưng **ý nghĩa từng field không đi kèm** mà rải rác ở `network_feature_contract.json`, `network_preprocess_spec.json` và trong code.
- Cùng một quy tắc (bảng cổng phổ biến `COMMON_PORTS`, danh sách feature) bị **chép hai lần**: trong `08b_loso_preprocess.py` (lúc fit preprocessing) và `04a_dl_shards_base.py` (lúc dựng shard). Nếu hai bản lệch nhau thì mã hóa lúc fit và lúc dựng shard khác nhau mà không báo lỗi.

## 2. Giải pháp

Một file duy nhất: `01_code/pipeline/network_event_schema_v1.json`, đọc qua `01_code/pipeline/network_schema.py` (kiểm tra cú pháp và tính nhất quán khi nạp).

| Phần trong file | Nội dung | Có được code đọc? |
|---|---|---|
| `fields` (34 field) | tên, nguồn (Bro hay eCAR-Bro hay dẫn xuất), kiểu, **vai trò**, **ý nghĩa tiếng Việt**, ví dụ thật, ghi chú | Mô tả; `network_schema.py` kiểm tra đủ trường và vai trò hợp lệ |
| `categorical.base_fields`, `derived_fields`, `reserved_ids` | danh sách cột categorical và ID `<UNK>`=0, `<MISSING>`=1 | **Có** (08b) |
| `numeric.fields` | 8 cột số ứng viên | **Có** (08b) |
| `port_class.common_ports` | bảng cổng phổ biến → tên (443 → `HTTPS`...) | **Có** (08b và 04a, nên không còn hai bản) |
| `roles`, `sample`, `model_input_groups`, các mô tả `*_vi` | giải thích vai trò, đơn vị sample, 4 nhóm đầu vào | Mô tả |

Trường `pipeline_reads` trong file liệt kê chính xác những khóa mà code đọc. Phần mô tả không được code đọc, nên không có chuyện tài liệu nói một đằng code làm một nẻo.

Vai trò của field: `join_audit` (chỉ để ghép/gom/chia split), `target` (nhãn), `categorical`, `numeric`, `binary`, `time`, `graph_only` (IP/cổng chỉ để dẫn xuất), `cross_check`, `not_used`.

Ví dụ một mục: `resp_bytes` — nguồn Bro `conn.resp_bytes`, kiểu `int`, vai trò `numeric`, "Số byte dữ liệu ứng dụng nhận về từ đích", ví dụ 2277.

## 3. Thay đổi code

| File | Thay đổi |
|---|---|
| `01_code/pipeline/network_event_schema_v1.json` (mới) | schema |
| `01_code/pipeline/network_schema.py` (mới) | nạp, kiểm tra, lấy bảng cổng |
| `01_code/pipeline/08b_loso_preprocess.py` | `BASE/DERIVED_CATEGORICAL_FIELDS`, `NUMERIC_FIELDS`, `RESERVED_IDS`, `COMMON_PORTS` lấy từ schema. Ở `--mode random` fingerprint ghi thêm `event_schema` (phiên bản + sha256 của schema) |
| `01_code/pipeline/04a_dl_shards_base.py` | `COMMON_PORTS` lấy từ schema (08c dùng file này) |
| `01_code/pipeline/11_check_schema.py` (mới) | kiểm tra schema khớp dữ liệu thật |

## 4. Kiểm chứng

1. **Hằng số và SQL:** các danh sách và `COMMON_PORTS` lấy từ schema bằng đúng giá trị cũ (so với bản trước khi sửa); SQL của `port_class_sql` ở cả 08b và 04a **trùng từng ký tự** với bản cũ.
2. **Preprocessing:** chạy lại `08b --mode random --freeze` cho `seed_1` bằng code mới vào thư mục tạm: `network_category_maps.json`, `network_numeric_stats.json`, `network_preprocess_spec.json` **byte-identical** với `10b_random_preprocess_v1/seed_1` (cùng SHA-256). Fingerprint mới chỉ thêm khóa `event_schema`.
3. **Shard:** chạy lại `08c --mode random --fold seed_1` bằng code mới vào thư mục tạm: **359/359 file `.npz`** giống hệt shard cũ ở mọi mảng (`x_cat`, `x_num`, `x_num_missing`, `x_bin`, `delta_t_log1p`, `sample_offsets`, `sample_labels`, `edge_*`), tổng **85,626,185 event** được so. Dataset hiện có (`seed_1`, `seed_2`, `seed_3`) và các model đã train **không cần build/train lại**. Thư mục tạm (4.4 GB) đã xóa.
4. **Schema so với dữ liệu thật** (`11_check_schema.py`, báo cáo `schema_check_seed_1.json`): 13/13 PASS, gồm 28 cột parquet đúng bằng 28 field nguồn của schema, danh sách categorical/numeric của spec/maps/stats khớp schema, bảng cổng khớp, hình dạng mảng trong một shard thật khớp số cột active, và không có field `join_audit/target/graph_only` lọt vào feature.

## 5. Cách dùng

```text
python 01_code/pipeline/11_check_schema.py --project-root D:\UIT\KLTNv2 ^
  --dataset-dir 03_datasets\random_network_dl_v1_1_15m\seed_1
```
- Thêm hoặc đổi feature: sửa schema (và vai trò), rồi chạy 08b và 08c; chạy `11_check_schema.py` để chắc schema vẫn khớp dữ liệu.
- Đổi bảng cổng: chỉ sửa một chỗ (`port_class.common_ports`).

## 6. Giới hạn (nói thẳng)

- Đây là **schema + từ điển**, không phải một file dữ liệu từng event đã mã hóa. Các event vẫn nằm trong parquet đã join (đọc được, mỗi dòng một flow) và trong shard `.npz` (mảng số, không đọc bằng mắt).
- Phần SQL dải cổng (0–1023, 1024–49151, 49152–65535), SQL loại IP và các thuật toán biến đổi vẫn nằm trong code; schema chỉ mô tả chúng ở các trường `*_vi`. Nếu sửa SQL thì phải cập nhật phần mô tả bằng tay.
- Các siêu tham số (tần suất tối thiểu của category, ngưỡng độ lệch chuẩn 0.01, ngưỡng cắt ±10) vẫn là tham số dòng lệnh của 08b, chưa đưa vào schema.
- Nếu muốn một **bảng event đã preprocess, đọc được, dùng để build shard** (hướng 2 mà bạn không chọn lần này), cần thêm một bước xuất parquet cho từng seed (vài GB mỗi seed) và sửa 08c.
