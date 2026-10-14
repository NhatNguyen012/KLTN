# S5 — Validate (kiểm tra chéo và giải mã ngược)

Ngày chạy: 2026-10-13. Mã: `01_code/pipeline_v2/s5_validate.py` (44 giây). Kết quả: **PASS**.

## Đã kiểm
| Kiểm tra | Kết quả |
|---|---|
| `checks.json` của S1, S2, S3, S4 | cả bốn PASS |
| Phạm vi fit S3 = cửa sổ TRAIN của S2 | khớp (77,281 cửa sổ, 59,902,514 flow); không dùng nhãn/VAL/TEST |
| Mỗi cửa sổ chỉ ở một split; `samples.csv` khớp `windows.csv` | đúng; nhãn cửa sổ = max nhãn sample |
| Sample dương theo scenario (train / val / test) | SC1 59 / 10 / 9 · SC2 338 / 72 / 72 · SC3 4 / 1 / 1 |
| **Giải mã ngược 400 sample** (150 dương, 250 benign) so với flow raw trong S1 | cùng số flow; 0 flow sai id category; sai số z-score lớn nhất 4.69e-07; 0 sai cờ thiếu / `has_missed_bytes` / nhãn; sai số `delta_t` lớn nhất 2.38e-07 |

Từng sample đã so: `sample_verification.csv`.

## Ý nghĩa
Chứng minh đường đi raw → shard không làm mất hay đổi flow, và bước mã hóa SQL (S4) khớp với quy tắc Python đọc được (S3, `preview_record.json`). Sau bước này có thể đóng gói (S6) và train.
