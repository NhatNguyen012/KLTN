# STEP 48 — Dataset và notebook Kaggle cho IL OpTC → ATLASv2 (BiLSTM và Mixed-Type)

Ngày: 2026-11-05. Chưa train (train do Lâm chạy trên Kaggle). Mã: `01_code/pipeline_v2/s36_atlas_flows.py` (flow + fold), `s36_prepare_il_atlas.py` (gói), `s36_il_train.py` (huấn luyện, dùng lại hàm của `s14_ft_train.py`), `s36_notebooks.py`, `s36_smoke_test.py`. Gói: `03_datasets/il_atlasv2_kaggle_upload/` (6.4 MB; bản nén `.zip` 1.3 MB). Notebook: `04_notebooks/10a_BiLSTM_IL_ATLASv2_Kaggle.ipynb`, `10b_Mixed_IL_ATLASv2_Kaggle.ipynb`.

## 1. Dữ liệu ATLASv2 trong gói
- Nguồn: bảng netconn Carbon Black đã trích ở STEP 40 (29,744 dòng) → bỏ `ACTION_CONNECTION_LISTEN` và dòng không có đầu xa → **29,565 flow, 7,761 dương** (nhãn REAPr mức **tiến trình**; firefox 27,287 flow trong đó 7,696 dương).
- Mã hóa theo đúng bản B (4 category `app_family, proto, resp_port_class, image_dir_class` + `delta_t_log1p`), cùng định dạng shards với OpTC v2. Cửa sổ 15 phút theo `hostname = atlas_<máy>_<kịch bản>`, tối đa 512 flow/mẫu: **456 cửa sổ (59 dương) → 463 mẫu (63 dương)**, độ dài trung vị 16 flow.
- **Từ điển mở rộng theo fold** (chỉ nối thêm id mới, id cũ giữ nguyên; token có ≥ 5 flow trong TRAIN của fold): `app_family` +9 đến +12 token (discord.exe, mmc.exe, iexplore.exe, lsass.exe, osppsvc.exe, payload.exe, …; id từ 61), `resp_port_class` +3 đến +4 (EPHEMERAL, PORT_135_RPC, PORT_123_NTP, …), `proto` và `image_dir_class` không có token mới. Hàng embedding mới khởi tạo bằng bản sao `<UNK>`.
- **Chia trộn theo cửa sổ, 3 fold, seed 42** (đúng yêu cầu của thầy; không host-disjoint): cửa sổ dương phân tầng theo kịch bản, cửa sổ âm theo kịch bản và ngày. Trong mỗi fold: **TEST = fold k; VAL = 1/5 phần còn lại (vb = 0); TRAIN = phần còn lại**.

| Fold | TRAIN (dương) | VAL (dương) | TEST (dương) |
|---|---|---|---|
| 0 | 227 (25) | 73 (15) | 163 (23) |
| 1 | 237 (33) | 74 (9) | 152 (21) |
| 2 | 252 (32) | 63 (12) | 148 (19) |

- **Replay OpTC thật** (`replay_R.csv`): toàn bộ 401 cửa sổ dương TRAIN + 1,601 cửa sổ âm TRAIN của OpTC v2 (không tổng hợp), đọc từ shards của gói OpTC v2 trên Kaggle.

## 2. Huấn luyện (`s36_il_train.py`)
- Kiểm tra khởi tạo: mô hình mở rộng (chưa train) phải cho cùng logit với mô hình gốc khi id mới đổi thành `<UNK>` (đã kiểm: chênh 0.000000 ở cả hai mô hình trong chạy thử CPU).
- **Mở dần (STEP 44):** A (hàng embedding mới + đầu phân loại, lr 1e-3, hàng embedding cũ bị chặn gradient) → B1 (+ encoder sự kiện) → B2 (+ tầng chuỗi, hệ số lr 0.5) → C (+ embedding cũ, hệ số lr 0.1). Weight decay = 0 cho embedding. Mỗi giai đoạn tối đa 8 (A) hoặc 10 epoch, dừng sớm nếu VAL không cải thiện 3 epoch, rồi nạp lại checkpoint tốt nhất trên VAL.
- Mỗi epoch trộn thêm 600 mẫu replay OpTC (150 dương).
- **Checkpoint và ngưỡng chỉ chọn trên VAL** (VAL PR-AUC + 0.1 × F1; ngưỡng = giữa cao nguyên F1 tối đa trên VAL). TEST và OpTC TEST tính **một lần**.
- Báo cáo theo quyết định đã chốt: **ma trận nhầm lẫn TRAIN, VAL, TEST (ATLASv2) và OpTC TEST**, thêm TEST theo kịch bản; **không** có so sánh trước/sau fine-tune.
- Siêu tham số mặc định chưa được tinh chỉnh: BiLSTM lr B 3e-4 (batch 32), Mixed-Type lr B 1e-4 (batch 16).

## 3. Cách chạy trên Kaggle
1. Dataset 1: `v2_network_dl_kaggle_upload` (OpTC v2, bạn đã có). Dataset 2: tải `il_atlasv2_kaggle_upload.zip` lên thành một dataset mới (cần đúng một `ft_manifest.json`).
2. Tạo notebook từ `10a` (BiLSTM) hoặc `10b` (Mixed-Type), gắn **cả hai** dataset, bật GPU, chạy hết; tải `*_il_atlasv2_seed42.zip` về.
3. Đặt zip kết quả vào `output_kaggle/`; tôi sẽ đọc và báo cáo.

## 4. Kiểm tra đã làm
- `s10_shards` qua kiểm tra (số flow/dương khớp, mã hóa lại 300 flow bằng Python khớp shards, `sample_id` duy nhất) cho cả 3 fold.
- Chạy thử **CPU** (1 epoch mỗi giai đoạn, 60 mẫu replay, 150 mẫu âm OpTC TEST, fold 0) cho cả BiLSTM và Mixed-Type: chạy hết đến ghi file kết quả. Đây chỉ kiểm tra mạch chạy; **không đọc số liệu F1 của lần chạy thử** vì chỉ 1 epoch.
- Lỗi bắt được khi chạy thử và đã sửa: ngưỡng gốc của Mixed-Type là 1.0 (ngưỡng trên xác suất fp16) nên đổi sang logit bằng cách chặn ở `1 − 2^-12`.

## 5. Khác với thí nghiệm IL BiLSTM của Nguyễn (STEP 45)
| | Nguyễn (Run 12) | Gói này |
|---|---|---|
| Nhãn ATLASv2 | IP/cổng C2 + mốc thời gian (73 sự kiện dương) | REAPr mức tiến trình (7,761 flow dương) |
| Chia | theo kịch bản (TEST s4, m6; 20 cửa sổ dương) | trộn theo cửa sổ, 3 fold (theo thầy) |
| Replay và OpTC TEST | **tổng hợp** (`generate_sequence`) | **OpTC thật** (shards v2) |
| Ngưỡng | 0.245, thiết kế lặp nhìn TEST | chọn trên VAL của từng fold |
| Kết quả đã báo | TEST F1 0.7727 (17/20), ROC-AUC 0.9872 | chưa có |

## 6. Về mục tiêu "đạt 0.9 như bạn"
- Số của Nguyễn là **F1 0.7727** trên TEST ATLASv2 (ROC-AUC 0.9872); "F1 1.0000 trên OpTC" đo trên dữ liệu tổng hợp nên không dùng làm chuẩn. Không có số 0.9 nào đáng tin để đuổi theo.
- Tôi **không** chỉnh cấu hình theo TEST để chạm một con số. Notebook chọn mọi thứ trên VAL; kết quả là gì thì báo đúng như vậy.
- Kỳ vọng thực tế (chưa đo, chỉ là suy luận từ STEP 40–42): firefox chiếm 99.7% flow ATLASv2 và cả nhãn 0 lẫn 1; tín hiệu tách được chủ yếu nằm ở cửa sổ có LOLBin (winword, mshta, regsvr32, powershell, payload.exe) và ở số lượng/nhịp kết nối. Với chia trộn theo cửa sổ (rò rỉ giữa các cửa sổ kề và 10 cuộc tấn công gần giống nhau), điểm TEST có thể cao nhưng chỉ đo khả năng nhận ra mẫu đã thấy; điểm có thể thấp ở cửa sổ chỉ có firefox bị gán dương do kế thừa nhãn (8/26 tiến trình) hoặc chạm IP công cộng gán nhầm.

## 7. Hạn chế
- 59 cửa sổ dương, 10 cuộc tấn công gần như giống nhau, nhãn mức tiến trình; một seed, VAL chỉ 9–15 mẫu dương nên ngưỡng không ổn định.
- `payload.exe` là tên chương trình của kẻ tấn công trong ATLASv2: token mới này tự nó là đường tắt (16/16 flow dương).
- Chưa có THEIA (cần dựng flow từ raw CDM18; làm sau nếu muốn).
- OpTC thiếu cmdline/cha trong eCAR-Bro nên chưa dùng ngữ cảnh cha–con ở đây; đây vẫn là đầu vào bản B.
