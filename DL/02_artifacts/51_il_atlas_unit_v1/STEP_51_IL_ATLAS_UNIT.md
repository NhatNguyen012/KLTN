# STEP 51 — Gói IL OpTC → ATLASv2 với đơn vị mẫu (máy, chương trình, cửa sổ 15 phút)

Ngày 2026-11-07. Lý do: STEP 50 (F1 TEST 0.35–0.68) — cửa sổ trộn firefox với các chương trình tấn công hiếm; probe LightGBM đơn vị mới ROC 0.91 (firefox riêng 0.735).

## Sản phẩm
- Dữ liệu: `02_artifacts/51_il_atlas_unit_v1/data/{flows_atlas.parquet, windows.csv}`, `checks_flows.json`; mã `01_code/pipeline_v2/s38_atlas_unit.py`, `s38_prepare_il_unit.py`, `s38_notebooks.py`, `s38_smoke_test.py`.
- Gói Kaggle: `03_datasets/il_atlas_unit_kaggle_upload(.zip)` (6.9 MB; zip 1.3 MB). Notebook `04_notebooks/12a_BiLSTM_IL_ATLASv2_unit_Kaggle.ipynb`, `12b_Mixed_IL_ATLASv2_unit_Kaggle.ipynb`. Gắn 2 dataset: `v2_network_dl_kaggle_upload` + `il_atlas_unit_kaggle_upload` (chỉ gắn MỘT gói IL, vì notebook tìm `ft_manifest.json` duy nhất). Trainer vẫn là `s36_il_train.py` (không đổi kiến trúc, đầu vào bản B).

## Đơn vị mới
- `hostname` mới = `host|app_family`, nên mỗi mẫu = flow của một chương trình trong một cửa sổ. 885 mẫu-đơn-vị (cũ: 456 cửa sổ), 99 dương: firefox 59, payload.exe 16, plugin-container 5, winword 4, powershell 4, python 3, mshta 3, osppsvc 2, regsvr32 2, explorer 1. 6 đơn vị > 512 flow (cắt chunk). 25 đơn vị có cả flow dương lẫn âm.
- fold/vb **thừa hưởng** từ cửa sổ gốc (máy, cửa sổ) ⇒ các chương trình trong cùng cửa sổ nằm cùng fold. VAL fold 0 = 125 âm + 27 dương.
- `delta_t` giờ tính giữa các flow của cùng chương trình.
- Từ điển mở rộng và replay OpTC giữ nguyên quy tắc STEP 48 (replay vẫn là mẫu cửa sổ OpTC thật ⇒ đơn vị replay khác đơn vị ATLASv2; ghi nhận).
- Kiểm tra shards PASS; CPU smoke BiLSTM + Mixed chạy hết, khớp khởi tạo chênh logit 0 (chỉ kiểm mã, không đọc F1).

## Hạn chế
1. Firefox (59/99 mẫu dương) vẫn giống hệt firefox benign trên đầu vào ⇒ kỳ vọng F1 cải thiện chủ yếu ở các chương trình hiếm; firefox riêng probe chỉ ROC 0.735. Không hứa đạt 0.9.
2. Đổi đơn vị so với OpTC (cửa sổ/máy): ma trận OpTC TEST vẫn đo mô hình gốc trên đơn vị cũ.
3. Còn các hạn chế STEP 48/50: nhãn mức tiến trình, chia trộn theo cửa sổ, 10 cuộc tấn công gần giống nhau, ít dương (VAL fold ~27 mẫu dương).
4. Chương trình tấn công hiếm (payload.exe…) chính là tên chương trình ⇒ đường tắt kiểu `app_family`, như đã nêu cho OpTC (powershell.exe).
