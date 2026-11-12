# STEP 53 — Gói IL OpTC → ATLASv2 với nhãn tinh chỉnh kiểu Nguyễn

Ngày 2026-11-07. Theo yêu cầu: dùng nhãn LabelRefiner của Nguyễn, không quan tâm rò rỉ (như OpTC), huấn luyện giống Nguyễn (4 category + delta_t, mẫu = cửa sổ/chunk theo máy, mở rộng từ điển, replay OpTC).

## Sản phẩm
- Mã: `01_code/pipeline_v2/s39_atlas_flows.py`, `s39_prepare_il_refined.py`, `s39_notebooks.py`, `s39_smoke_test.py`; dữ liệu `02_artifacts/53_il_atlas_refined_v1/data/`.
- Gói: `03_datasets/il_atlas_refined_kaggle_upload(.zip)` (1.34 MB, zip dùng `/`). Notebook: `04_notebooks/13a_BiLSTM_IL_ATLASv2_refined_Kaggle.ipynb`, `13b_Mixed_IL_ATLASv2_refined_Kaggle.ipynb`; gắn `v2_network_dl_kaggle_upload` + `il_atlas_refined_kaggle_upload`.
- Trainer `s36_il_train.py` (mở dần A→B1→B2→C; freeze bằng requires_grad + mask hàng embedding cũ; VAL chọn checkpoint/ngưỡng).

## Nhãn
Tái hiện luật netconn của `label_refiner.py`: dương = `label_proc`=1 VÀ sau mốc tấn công đầu tiên của kịch bản VÀ (với firefox/winword/excel/powerpnt/explorer) đích ∈ {10.193.66.115, 192.168.223.129} hoặc domain ortrta.net. Kết quả: **51 flow dương** (từ 7,761), 17 cửa sổ dương. (Chưa tái hiện luật file/process/module của host vì DL dùng flow; chưa dùng file `.seeds` ⇒ có thể thiếu vài flow dương so với bản gốc của Nguyễn.)

## Chia
Mẫu = cửa sổ 15 phút/máy, 3 fold chia trộn theo cửa sổ (seed 42); cửa sổ dương gom một tầng để chia đều (6/6/5); VAL dùng 3 nhóm (không phải 5) để có thêm dương. Mẫu (dương): fold 0 train 198 (8) / val 104 (3) / test 161 (6); fold 1: 203 (7) / 104 (4) / 156 (6); fold 2: 205 (7) / 112 (5) / 146 (5).

## Hạn chế (quan trọng)
1. **Chỉ 5–6 mẫu dương mỗi TEST, 3–5 mỗi VAL, 7–8 mỗi TRAIN**: F1 sẽ rất nhảy (một mẫu = ±0.1), ngưỡng chọn trên VAL không ổn định. Không thể tái tạo test 768 mẫu/20 dương của Nguyễn (khác cách chia/chunk).
2. 47/51 flow dương tới cổng 8080/8443/9999/8000 (có trong `resp_port_class`): nhãn gần như là luật theo cổng/IOC ⇒ F1 cao nếu có chủ yếu phản ánh luật (người dùng đã chấp nhận, không quan tâm rò rỉ).
3. Nhãn phụ thuộc IOC và mốc giờ gõ tay của Nguyễn; chia trộn theo cửa sổ.
4. CPU smoke chạy hết, khớp khởi tạo chênh 0 (chỉ kiểm mã).
