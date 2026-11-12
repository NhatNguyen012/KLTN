# optc_il — Incremental learning OpTC → ATLASv2 cho BiLSTM Network-DL

Báo cáo: [`analyst/dl_optc_il_20261112.md`](../../../analyst/dl_optc_il_20261112.md).

| File | Vai trò |
|---|---|
| `vendor/05b_train_bilstm.py`, `vendor/network_dl_dataset_v1_1.py` | Mã gốc của mô hình OpTC, tách nguyên văn từ `DL/04_notebooks/06e_BiLSTM_Kaggle_v2_subsetB.ipynb` |
| `contract.py` | Hợp đồng đầu vào bản B (`app_family`, `proto`, `resp_port_class`, `image_dir_class` + `delta_t`), quy tắc chép từ `DL/01_code/pipeline_v2/v2_common.py`; từ điển OpTC đọc từ `preprocess_spec.json` |
| `il_model.py` | Mô hình OpTC gốc + phần mới (mở rộng từ điển, nhánh ngữ cảnh host, BiLSTM thứ hai, event head, stage head, gate) |
| `train_il.py` | Huấn luyện IL: lịch freeze A→B→C hoặc fine-tune toàn bộ, replay OpTC thật, chọn epoch/ngưỡng trên VAL, TEST một lần |
| `run_matrix.sh` | 6 cấu hình × 3 seed |
| `summarize.py` | Bảng mean ± std |
| `plot_confusion.py` | Vẽ confusion matrix (ATLASv2 binary, OpTC trước/sau, ATLASv2 last stage) từ `result.json` |

Dữ liệu vào:
- ATLASv2: `output/bilstm_v9_20261112/dataset_v9b_stage_optc.pkl` (tạo bởi `bilstm_v9/build_dataset.py --out-name dataset_v9b_stage_optc.pkl`; đã có trường `optc_raw`).
- OpTC (chỉ đọc): `/mnt/SSD_Data/optc/DL/02_artifacts/22_v2_pipeline/S4_shards`.
- Mô hình gốc: `../pretrained_optc_model` (trùng md5 với `DL/05_models/v2_subsetB/bilstm`).

```bash
cd /mnt/SSD_Data/optc/IL/dataset_1-ATLASv2/code/DL
python3 bilstm_v9/build_dataset.py --work output/bilstm_v9_20261112 --out-name dataset_v9b_stage_optc.pkl  # nếu chưa có
bash optc_il/run_matrix.sh output/optc_il_<ngày>
```
