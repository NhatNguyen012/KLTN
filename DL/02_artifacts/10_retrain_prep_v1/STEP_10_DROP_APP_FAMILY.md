# STEP 10 (Phần A) — Tuỳ chọn `DROP_APP_FAMILY` cho notebook train

## Trạng thái

**HOÀN TẤT (đã kiểm tra local, chưa chạy trên Kaggle).** Không train local. Không build lại shards. Không đổi kiến trúc model.

## Mục đích

Theo STEP 09B §4.2 (E2/A1): đo xem model còn nhận ra beacon chỉ từ hành vi mạng khi bỏ shortcut `app_family` (`powershell.exe` ⇒ 100% malicious, rule một dòng F1 test 0.975).

## Thay đổi

| File | Loại | Ghi chú |
|---|---|---|
| `04_notebooks/06b_BiLSTM_Kaggle_v2.ipynb` | mới | sinh từ `06_BiLSTM_Kaggle.ipynb` |
| `04_notebooks/07b_Mixed_Type_Self_Attention_Kaggle_v2.ipynb` | mới | sinh từ `07_Mixed_Type_Self_Attention_Kaggle.ipynb` |
| `01_code/pipeline/10_make_noapp_notebooks.py` | mới | script vá notebook; mỗi lần vá có `assert` số lần khớp; từ chối ghi đè file đích |
| `04_notebooks/06_…ipynb`, `07_…ipynb` | **giữ nguyên** | không đụng |

### Trong notebook v2

1. **Cell cấu hình mới** (ngay sau cell import đầu tiên):
   - `DROP_APP_FAMILY = False` (mặc định).
   - `RUN_SUFFIX = ''` (vd. `'_seed1'` khi train trên dataset random-split `seed_k`).
   - `RUN_NAME = bilstm_v2_{noapp|full}{RUN_SUFFIX}` (BiLSTM) hoặc `mixed_v2_{noapp|full}{RUN_SUFFIX}` (Mixed-Type).
   - Thư mục output và file zip dùng `RUN_NAME`, không trùng `05_models/06_bilstm_baseline_v1` hay `07_mixed_type_attention_v1`.
2. **Cell lệnh train** tự thêm `--drop-app-family` khi `DROP_APP_FAMILY = True`.
3. **Module dataset nhúng** (`network_dl_dataset_v1_1.py`): `PackedNetworkDataset(..., drop_app_family=False)`.
   - Khi bật: đọc `preprocessing/network_preprocess_spec.json`, tìm cột `app_family` **theo tên**, assert nó là cột 0 và `<UNK>` = id 0 trong category map; sau đó `x_cat[:, 0] = 0` trên **bản copy** của slice (cache shard không bị sửa).
   - Áp dụng cho train, val và test (cùng một lớp dataset).
4. **Script train** (`05b_train_bilstm.py`, `05e_train_mixed_type_attention.py`): thêm `--drop-app-family`, truyền vào 3 dataset, kiểm tra batch đầu tiên (cột `app_family` toàn 0, nếu không thì raise), ghi `"drop_app_family"` vào `config.json`.
5. **`05e_attention_audit.py`**: đọc `drop_app_family` từ `config.json` của model để audit chạy trên đúng dữ liệu lúc train.
6. **Cell sanity DataLoader**: dùng cùng cờ và in tập id của cột `app_family` trong batch.

### Lưu ý diễn giải

- Embedding `app_family` **vẫn tồn tại** (kiến trúc không đổi) nhưng chỉ nhận một id hằng ⇒ hoạt động như một bias học được, không mang thông tin.
- Bỏ `app_family` không loại hết mọi shortcut: `service`, `resp_port_class`, timing/bytes vẫn mang chữ ký beacon (STEP 09 §7, attention audit). Đó chính là điều ablation này muốn đo.
- `pos_weight`, checkpoint (VAL PR-AUC), threshold (VAL F1) không đổi ⇒ so sánh A0 vs A1 công bằng.

## Kiểm tra đã làm (local, CPU, không train)

- Giải mã code nhúng của 2 notebook mới, `py_compile` tất cả module: OK.
- Trên shards thật `03_datasets/network_dl_v1_1_15m` (split `val`), cho cả hai bản dataset module (06b và 07b): với 3 positive + 3 sample đầu, `x_cat[:, 0] == 0` khi bật, các cột 1..4 **giống hệt** bản không bật, và đọc lại bản không bật sau đó vẫn nguyên (cache không bị sửa). Sample đầu có `app_family` id 5 (`ping.exe`) → 0.
- `collate_sequence_batch` trên batch đã drop: `x_cat[:, :, 0]` chỉ có giá trị `{0}`.
- `--help` của 2 script train hiển thị `--drop-app-family` (stub `sklearn` vì máy local không có).
- **Chưa chạy** trên Kaggle (theo yêu cầu không train local). Lần chạy đầu trên Kaggle nên xem dòng `[DROP app_family] …` và `app_family ids in batch: [0]` trong log.

## Sửa lỗi phát hiện khi đối chiếu với dataset random-split

Script train gốc đọc `manifest["source"]["step04c_preprocess_fingerprint"]`. Dataset build bằng 08c (LOSO/random) ghi khóa `step05f_c_preprocess_fingerprint` ⇒ notebook gốc sẽ `KeyError` trên dataset mới. Notebook v2 dùng `.get("step04c_…") or ["step05f_c_…"]` (chạy với cả dataset cũ và mới); đã kiểm tra biểu thức trên manifest của `network_dl_v1_1_15m` và `random_network_dl_v1_1_15m/seed_1`. Cũng đã kiểm tra `drop_app_family` trên shards của `seed_1` (split test): các cột khác giữ nguyên, cột `app_family` → 0.

## Sửa lỗi resolver dataset trên Kaggle (phát hiện khi chạy thật)

Lỗi `FileNotFoundError: …/dataset-kltn/split/network_sample_manifest.csv` trên Kaggle: dataset được upload dưới dạng các file zip (`split.zip`, `shards.zip`…) nên Kaggle tự giải nén thành thư mục lặp tên (`split/split/…`, `shards/shards/…`, `preprocessing/preprocessing/…`). Resolver của notebook 06 gốc thấy thư mục `split` tồn tại nên trả về root "thô" (thiếu một cấp), còn resolver của notebook 07 có `unwrap_same_name_folder` nên không gặp lỗi. Notebook 06b nay dùng resolver của 07; cả 06b và 07b thêm chốt chặn: nếu tìm thấy **nhiều** `dataset_manifest.json` (ví dụ gắn nhầm dataset LOSO có 3 holdout) thì báo lỗi thay vì âm thầm chọn một cái. Đã mô phỏng bố cục lồng nhau từ các zip thật của `network_dl_v1_1_15m` và chạy resolver + `PackedNetworkDataset(..., drop_app_family=True)`: OK (mô phỏng dùng copy thay symlink vì Windows không cấp quyền symlink; Kaggle chạy Linux).

## Cách dùng

1. Upload dataset lên Kaggle (dataset cũ hoặc dataset random-split `seed_k` từ STEP 10C).
2. Mở notebook v2, đặt `DROP_APP_FAMILY = True/False` (và `RUN_SUFFIX`), Run All.
3. So sánh `full` và `noapp` trên cùng dataset/seed; chỉ kết luận khi chênh lệch vượt dao động giữa các seed (CLAUDE.md).
