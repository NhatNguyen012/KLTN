# STEP 34 — Chẩn đoán chỉ trên TRAIN: BiLSTM fine-tune có fit được mẫu dương TRAIN khi học lâu hơn không

Ngày: 2026-10-23. Mã: `01_code/pipeline_v2/s15_train_diag.py` (chạy CPU hoặc Kaggle), `s15_notebooks.py` (sinh `04_notebooks/09a_BiLSTM_traindiag_Kaggle.ipynb`, `09b_Mixed_traindiag_Kaggle.ipynb`; **chưa chạy trên Kaggle**). Số liệu: `runs/diag_bilstm_fold0_cpu_e20_lr1e-3.{json,csv}`, `runs/log_bilstm_cpu_e20.txt`. **Đây là chẩn đoán, không phải kết quả chính.** Không đọc mẫu test của fold 0, không chạy OpTC TEST, không chọn gì theo chúng.

## Câu hỏi
STEP 33: checkpoint fine-tune không phát hiện được cả mẫu dương TRAIN của chính nó (BiLSTM 0/32; Mixed-Type chỉ phát hiện nhóm có `powershell.exe`). Nguyên nhân là (a) đầu vào không đủ tách, hay (b) huấn luyện quá ngắn / lr quá nhỏ?

## Thiết lập đã chạy (khác thiết kế STEP 30, cố ý)
BiLSTM, fold 0, seed 42, TRAIN = 753 mẫu (9 dương: 5 skrghosh + 4 FiveDirections; 2 trong 9 có `powershell.exe`), mô hình khởi tạo như fine-tune (mô hình gốc + từ điển mở rộng), **mở khóa toàn bộ tham số ngay từ đầu**, lr 1e-3 (10 lần giai đoạn B cũ), AdamW wd 1e-4, 20 epoch (so với 6), batch 32, `pos_weight` theo tỉ lệ TRAIN, **không replay OpTC**, CPU (≈ 50–250 s/epoch). Mỗi 4 epoch đo độ khớp trên chính 753 mẫu TRAIN.

## Kết quả (độ khớp TRAIN, 9 mẫu dương, 744 âm)
| Epoch | Loss | TP tại 0.5 | FP tại 0.5 | ROC-AUC | PR-AUC |
|---:|---:|---:|---:|---:|---:|
| 1 | 4.51 | 0/9 | 0 | 0.31 | 0.009 |
| 4 | 2.86 | 0/9 | 0 | 0.84 | 0.161 |
| 8 | 1.51 | 6/9 | 13 | 0.91 | 0.473 |
| 12 | 1.15 | 7/9 | 11 | 0.98 | 0.781 |
| 16 | 1.46 | 8/9 | 6 | 0.996 | 0.917 |
| **20** | 0.43 | **8/9** | **0** | **0.998** | **0.939** |
Tại ngưỡng VAL OpTC (0.9956): 5/9, FP 0. Xác suất trung vị mẫu dương 0.997, mẫu âm 0.0006; mẫu âm cao nhất 0.48 (6 mẫu âm > 0.1). Loss không giảm đều (epoch 16 tăng lại 1.15 → 1.46): lr 1e-3 khá nhiễu.

Mẫu dương còn lại (xác suất sau epoch 20): 1 mẫu **không fit** (`f1a53a38…`, FiveDirections, `firefox.exe`, 1 flow dương trong 512, p = 0.026); 8 mẫu fit (p 0.96–1.0), trong đó **chỉ 2 mẫu có `powershell.exe`** (`a1a1a95c…`, `775ef78d…`) còn **6 mẫu không có `powershell.exe`** — gồm 3 mẫu FiveDirections `svchost.exe` và 3 mẫu skrghosh token lạ (`<UNK>`), có mẫu chỉ 1 flow dương trong 512 flow.

## Đọc kết quả
- **Với cấu hình cũ (6 epoch, lr nhỏ, replay), 0/32 chủ yếu là do huấn luyện quá ngắn/lr nhỏ chứ không phải đầu vào hoàn toàn không phân tách được**: cùng kiến trúc và cùng đầu vào, 20 epoch lr 1e-3 đã khớp 8/9 mẫu dương TRAIN với 0 báo nhầm tại 0.5, kể cả các mẫu không có `powershell.exe`. Cần nhớ đây là *một fold, một seed, một mô hình (BiLSTM)*; chưa chạy Mixed-Type.
- **Không được suy ra là mô hình khái quát được.** Fit 9 mẫu dương trong 753 bằng mạng có `delta_t` liên tục và tên tiến trình có thể là **ghi nhớ (memorization)** các cửa sổ cụ thể, không phải học quy luật tấn công. Chẩn đoán trên TRAIN không cho biết điều này; muốn biết phải đo trên mẫu chưa thấy (TEST fold 0, hoặc chạy lại 3 fold), tức mở TEST lần hai (phải ghi rõ). Một mẫu (1 flow dương/512, `firefox.exe`) vẫn không fit, đúng giả thuyết H2 của STEP 30 cho riêng trường hợp này.
- Chưa đo quên: lần chẩn đoán này không có replay, không đánh giá OpTC. Kết quả không nói gì về việc replay có cản trở việc fit hay không (hai cấu hình có replay có sẵn trong notebook 09a/09b).

## Hạn chế
Một fold (0), một seed, BiLSTM, một cấu hình (không quét lr/epoch), CPU; không có replay; độ khớp trên 9 mẫu dương (1 mẫu = 11 điểm recall); không tách nhiễu seed; mẫu dương skrghosh có nhãn lan theo cây tiến trình, FiveDirections nhãn mức tiến trình (xem STEP 29/30). Cấu hình chạy khác thiết kế STEP 30 nên **không** thay thế kết quả STEP 33.
