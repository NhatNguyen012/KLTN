# Deep Learning: Multi-Task Causal Sequence Architecture (`DL/code/`)

Tài liệu này mô tả chi tiết kiến trúc, cấu trúc tệp tin, mô hình và hướng dẫn vận hành của phân hệ **Deep Learning (DL)** trong phát hiện APT đa nhiệm (Binary Detection, Campaign Scenario Classification, Kill-Chain Stage Identification).

Cấu trúc thư mục của `DL/code/` được đồng bộ chuẩn hóa 1:1 theo đúng kiến trúc của `ML/code/`.

---

## 1. Cây thư mục `DL/code/`

```text
DL/code/
├── README.md                          # Tài liệu kỹ thuật tổng thể phân hệ Deep Learning
├── preprocess/                        # Tiền xử lý dữ liệu, định nghĩa mô hình PyTorch và huấn luyện
│   ├── causal_dataset.py              # PyTorch Dataset, TokenVocabulary, collate_causal_batch
│   ├── model_causal_bilstm.py         # Mạng BiLSTM đa nhiệm 3 đầu ra trên chuỗi nhân quả (E_incoming -> E_parent -> E_current)
│   ├── model_mixhead_attention.py     # Mạng Transformer Mix-Head Self-Attention đa nhiệm (Peter Bloem)
│   ├── trainer.py                     # MultiTaskTrainer & MultiTaskLoss cân bằng trọng số (Uncertainty Weighting)
│   ├── train_causal_bilstm.py         # CLI huấn luyện BiLSTM hỗ trợ DDP (Dual GPU T4x2 / RTX 3050)
│   ├── train_mixhead_attention.py     # CLI huấn luyện Mix-Head Self-Attention hỗ trợ DDP
│   └── __init__.py                    # Khởi tạo gói preprocess
├── kaggle/                            # Môi trường đóng gói và Jupyter Notebook chạy trên Kaggle GPU T4x2
│   ├── 15_BiLSTM_Causal_MultiTask_Kaggle_T4x2.ipynb          # Notebook huấn luyện Causal BiLSTM trên Kaggle T4x2
│   ├── 16_MixHead_SelfAttention_Causal_Kaggle_T4x2.ipynb     # Notebook huấn luyện Mix-Head Transformer trên Kaggle T4x2
│   ├── pack_kaggle_causal_bilstm.py                          # Script đóng gói self-contained zip tải lên Kaggle
│   ├── generate_kaggle_notebook.py                           # Tự động sinh notebook BiLSTM
│   ├── generate_kaggle_notebook_mixhead.py                   # Tự động sinh notebook Mix-Head Transformer
│   └── kaggle_causal_bilstm_t4x2_upload.zip                 # Gói nén khép kín tải lên Kaggle (44.8 MB)
├── test/                              # Kiểm thử tự động (Unit test & Integration test)
│   ├── test_causal_bilstm.py          # Kiểm thử tích hợp toàn trình Causal BiLSTM
│   └── test_mixhead_attention.py      # Kiểm thử kiến trúc Mix-Head Self-Attention
├── others/                            # Cấu hình, yêu cầu môi trường và tệp phụ trợ
│   ├── requirements.txt               # Thư viện phụ thuộc cho Deep Learning (PyTorch, PyArrow...)
│   └── sample_multitask_cohort_42k.json.gz  # Tập mẫu cohort 42k sự kiện cho kiểm thử cục bộ
└── output/                            # Checkpoints mô hình đã huấn luyện
    ├── causal_bilstm_multitask.pt     # Trọng số tối ưu của Causal BiLSTM
    └── mixhead_attention_multitask.pt # Trọng số tối ưu của Mix-Head Self-Attention
```

---

## 2. Các Kiến Trúc Deep Learning Cốt Lõi

### A. Causal BiLSTM Multi-Task (`preprocess/model_causal_bilstm.py`)
* **Đầu vào:** Chuỗi 3 bước nhân quả $[E_{\text{incoming}},\, E_{\text{parent}},\, E_{\text{current}}]$.
  - Mỗi bước được nhúng qua `nn.EmbeddingBag` từ từ vựng cấu trúc ngữ nghĩa Host ML.
* **Xương sống (Backbone):** 2 lớp BiLSTM hai chiều (`hidden_dim = 128`), trích xuất nhịp điệu chuyển giao giữa các bước tấn công.
* **3 Đầu ra Đa nhiệm (Multi-Task Heads):**
  1. **Head 1 (Binary Detection):** $P(\text{Malicious} \mid \mathbf{x})$.
  2. **Head 2 (Campaign Classification):** Phân loại kịch bản tấn công (Scenario 1, Scenario 2, Scenario 3...).
  3. **Head 3 (Stage / Tactic Identification):** Phân loại chiến thuật MITRE ATT&CK.

### B. Mix-Head Self-Attention Transformer (`preprocess/model_mixhead_attention.py`)
* **Thiết kế:** Tuân thủ nguyên lý Transformer từ Peter Bloem (`MultiHeadSelfAttention` kết hợp `bmm` và scaling dot-product).
* **Đặc tính hỗ trợ Incremental Learning:**
  - Cơ chế `freeze_backbone()`: Đóng băng các tầng biểu diễn cơ sở khi chuyển sang miền mới (ATLASv2, THEIA), chỉ cập nhật các đầu phân loại bổ sung để triệt tiêu hiện tượng quên thảm khốc (Catastrophic Forgetting).

---

## 3. Hướng Dẫn Chạy Kiểm Thử và Huấn Luyện

### Chạy kiểm thử tự động:
```bash
python3 DL/code/test/test_causal_bilstm.py
python3 DL/code/test/test_mixhead_attention.py
```

### Đóng gói và chuẩn bị cho Kaggle:
```bash
python3 DL/code/kaggle/pack_kaggle_causal_bilstm.py
```
Gói nén đầu ra sẽ sẵn sàng tại `DL/code/kaggle/kaggle_causal_bilstm_t4x2_upload.zip`.
