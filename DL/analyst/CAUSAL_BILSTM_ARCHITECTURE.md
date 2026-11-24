# Causal Triplet BiLSTM Multi-Task Architecture (OpTC Host Deep Learning)

## 1. Bối Cảnh & Sự Chuyển Dịch Kiến Trúc

### 1.1. Hạn chế của Cửa sổ Thời gian Phẳng (15-Minute / 3-Minute Windows)
Trước đây, nhánh DL tiếp cận theo cách cắt dữ liệu theo cửa sổ thời gian (15 phút trên OpTC hoặc 3 phút trên ATLASv2/SL700) và giới hạn mỗi chunk 512 dòng:
- **Pha loãng tín hiệu (Noise Interleaving):** Hàng chục nghìn sự kiện nền lành tính (`svchost`, telemetry, browser threads) chen ngang giữa các sự kiện tấn công, khiến BiLSTM phải học mối tương quan thời gian vô nghĩa thay vì liên kết nhân quả.
- **Cắt đứt biên nhân quả (Boundary Truncation):** Kẻ tấn công tiêm mã (process injection) lúc $t_1$, nhưng 15 phút sau mới thực thi lệnh shell. Việc cắt cửa sổ theo thời gian phẳng làm mất hoàn toàn liên kết giữa hành vi tiêm và hành vi thực thi.
- **Thiếu hụt ngữ cảnh ("Semantic Starvation"):** Mô hình DL cũ chỉ dùng khoảng 4 trường danh mục thô (`app_family`, `proto`, `resp_port_class`, `image_dir_class`), không hề có dòng lệnh AST, switches, danh mục thư mục chi tiết hay ngữ cảnh tiêm luồng từ xa.

---

## 2. Kiến Trúc Chuỗi Nhân Quả Tam Giác $[E_{\text{incoming}}, E_{\text{parent}}, E_{\text{current}}]$

Mỗi sự kiện ứng viên cần đánh giá $E_{\text{current}}$ được gắn với một **chuỗi nhân quả trực tiếp (Causal Sequence)** có độ dài cố định $L = 3$:

```
 Bước 1: E_incoming                Bước 2: E_parent                 Bước 3: E_current
 (Sự kiện Tiêm / Tương tác)        (Ngữ cảnh Tiến trình Cha)        (Hành động Hiện tại)
 ┌───────────────────────────┐     ┌───────────────────────────┐    ┌───────────────────────────┐
 │- ctx::incoming::thread_   │     │- ctx::actor::exe=lsass.exe│    │- action::create           │
 │  remote_create            │     │- ctx::actor::path_role=   │    │- object::process          │
 │- source_exe=ckfgw.exe     │     │  system32                 │    │- launcher=cmd.exe         │
 │- source_path_role=temp    │     │- ctx::actor::principal=   │    │- switch=/add              │
 │- age=lt_1s                │     │  nt_system                │    │- cmd::admin, cmd::user    │
 └─────────────┬─────────────┘     └─────────────┬─────────────┘    └─────────────┬─────────────┘
               │                                 │                                │
               ▼                                 ▼                                ▼
       [ EmbeddingBag ]                  [ EmbeddingBag ]                 [ EmbeddingBag ]
               │                                 │                                │
               ▼                                 ▼                                ▼
           Vector x_1                        Vector x_2                       Vector x_3
           (R^128)                           (R^128)                          (R^128)
               └─────────────────────────────────┼────────────────────────────────┘
                                                 ▼
                                     [ BiLSTM Backbone (L=3) ]
                                  Forward: Causal Influence (x1 -> x2 -> x3)
                                  Backward: Justification (x3 -> x2 -> x1)
                                                 │
                                                 ▼
                                       [ Attention Pooling ]
                                                 │
                                                 ▼
                                         Vector Context h
                                                 │
                         ┌───────────────────────┼───────────────────────┐
                         ▼                       ▼                       ▼
                  [ Head 1: Binary ]      [ Head 2: Scenario ]    [ Head 3: MITRE Stage ]
                  Sigmoid (0 vs 1)        Softmax (4 classes)     Softmax (10 classes)
```

### Ý Nghĩa Của 3 Bước Trong Chuỗi:
1. **Bước 1 ($E_{\text{incoming}}$):** Nắm bắt các hành vi can thiệp từ ngoài vào tiến trình hiện tại: `THREAD:REMOTE_CREATE` (tiêm luồng từ xa), `PROCESS:OPEN` với quyền can thiệp bộ nhớ từ một tiến trình khác trước thời điểm $t$.
2. **Bước 2 ($E_{\text{parent}}$):** Nắm bắt nguồn gốc sinh ra tiến trình trong phả hệ hệ điều hành: Tiến trình cha là ai (`lsass.exe`, `wmiprvse.exe`, `gup.exe`), dòng lệnh của cha, phân loại thư mục cha (`system32`, `temp`).
3. **Bước 3 ($E_{\text{current}}$):** Hành vi cụ thể mà tiến trình đang thực hiện ở thời điểm hiện tại: Gọi lệnh gì (`cmd.exe /c net user admin /add`), nạp DLL gì, kết nối mạng tới đâu.

---

## 3. Tích Hợp Toàn Bộ Đặc Trưng Cấu Trúc Của Host ML

Nhánh DL không còn dùng các trường thô sơ mà kế thừa trực tiếp hệ thống trích xuất hơn 10.000 token cấu trúc từ `ML/code/preprocess/ecar_tokenizer.py` và `process_context_tracker.py`:
- **Lexical & Path Roles:** `image_path::category=system32`, `temp`, `appdata`, `program_files`.
- **Command Syntax AST:** Launcher (`powershell`, `cmd`), Switches (`-enc`, `/c`, `/add`), Operands (`admin`, `supersecret`).
- **Principal Identity:** `SYSTEM`, `LOCAL SERVICE`, `domain_user`.
- **Causal Relations:** `structure::process_lineage=lsass.exe->cmd.exe`, `ctx::relation::lineage=powershell->cmd`.

Tầng `CausalStepEmbedding` sử dụng PyTorch `nn.EmbeddingBag` để nén túi token rời rạc tại mỗi bước thành vector đặc trưng dày đặc $x_t \in \mathbb{R}^{128}$.

---

## 4. Cơ Chế Đa Nhiệm (Multi-Task Heads)

Mô hình dự đoán đồng thời 3 mục tiêu thông qua 3 đầu phân loại độc lập:
1. **Head 1 - Binary Detection:** Dự đoán sự kiện là Độc hại ($1$) hay Lành tính ($0$) bằng hàm mất mát `BCEWithLogitsLoss`.
2. **Head 2 - Scenario Attribution:** Nhận diện chiến dịch tấn công:
   - `0`: Benign
   - `1`: `SC1_EmpireStaging` (2019-09-23)
   - `2`: `SC2_CustomEmpireLateral` (2019-09-24)
   - `3`: `SC3_MaliciousUpdate` (2019-09-25)
3. **Head 3 - MITRE ATT&CK Stage / Tactic:** Phân loại 10 lớp chiến thuật:
   - `0`: Benign
   - `1`: `Execution`
   - `2`: `Defense_Evasion_Injection` (T1055)
   - `3`: `Defense_Evasion_AMSI` (T1562)
   - `4`: `Discovery` (T1018, T1057)
   - `5`: `Credential_Access` (T1003)
   - `6`: `Lateral_Movement` (T1021, T1047)
   - `7`: `Persistence` (T1078, T1547)
   - `8`: `Command_and_Control` (T1071)
   - `9`: `Collection_Exfiltration` (T1560, T1048)

Hàm mất mát tổng hợp:
$$\mathcal{L}_{\text{total}} = 1.0 \times \mathcal{L}_{\text{Binary}} + 0.5 \times \mathcal{L}_{\text{Scenario}} + 0.8 \times \mathcal{L}_{\text{Stage}}$$

---

## 5. Tương Thích Với Sidecar Label Index

Mô hình tích hợp trực tiếp với bộ tra cứu [DATASET/Preprocess/label_catalog.py](file:///mnt/SSD_Data/optc/DATASET/Preprocess/label_catalog.py).
- Catalog nhãn chỉ nặng **7.68 MB**, nạp vào RAM trong **5 giây**.
- Tra cứu $O(1)$ với độ trễ chỉ **59 nanoseconds / sự kiện**.
- Tuyệt đối không chạm vào, sửa đổi hay nén lại dataset gốc 1 TB.
