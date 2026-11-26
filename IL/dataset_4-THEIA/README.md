# DARPA TC E3 THEIA Continual Learning & Domain-Incremental Pipeline

Domain-Incremental Learning (Domain 2: Linux Telemetry) transferring from **DARPA OpTC (Domain 0)** $\rightarrow$ **DARPA TC E3 THEIA (Domain 2)** using exact `MixHeadSelfAttentionCausalHost` ($L=3$ Causal Triplets).

---

## 1. Cấu Hình Dữ Liệu Sạch (Dựa Trên Paper Audit & REAPr Ground Truth)

Các cải tiến chuẩn hóa áp dụng từ **NDSS 2027 Theseus**, **REAPr**, **PIDSMaker**, **MAGIC**, **StageFinder** và **RAPiDLe**:
- **Bảng nguồn T3 + Sắp xếp nhân quả**: Đọc từ `Parquet/event_table.parquet` lọc theo phân vùng hậu-reboot T3 (`timestamp_rec >= 1523378673000000000`, `2018-04-10 16:44:33 UTC`, tổng 25,091,872 sự kiện) và **sort theo `(timestamp_rec, event_uuid)`** trước khi xây dựng chuỗi $L=3$. Giữ nguyên toàn bộ **158,894 `EVENT_CLONE`** và **231,370 `EVENT_UNLINK`** (vốn bị `CSV/event_table_preprocessed.parquet` loại bỏ).
- **Xử lý chiều cạnh (`EDGE_REVERSED_OPS`)**: Xác định đúng Process chủ thể và Object/Netflow cho 11 operation đảo chiều (`EVENT_OPEN`, `EVENT_READ`, `EVENT_EXECUTE`, `EVENT_RECVFROM`, v.v.).
- **Loại bỏ toàn bộ Failed Attempts & Contaminated (`fail` + `contaminated`)**: Theo khuyến cáo REAPr và NDSS 2027 Theseus, loại hoàn toàn khỏi dataset (không gán `1` và cũng không lẫn vào `0`):
  - 4 chuỗi thất bại: `theia_3.3_fail_allstate`, `theia_3.3_fail_gatech_clean`, `theia_3.11_fail`, `theia_4.8_fail` (`tcexec` lỗi thiếu Qt)
  - 2 cạnh `contaminated` trùng trên `Firefox` (`3A3530B4-0200-0000-0000-000000000020`)
  - 17 sự kiện Section 4.6 phishing (`208.75.117.2`, `208.75.117.3`, `62.83.155.175`)
- **Loại bỏ `.so` / dynamic linker nhiễu của OS (`os_shared_lib_noise`)**: Theo chứng minh thực nghiệm từ **MAGIC** (nút `/lib64/ld-linux-x86-64.so.2` có anomaly score `0.01`, không phân biệt được với benign) và **ATLASv2**, loại **1,050,433** sự kiện nạp `/etc/ld.so.cache` và thư viện hệ thống `/lib/*.so*`, `/usr/lib/*.so*` nhưng **giữ lại 100% `/tmp/memtrace.so`** của kẻ tấn công.
- **Zero-Leakage Split & OpTC Vocab Alignment**:
  - Phân tách theo **cửa sổ thời gian 5s không giao nhau** (attack) / **block 60s** (benign), đảm bảo `0` overlap cửa sổ giữa `train`/`val`/`test`.
  - Ánh xạ trực tiếp token tương đồng sang **10,499 ID gốc của OpTC (`dl_vocab.json`)** (chiếm ~56% lượt xuất hiện token trên THEIA), học mới **10,438 token Linux** chỉ từ tập `train`.

---

## 2. Số Lượng Mẫu Đã Làm Sạch (580,048 Mẫu, 59 Shards)

| Phân loại | Tổng cộng | Train (41 shards) | Val (6 shards) | Test (12 shards) | Ghi chú |
| :--- | ---: | ---: | ---: | ---: | :--- |
| **Tổng sự kiện đã trích xuất** | **580,048** | **408,633** | **56,838** | **114,577** | Không chứa `fail`, `contaminated`, OS `.so` |
| **Benign (`0`)** | 513,606 | 361,312 | 50,735 | 101,559 | Lấy mẫu ~2.15% trên toàn T3 sạch |
| **Attack (`1` - REAPr Success)** | **66,442** | **47,321** | **6,103** | **13,018** | Gồm `3.3_success` (1,314) + `3.11_success` (65,128) |
| **Stage 1: Initial Compromise** | **754** | **551** | **57** | **146** | Delivery (`141.43.176.203`, `146.153.68.151`), `pass_mgr`, `gtcache`/`profile` drop |
| **Stage 2: Execution & PrivEsc** | **116** | **82** | **13** | **21** | `/dev/glx_alsa_675`, `/tmp/memtrace.so`, thực thi `profile`/`gtcache`/`mail`, staging `/var/log/{xdev,wdev}` |
| **Stage 3: Discovery & Recon** | **65,230** | **46,467** | **6,001** | **12,762** | Micro APT portscan, `/etc/passwd`, `/etc/group`, `/proc/*/stat`, `/proc/*/maps`, `uname` |
| **Stage 4: C2 & Exfiltration** | **342** | **221** | **32** | **89** | Beacon tới C2 thực sự (`161.116.88.72:80`, `149.52.198.23:80`) |

---

## 3. Kiến Trúc Expandable Multi-Layer + 3-Head & Continual Learning Replay (`THEIA-MixHead-IL.ipynb`)

1. **Multi-Layer + $L=3$ Lines (`ExpandableMixHeadCausalIL`)**:
   - Bảo toàn trọn vẹn **50/50 tensors** từ Domain 0 (`mixhead_attention_t4x2_full.pt`, 2 Transformer blocks + `il_adapter` + `line_pooling_attn` trên 3 line `[E_incoming, E_parent, E_current]`).
   - Thêm mới **1 Domain Transformer Block (`domain_blocks`)** + Attention Pooling riêng trên 3 line sau block mới, nối `[pooled_dom, line_0, line_1, line_2]` (`dom_dim = 512`) vào 3 residual heads (`delta_binary_head`, `delta_scenario_head` 6 classes, `delta_stage_head` 14 classes) với **residual gates khởi tạo `0.0`** (`gate_bin`, `gate_sc`, `gate_st`) $\rightarrow$ đảm bảo **Epoch-0 equivalence `max|Δ| == 0.00e+00`** trên OpTC.
2. **Unified Expandable Heads (Zero Task-ID khi suy luận)**:
   - **Head 1 (`binary_head`, 1 logit)**: `0: Benign`, `1: Attack`.
   - **Head 2 (`scenario_head`, 6 Unified classes)**:
     - `0`: Benign | `1..3`: OpTC (`SC1_EmpireStaging`, `SC2_CustomEmpireLateral`, `SC3_MaliciousUpdate`) | `4`: `THEIA_NationState_Firefox_Drakon` (`3.3_success`) | `5`: `THEIA_BrowserExtension_MicroAPT` (`3.11_success`).
   - **Head 3 (`stage_head`, 14 Unified classes)**:
     - `0`: Benign | `1..9`: OpTC Stages (`OpTC_Execution` .. `OpTC_Collection_Exfiltration`) | `10..13`: `THEIA_Initial_Compromise`, `THEIA_Execution_PrivilegeEscalation`, `THEIA_Discovery_Reconnaissance`, `THEIA_C2_Exfiltration`.
3. **Progressive Unfreezing (`Phase A -> B -> C`, 12 epochs)**:
   - **Phase A (`ep 1..4`, `A_new_only`)**: Khóa cứng toàn bộ OpTC backbone + `token_embedding[:10499]`, chỉ train `domain_blocks`, `delta_*`, `gate_*` (`lr=1e-3`) và new tokens `[10499:]` (`lr=2e-3`).
   - **Phase B (`ep 5..8`, `B_unfreeze_upper`)**: Mở khóa `blocks.1`, `il_adapter`, `line_pooling_attn` và base heads với `lr=1e-4` (giữ `blocks.0` và `token_embedding[:10499]` khóa nguyên).
   - **Phase C (`ep 9..12`, `C_unfreeze_all`)**: Mở khóa `blocks.0`, `token_norm`, `line_embedding` tại `lr=2e-5` và bước cập nhật trên `token_embedding[:10499]` được scale `0.02×` sau `AdamW.step()` (effective `lr=2e-5`).
4. **Experience Replay + LwF Logit Distillation + Đánh giá Kép Trên Kaggle (`OptC Test` + `THEIA Test`)**:
   - Đóng gói sẵn **`optc_replay_train.pt` (100,000 mẫu train OpTC phân tầng đủ cả 8 stage, `18.23 MB`)**, **`optc_val_eval.pt` (50,000 mẫu val OpTC phân tầng đủ cả 8 stage, `7.22 MB`)** và **toàn bộ 125 shards `optc_test_shards/` (1,249,689 mẫu test OpTC)**.
   - Mỗi step trộn **384 mẫu THEIA + 128 mẫu OpTC Replay** kèm **MSE Logit Distillation** bám sát logits teacher OpTC (`t_bin, t_sc, t_st`).
   - Chạy 1 lần duy nhất trên Kaggle xuất đồng thời metric **THEIA Test (114,577 mẫu)**, **Backward Transfer (BWT Before vs After IL trên toàn bộ 1,249,689 mẫu OpTC Test)** và forensic traceback ZIP.

---

## 4. Cấu Trúc Thư Mục & Hướng Dẫn Chạy Kaggle

```
IL/dataset_4-THEIA/
├── README.md
├── docs/
│   └── THEIA_GROUND_TRUTH_ANALYSIS.md
├── code/
│   ├── preprocess/
│   │   ├── theia_schema.py              # Index bounds, T3, EDGE_REVERSED_OPS, filter .so, OpTC scopes
│   │   ├── theia_stage_mapper.py        # REAPr GT + exclusion (fail/contaminated/4.6/.so) + 3 heads
│   │   ├── build_theia_causal_shards.py # Sort T3 Parquet, causal L=3 tracker, 5s window split, OpTC vocab
│   │   └── build_optc_replay_bundle.py  # Tạo optc_replay_train.pt (100k) & optc_val_eval.pt (50k) đủ 8 OpTC stages
│   ├── test/
│   │   ├── test_theia_labeling.py       # Unit tests cho REAPr exclusion, .so filter, Stage 1-4, OpTC vocab
│   │   └── test_theia_il_model.py       # Regression tests ExpandableMixHeadCausalIL, Epoch-0 ==0, pad_triplets, ZIP
│   └── kaggle/
│       ├── generate_kaggle_notebook_theia.py
│       ├── THEIA-MixHead-IL.ipynb
│       └── pack_kaggle_theia_il.py
└── output/
    ├── dl_shards/                       # 59 THEIA shards + extended_dl_vocab.json (20,937 tokens) + split_manifest.json
    ├── optc_il_eval/                    # optc_replay_train.pt (18.23 MB) + optc_val_eval.pt (7.22 MB) + manifest
    ├── theia_dl_shards.zip              # Standalone shards zip (25.82 MB)
    └── kaggle/
        └── kaggle_theia_upload.zip      # Full Dual-Domain Kaggle bundle zip (58.42 MB, gồm 125 OpTC test shards)
```

### Chạy trên Kaggle
1. Upload `IL/dataset_4-THEIA/output/kaggle/kaggle_theia_upload.zip` (`58.42 MB`, chứa sẵn THEIA shards, OpTC Replay/Val, **toàn bộ 125 OpTC test shards**, checkpoint `mixhead_attention_t4x2_full.pt`, và notebook) làm Kaggle Dataset.
2. Mở notebook `IL/dataset_4-THEIA/code/kaggle/THEIA-MixHead-IL.ipynb` trên GPU (`T4 x 2` hoặc `P100`).
3. Chọn **Run All** — kết quả THEIA Test, **Backward Transfer trên 1,249,689 mẫu OpTC Test**, checkpoint tốt nhất `theia_mixhead_il_best.pt` và forensic error traceback sẽ tự động đóng gói thành `/kaggle/working/theia_traceback_results.zip`.
