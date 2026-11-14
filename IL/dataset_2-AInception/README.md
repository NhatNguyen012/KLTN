# IL dataset 3 — AInception (Windows Sysmon/Security + Linux auditd)

Dữ liệu gốc (chỉ đọc): `/mnt/SSD_Data/optc/DATASET/AInception/` (zip + `extracted/`).
Báo cáo: [`analyst/relabel_v2_20261113.md`](analyst/relabel_v2_20261113.md) (nhãn hiện hành cho SL300; SL700 dùng relabel_v3, xem [`analyst/rootcause_sl700_20261113.md`](analyst/rootcause_sl700_20261113.md)), [`analyst/eid3_shortcut_check_20261113.md`](analyst/eid3_shortcut_check_20261113.md), [`analyst/relabel_v1_20261113.md`](analyst/relabel_v1_20261113.md) (cũ: tactic theo khung thời gian bị lệch 1 giờ, xem v2 mục 1).

| File | Vai trò |
|---|---|
| `code/adapters.py` | Bước 1: đưa log về một dạng sự kiện chung. Windows: Sysmon EID 1/3/5/8/10/11/12-14/22 + Security 4688/4624…/4798. Linux: auditd thô hoặc ECS filebeat, gom các bản ghi theo `msg=audit(ts:serial)` (SYSCALL+EXECVE+PROCTITLE+PATH+SOCKADDR) |
| `code/relabel.py` | Bước 2: dựng lại nhãn attack/tactic từ attack log + cây tiến trình (thay cho nhãn thô theo khung thời gian của bộ dữ liệu) |
| `code/relabel_v2.py` | **Nhãn hiện hành.** Bù giờ Lore (CET → UTC, −60 phút), hạt giống theo logon/service/exploit, gắn sự kiện không có ProcessGuid, cột `stage` theo tiến trình (1 IC, 2 ED, 3 LM, 4 EX, 5 Impact). SL300 v2/v4/v5/v7 + SL700 6 run |
| `code/summarize_relabel_v2.py` | Bảng tổng hợp từ `output/relabel_v2/*/report.json` |
| `code/check_eid3_benign.py` | Kiểm tra bẫy Sysmon EID 3: so ngày benign (đọc thẳng từ zip) với ngày tấn công; output `output/eid3_check_v1/`, báo cáo [`analyst/eid3_shortcut_check_20261113.md`](analyst/eid3_shortcut_check_20261113.md) |
| `code/remote_zip.py` | Đọc zip trên Zenodo bằng HTTP Range (không tải cả file): `ls <zip>` liệt kê, `get <zip> --grep REGEX --out DIR` chỉ tải các file khớp (kiểm CRC) |
| `code/summarize_listing.py` | Tổng hợp dung lượng nén theo thành phần từ `output/remote_listing/*.tsv` (mục lục 15 zip) |
| `code/fetch_host_logs.sh`, `code/selection.sh` | Tải từng phần log host (bỏ Suricata, mail, labelled benign) vào `DATASET/AInception/extracted/SL300_vN hoặc SL700_x_y/`, mỗi thư mục có `PARTIAL_EXTRACT.txt`; log tải ở `output/fetch_logs/`. Chạy lại được (`--skip-existing`) |

```bash
cd /mnt/SSD_Data/optc/IL/dataset_2-AInception/code
python3 relabel_v2.py --workers 3        # nhãn hiện hành: output/relabel_v2/<scenario>/{events.parquet, report.json}
python3 relabel.py --scenarios SL700_f_a,SL300_v7 --out ../output/relabel_v1   # v1, giữ để tái lập
```
Output v1: `output/relabel_v1/<scenario>/events.parquet` (sự kiện chung + `coarse_mal/coarse_tactics` gốc + `y_new/tactics_new`) và `report.json`.

Mục lục 15 zip: `output/remote_listing/`. Attack log của mọi variant SL300 và attackmate.json của 6 run SL700 (tải bằng `remote_zip.py get`): `output/remote_parts/`.

## IL bước 3: OpTC → ATLASv2 → SL700 (`code/DL/`)

| File | Vai trò |
|---|---|
| `code/DL/build_sl700_windows.py` | relabel_v2 SL700 → cửa sổ 180 s / 30 s cùng định dạng ATLASv2 (`optc_raw` + token ngữ cảnh thô). Chia theo run: train a_a,a_b,b_a,e_a; val a_c; test f_a. Output `output/sl700_windows_v1/` |
| `code/DL/train_il_step3.py` | Dựng lại đúng model bước 2 (`optc_il_20261112/runs/freeze_replay_s<seed>/best.pt`), mở rộng từ điển (contract + ngữ cảnh), stage head 4→5 (Impact), kiểm tra tương đương, train (freeze A→B→C hoặc full) với replay OpTC/ATLASv2, chấm TEST trước/sau trên 3 miền |
| `code/DL/run_matrix_step3.sh` | 4 cấu hình × 3 seed (freeze_replay2, freeze_replayoptc, full_noreplay_selsl, scratch_selsl) → `output/il_step3_20261113/` |
| `code/DL/summarize_step3.py`, `code/DL/run_scratch40.sh` | Bảng mean ± std; baseline từ đầu 40 epoch. Báo cáo: [`analyst/dl_il_step3_sl700_20261113.md`](analyst/dl_il_step3_sl700_20261113.md) |

## Nguyên nhân F1 SL700 chưa đạt SOTA, nhãn v3 và đầu vào Linux (13/11/2026)

Báo cáo: [`analyst/rootcause_sl700_20261113.md`](analyst/rootcause_sl700_20261113.md).

| File | Vai trò |
|---|---|
| `code/relabel_v3_linux.py` | **Nhãn SL700 hiện hành (v3).** Sửa luật Linux của v2: payload meterpreter fork không exec, burst subshell linpeas, trùng thời gian với job hệ thống; thêm lệnh tiêm IC. Output `output/relabel_v3/` |
| `code/DL/build_sl700_windows_v3.py` | Cửa sổ trên nhãn v3, cùng công thức với v1 (`--split` cho fold khác) → `output/sl700_windows_v3/`, `output/sl700_windows_v3_test_ea/` |
| `code/rootcause/linux_ctx.py`, `code/rootcause/build_sl700_events_v2.py` | Token Linux theo Base OpTC + ngữ cảnh actor/parent/session (audit `ses`), cùng lưới cửa sổ → `output/rootcause_20261113/events_v2` (nhãn v2), `events_v3` (nhãn v3) |
| `code/rootcause/rc_*.py` | LightGBM trên token DL, ablation nhóm token, lỗi từng cửa sổ, nhãn trong burst, leave-one-run-out |
| `code/DL/train_il_step3_v2.py` | IL bước 3 + túi token Linux (EmbeddingBag nối vào nhánh ngữ cảnh, cột mới khởi tạo 0); `--sl700-data`, `--events-dir`, `--bag-groups none` hoặc `g_ev,g_par,g_ses[,g_scope]` |
| `code/DL/run_matrix_v3.sh`, `code/DL/run_testea.sh`, `code/DL/summarize_step3_v2.py` | Ma trận trên nhãn v3 → `output/il_step3v3_20261113/`; fold giữ e_a làm TEST → `output/il_step3v3_testea_20261113/`; bảng mean ± std |

```bash
cd /mnt/SSD_Data/optc/IL/dataset_2-AInception/code
for r in a_a a_b b_a e_a a_c f_a; do python3 relabel_v3_linux.py $r; done
python3 DL/build_sl700_windows_v3.py
python3 rootcause/build_sl700_events_v2.py --relabel ../output/relabel_v3 \
    --ref ../output/sl700_windows_v3/dataset.pkl --out ../output/rootcause_20261113/events_v3
bash DL/run_matrix_v3.sh                          # DL, 3 seed
EVD=events_v3 python3 rootcause/rc_lgbm_v2.py     # LightGBM ablation
EVD=events_v3 python3 rootcause/rc_lgbm_loro.py   # leave-one-run-out
```

## ML IL bước 3: OpTC → ATLASv2 → SL700, LightGBM boosting phần dư (`code/ML/`)

Báo cáo: [`analyst/ml_il_step3_sl700_20261113.md`](analyst/ml_il_step3_sl700_20261113.md). Model cũ = model OpTC → ATLASv2 (v9b) của `dataset_1-ATLASv2/code/ML`; bước 3: `z2 = 0,8 · z1 + z_SL700`.

| File | Vai trò |
|---|---|
| `code/ML/sl700_ecar.py` | Sự kiện auditd → bản ghi eCAR (tokenizer Base OpTC) + token ngữ cảnh kiểu bước ATLASv2 + token Linux (`lx:`) |
| `code/ML/build_sl700_host_ml.py` | Ma trận nhị phân theo sự kiện (nhãn relabel_v3, split theo run như DL), từ vựng 12.365 → 21.493 → `output/ml_il_step3_20261113/data/` |
| `code/ML/train_ml_il_step3.py` | Booster phần dư với replay OpTC + ATLASv2, hoặc baseline từ đầu; SL700 theo sự kiện và theo cửa sổ; BWT trên TEST ATLASv2/OpTC |
| `code/ML/eval_old_val.py` | VAL ATLASv2/OpTC để chọn α của replay dương (chọn 0,5) |
| `code/ML/run_ml_matrix.sh`, `code/ML/summarize_ml_step3.py`, `code/ML/ml_window_errors.py` | Ma trận, bảng (`output/ml_il_step3_20261113/summary.md`), phân tích cửa sổ sót |

```bash
cd /mnt/SSD_Data/optc/IL/dataset_2-AInception/code/ML
python3 build_sl700_host_ml.py
python3 train_ml_il_step3.py --out ../../output/ml_il_step3_20261113/runs/incA05_ecar_lx_s1 --config ecar_lx --mode inc --rep-pos-alpha 0.5 --seed 1
```
