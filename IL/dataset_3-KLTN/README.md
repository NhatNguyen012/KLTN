# IL dataset_3-KLTN — chạy thử L1 + L5 (2026-11-18)

Dataset sinh từ chính pipeline KLTN đang serving (auditd → kltn_features), nên khớp sẵn BiLSTM + LightGBM.
Hai incident đầu tiên chạy thử theo `Openstack/KLTN/red-team/scenarios_group1.md` (đã duyệt ROE §10).

## Ground truth
- `runs/gt_L1_20261118T091318Z.jsonl` — L1 baseline (9 bước, 8 ok). Cửa sổ UTC **09:13:18–09:14:03**.
- `runs/gt_L5_20261118T092457Z.jsonl` — L5 held-out test (6 bước, 6 ok). Cửa sổ UTC **09:24:57–09:25:02**.
- Mỗi dòng JSONL = một giai đoạn (stage, technique ATT&CK, target, status, evidence, ts). Chỉ ghi khi bước
  được **xác minh thành công** (parse output lệnh, không chỉ gửi đi).

## TTP đã chạy (khác nhau giữa L1/L5 → L5 là fold test)
| | Initial | Exec/Disc | Privesc | Persistence | Lateral | Exfil | Impact |
|---|---|---|---|---|---|---|---|
| **L1** | SQLi Juice Shop → reuse pass SSH (T1190/T1078) | discovery thường (T1082) | sudo find GTFOBin (T1548.003) | authorized_keys + cron (T1098.004/T1053.003) | ssh v1→v2 reuse cred (T1021.004) | — | mã hoá canary, reversible (T1486) |
| **L5** | reuse pass SSH (T1078) | base64-decoded (T1140) | sudo find (T1548.003) | **systemd timer** (T1053.003) | ssh v1→v2 (T1021.004) | **DNS-style** (T1048) | **dừng service**, reversible (T1489) |

## Kết quả phát hiện (vai SOC)
- **True positive — cả hai incident đều bị phát hiện ở tầng model + fusion.**
  - L1: host_ml ≤0.99 (ubuntu-1), host_dl ≤0.9999 (ubuntu-2); fusion risk ~1.0, pred=1 các bucket 09:10/09:15/09:20.
  - L5: host_ml ≤0.997; fusion risk 1.0/0.99, pred=1 bucket 09:20/09:25.
- **Độ trễ phát hiện** ≈ đóng bucket (fusion `bucket_seconds=300`, 5 phút) + xử lý ⇒ khoảng 5–9 phút.

## Phát hiện quan trọng cần xử lý trước khi build dataset chính thức
1. **Benign mới bị FP nặng.** Cửa sổ chỉ-benign trước tấn công (08:00–09:10) có ~180–200 score host_ml vượt
   ngưỡng, trung bình **~0.94**, trên cả hai host Linux. Model champion hiện **chưa học baseline benign mới**
   (admin sudo, dev build, web, SSH chéo, Juice Shop) → coi gần như mọi thứ là tấn công. **Đây chính là động lực
   của IL step 4** và giờ đã định lượng được.
2. **Alert không bao giờ đóng → lẫn benign và attack.** Alert `needs_review` trên 2 host Linux mở liên tục từ
   **2026-11-13**, incident L1/L5 chỉ **gộp bucket** vào đó thay vì tạo alert riêng. Hệ quả: ở mức alert hiện tại
   không tách được attack khỏi benign; phải dựa vào ground-truth JSONL để gán nhãn cửa sổ tấn công.
3. **Hệ quả cho dataset:** dùng ground-truth (cửa sổ UTC per stage) làm nhãn attack; toàn bộ thời gian còn lại
   trong run là benign. Vì model FP, KHÔNG dùng alert làm nhãn.

## Hạ tầng (đã dọn)
- Attacker `kltn-attacker` 203.0.113.66, cô lập (không Internet/central). Foothold qua reuse credential (user lab
  `dmorris`, password-auth bật như tiền đề "weak config"). Privesc qua sudoers misconfig có kiểm soát.
- Sau mỗi run đã rollback: canary giải mã khôi phục, gỡ authorized_keys/cron/systemd-timer của attacker, service
  khôi phục. Snapshot tiền-run `snap-kltn-ubuntu-{1,2}-preL1-*` giữ làm lưới an toàn.

## Bước tiếp
- Export telemetry thô theo cửa sổ 2 run từ central (`events`/`host_events`) + gán nhãn theo ground-truth → shard
  train/test. Mở rộng L2/L3/L4 (train) + W-series để đủ gate (≥3 incident/domain, attack ở cả val/test).
- Dùng dataset cho IL step 4 (OpTC→ATLASv2→SL700→KLTN) để model học benign mới (giảm FP) mà vẫn giữ phát hiện.
