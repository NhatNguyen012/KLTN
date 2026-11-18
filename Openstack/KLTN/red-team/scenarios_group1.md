# Nhóm kịch bản #1 — đề xuất (chờ duyệt, ROE.md §10)

> **Mức mô tả: giai đoạn + kỹ thuật ATT&CK.** Chưa có payload/exploit cụ thể, chưa chạy. Sau khi anh duyệt
> nhóm này, mỗi kịch bản mới được dựng playbook chi tiết (AttackMate/ART) và chạy theo checklist ROE §8.
> Mọi impact đảo ngược được; mọi run snapshot trước, rollback sau.

## 0. Thay đổi so với ma trận cũ trong README
- **Initial access giờ là đường web thật**, không còn assume-breach mặc định: đã có OWASP Juice Shop chạy thật
  trên `kltn-ubuntu-1:80` (exposed cho `kltn-inet`). Attacker `203.0.113.66` xuất phát từ "Internet giả lập".
- **Cầu nối web → host** (điểm mấu chốt để có telemetry host có nhãn): attacker khai thác tầng web để **lấy
  credential**, rồi dùng lại credential đó để **đăng nhập hợp lệ** vào host. Không cần giả lập RCE.
  Chuỗi: `T1595 recon → T1190 exploit web (Juice Shop) → T1552/T1110 cred access → T1078 valid account (SSH)`.
  Để chuỗi này chạy được, provisioning sẽ đặt **một user lab trên ubuntu-1 có mật khẩu trùng** với một tài
  khoản trong Juice Shop (ghi rõ trong playbook, là dữ liệu lab, không phải credential thật).
- Benign đối chứng đã có: user/admin/dev/web + đăng nhập admin nội bộ ubuntu-1↔ubuntu-2.

## 1. Bản đồ giai đoạn (stage model, khớp nhãn hiện có)
`initial_compromise → execution_discovery → lateral_movement → exfiltration → impact`
Mỗi run = một incident (SOC mở/đóng alert trước–sau). Nhãn lấy từ nhật ký AttackMate (metadata mỗi bước) +
process lineage, không lấy từ alert.

## 2. Linux (kltn-ubuntu-1 entry, kltn-ubuntu-2 lateral) — engine AttackMate
| Run | Initial access (T1190 qua Juice Shop) | Exec/Discovery | Privesc | Persistence | Lateral | Exfil | Impact | Split |
|---|---|---|---|---|---|---|---|---|
| **L1** baseline | SQLi lấy user table → reuse pass SSH (T1552/T1078) | lệnh discovery host | pkexec (T1068) | cron + authorized_keys (T1098.004) | SSH sang ubuntu-2 (T1021.004) | — | mã hoá canary `/opt/kltn-canary` (T1486, reversible) | TRAIN |
| **L2** obfuscated | như L1 | base64/hex (T1027/T1140) | pkexec | cron | SSH key | — | canary enc | TRAIN |
| **L3** lolbin | lạm dụng chức năng Juice Shop (upload/redirect) → foothold www-data | một phần | sudo-misconfig / GTFOBins (T1548.003) | `~/.bashrc` (T1546.004) | reuse SSH key | curl POST dữ liệu giả (T1041) | dừng service không quan trọng (T1489) | VAL |
| **L4** exfil/systemd | như L1 | — | pkexec | systemd service (T1543.002) | scp | tar + curl (T1041) | canary enc | TRAIN |
| **L5** unseen (held-out TEST) | reuse pass SSH | hex | sudo-misconfig | **systemd timer** (T1053.003) | SSH key | DNS-style (T1048) | svc stop | **TEST** |

## 3. Windows (kltn-windows-1) — engine Atomic Red Team — domain đang `shadow_unvalidated`
| Run | Initial access | Obfuscation | Privesc | Persistence | Lateral | Exfil | Impact | Split |
|---|---|---|---|---|---|---|---|---|
| **W1** baseline | user-exec (phishing giả lập, assume-open) | — | token/UAC (T1134/T1548.002) | Run key (T1547.001) | WinRM (T1021.006) | — | svc stop (T1489) | TRAIN |
| **W2** obfuscated | `powershell -enc` | T1027.010 | — | scheduled task (T1053.005) | SMB (T1021.002) | HTTP (T1041) | — | VAL |
| **W3** unseen (TEST) | mshta/LOLBin (T1218.005) | T1140 | — | WMI event sub (T1546.003) | — | DNS (T1048) | canary enc (T1486) | **TEST** |

## 4. Cách phủ & điều kiện IL (gate)
- ≥ 3 incident/domain; attack xuất hiện ở cả VAL và TEST → đã bố trí sẵn train/val/test.
- Mỗi run chạy ≥ 1 lượt; cần thêm incident thì đổi `vars` (giờ chạy, host đích, thứ tự bước) rồi chạy lại,
  tăng đa dạng mà không lộ nhãn.
- **Fold giữ lại**: L5 và W3 là kịch bản chưa từng dùng khi train/tuning (đo generalization, giống fold e_a SL700).

## 5. Telemetry & nhãn kỳ vọng
- Juice Shop sinh log tầng ứng dụng + netconn inbound trên ubuntu-1; foothold host sinh auditd execve/login-session.
- Nhãn per-process theo stage 1–5; attribution pid chỉ khi khớp tiến trình attacker (bài học relabel_v3 SL700:
  cẩn thận fork không exec, subshell — gán bằng process lineage, không bằng cửa sổ thời gian thô).
- Benign đối chứng phải chạy xuyên suốt run (benign xen lẫn tấn công).

## 6. An toàn (nhắc lại từ ROE)
- Initial access web ở mức khai thác lỗ hổng có sẵn của Juice Shop; không tải/chạy mã độc thật.
- Impact chỉ trong `/opt/kltn-canary` (Linux) / `C:\KLTN-canary` (Windows) hoặc service không quan trọng; có bước hoàn tác.
- Ngưỡng dừng RAM < 4 GiB; không chạy khi đang train GPU; snapshot/rollback mỗi run.

## 7. Đề xuất chạy trước (để anh duyệt)
Bắt đầu nhỏ: **L1 (TRAIN) + L5 (TEST)** trên Linux (domain validated, giá trị cao nhất) để chạy thử trọn vòng
recon→web→foothold→lateral→impact→SOC, kiểm tra nhãn và độ trễ phát hiện, trước khi mở rộng L2/L3/L4 và sang
Windows. Sau khi anh gật đầu nhóm này, tôi dựng playbook L1 chi tiết và chạy theo checklist ROE §8.

## 8. Nhật ký duyệt
| Hạng mục | Trạng thái | Người duyệt | Ngày |
|---|---|---|---|
| Nhóm kịch bản #1 (cấu trúc + initial access qua Juice Shop) | ☑ ĐÃ DUYỆT | nguyen | 2026-11-18 |
| Chạy thử L1 + L5 | ☑ ĐÃ DUYỆT | nguyen | 2026-11-18 |
