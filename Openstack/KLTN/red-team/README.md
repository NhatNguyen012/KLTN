# red-team/ — kịch bản sinh mẫu APT cho lab KLTN

> **AUTHORIZED LAB USE ONLY.** Mọi playbook ở đây chỉ nhắm **VM của chính lab**. Snapshot trước mỗi đợt.
> Các file này được **viết ra nhưng chưa chạy**. Impact luôn đảo ngược được (canary / service stop).
> **Quy tắc tham gia: [ROE.md](ROE.md)** — phạm vi, vai trò red team/SOC, cấm/được phép, kill switch.
> Mục đích: sinh telemetry **có nhãn** cho vòng SOC → IL của hai model (DL theo cửa sổ, ML theo event).

## Hai domain, hai engine
| Domain | Host | Engine | Vì sao |
|---|---|---|---|
| `linux-audit` (validated) | kltn-ubuntu-1/2 | **AttackMate** | cùng họ công cụ với SL700, không agent |
| `windows-sysmon` (shadow) | kltn-windows-1 | **Atomic Red Team** (`Invoke-AtomicTest`) | Windows-native; gỡ shadow cho Sysmon |

## Ma trận biến thể (phủ stage + làm model bền)
| Run | Initial access | Obfuscation | Privesc | Persistence | Lateral | Exfil | Impact | Split |
|---|---|---|---|---|---|---|---|---|
| **L1** baseline | assume-breach | — | pkexec (T1068) | cron + authkeys | ssh pw | — | canary enc (T1486) | TRAIN |
| **L2** obfuscated | assume-breach | base64/hex (T1027/T1140) | pkexec | cron | ssh pw | — | canary enc | TRAIN |
| **L3** lolbin | web foothold | một phần | sudo-misconfig (GTFOBins) | ~/.bashrc | ssh key | curl POST (T1041) | svc stop (T1489) | TRAIN |
| **L4** exfil/systemd | assume-breach | — | pkexec | systemd service (T1543.002) | scp | tar+curl (T1041) | canary enc | VAL |
| **L5** unseen | assume-breach | hex | sudo-misconfig | systemd **timer** | ssh key | DNS-ish (T1048) | svc stop | TEST |
| **W1** baseline | user-exec | — | token/UAC | run-key (T1547.001) | WinRM (T1021.006) | — | svc stop (T1489) | TRAIN |
| **W2** obfuscated | powershell -enc | T1027.010 | — | sched task (T1053.005) | SMB (T1021.002) | HTTP (T1041) | — | VAL |
| **W3** unseen | mshta/LOLBin | T1140 | — | WMI event (T1546.003) | — | DNS (T1048) | T1486 (reversible) | TEST |

- Stage model: `initial_compromise → execution_discovery → lateral_movement → exfiltration → impact`.
- **Mỗi run = một incident** (nhớ review đóng alert trước/sau). Gate IL: ≥ 3 incident/domain, attack ở cả VAL và TEST → bộ này đã bố trí sẵn train/val/test cho từng domain.
- Chạy mỗi run **≥ 1 lượt**; cần thêm incident thì đổi `vars` (host/thời điểm) chạy lại.

## Chạy (chỉ sau khi ROE.md mục 10 đã duyệt)
```bash
# Linux (trên kltn-attacker 203.0.113.66, đã có msfrpcd nếu dùng msf-module)
attackmate linux/L1_baseline.yml          # lặp cho L2..L5
# Windows (trên kltn-windows-1, đã Install-Module invoke-atomicredteam)
powershell -ep bypass -f windows/run_atomics.ps1 -Plan windows/W1_baseline.txt -Attacker 203.0.113.66
```
Nhật ký red team (ground truth để tick nhãn SOC): AttackMate ghi `metadata` mỗi bước; `run_atomics.ps1` ghi CSV UTC. Gộp bằng `gen_redteam_log.py`.

## An toàn
- Initial access mặc định **assume-breach**; bản exploit thật (ZoneMinder) để comment, cần VM cố tình lỗi.
- Impact chỉ đụng thư mục canary hoặc service không quan trọng, **đảo ngược được**.
- Điền `vars.example.yml` bằng giá trị lab của bạn trước khi chạy.
