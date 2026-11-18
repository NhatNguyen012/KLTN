# Rules of Engagement — red team / SOC lab KLTN

> **Trạng thái:** BẢN NHÁP v0.1 (2026-11-18) — **chờ chủ lab duyệt**. Chưa được chạy bất kỳ bước tấn công nào
> cho tới khi mục 10 có chữ ký duyệt.
> Mọi thay đổi ROE phải ghi vào mục 11 (nhật ký thay đổi).

## 1. Mục đích
Sinh telemetry **có nhãn chính xác** (auditd / Sysmon / Security / PowerShell) từ các chiến dịch tấn công mô phỏng
nhiều giai đoạn theo MITRE ATT&CK, chạy end-to-end qua pipeline KLTN (agent → central → host ML/DL → fusion →
SOC → response), để:
1. tạo dataset mới cho **IL step 4** (BiLSTM + LightGBM, chuỗi OpTC → ATLASv2 → SL700 → KLTN);
2. đo khả năng phát hiện / độ trễ / quy trình response của hệ thống;
3. validate domain `windows-sysmon` (hiện `shadow_unvalidated`).

## 2. Vai trò
| Vai | Người | Quyền |
|---|---|---|
| Chủ lab / người duyệt ROE | nguyen | Duyệt ROE, duyệt từng nhóm kịch bản, dừng chiến dịch bất kỳ lúc nào |
| Red team (attacker) | Claude | Thiết kế, chuẩn bị, chạy, biến đổi kịch bản **trong phạm vi mục 3** |
| SOC (blue team) | Claude | Điều tra alert, xác nhận/đóng alert, duyệt response, cô lập / mở cô lập host trong phạm vi |

Một tác nhân giữ cả hai vai ⇒ red team **biết trước** kịch bản. Biện pháp bù (bắt buộc ghi trong báo cáo dataset):
- quyết định SOC chỉ dựa trên **bằng chứng có trong central** (`events`, `host_events`, `scores`, `alerts`), ghi
  rõ bằng chứng nào dẫn tới quyết định;
- nhãn ground truth lấy từ **nhật ký red team** (AttackMate metadata / CSV `run_atomics.ps1`) + process lineage,
  không lấy từ alert;
- đánh giá mô hình trên ít nhất một nhóm kịch bản **giữ lại** (chưa từng dùng khi train/tuning);
- chủ lab review mẫu nhãn và các quyết định cô lập trước khi công bố dataset.

## 3. Phạm vi
### 3.1 Trong phạm vi (được tấn công / hoạt động)
| Thành phần | Địa chỉ | Ghi chú |
|---|---|---|
| `kltn-attacker` | 203.0.113.66 (`kltn-inet`, 203.0.113.0/24) | Nguồn **duy nhất** của mọi hoạt động tấn công |
| `kltn-ubuntu-1` | 10.30.1.0/24 | Host "hướng Internet": publish TCP 22/80/443 cho `kltn-inet` |
| `kltn-ubuntu-2` | 10.30.2.0/24 | Nội bộ |
| `kltn-windows-1` | 10.30.3.0/24 | Nội bộ |
| Mạng | `kltn-net-1..3`, `kltn-inet` qua `kltn-router` | Chỉ lưu lượng giữa các thành phần trên |

Mô hình: attacker ở "Internet giả lập" chỉ chạm được dịch vụ đã publish của `kltn-ubuntu-1` (perimeter = SG
`kltn-exposed`); ba subnet nạn nhân là một LAN nội bộ phẳng (SG `kltn-internal-lan`) ⇒ cần foothold rồi mới di
chuyển ngang. Nạn nhân được phép gọi ra (egress) tới `kltn-inet` (mô phỏng C2 / callback).

### 3.2 Ngoài phạm vi (CẤM tác động)
- Máy host vật lý `openstack-aio` dưới mọi địa chỉ: 192.168.2.10, VIP 192.168.2.250, **172.31.250.1** (br-exnat),
  100.99.56.11 (Tailscale).
- **Central KLTN** (`kltn-il3-*`: api, caddy, NATS, Postgres, MLflow, framework, workers) và các container Kolla /
  OpenStack control plane (Keystone, Nova, Neutron/OVN, Glance, MariaDB, RabbitMQ, ...).
- `public-net` 172.31.250.0/24 ngoài vai trò quản trị; `private-net` 10.20.0.0/24 và `main-router`.
- LAN 192.168.2.0/24, mạng Tailscale, Internet thật, mọi thiết bị khác.
- Hạ tầng OpenStack của chính lab ở mức API (tạo/xoá VM, sửa SG...) **không phải mục tiêu tấn công**; chỉ được
  dùng ở vai trò vận hành (mục 6) và response SOC (mục 7).

### 3.3 Ràng buộc kỹ thuật (đã thực thi bằng mạng, không chỉ bằng lời)
- SG `kltn-attacker`: không rule mặc định; ingress chỉ SSH 22 từ 172.31.250.1 (quản trị) + mọi lưu lượng từ
  10.30.0.0/16; egress chỉ tới 10.30.0.0/16.
- Floating IP của attacker **chỉ dùng để quản trị**; attacker không có đường tới 172.31.250.0/24 khi
  `attacker_provisioning = false`.
- Giai đoạn chuẩn bị (`attacker_provisioning = true`) attacker được ra Internet để cài công cụ — **cấm chạy bất kỳ
  bước tấn công nào** khi cờ này đang bật. Trước run đầu tiên: `terraform apply -var attacker_provisioning=false`
  và kiểm tra egress bị chặn (mục 8).

## 4. Hoạt động được phép
- Mô phỏng kỹ thuật ATT&CK bằng **framework mô phỏng đối thủ công khai, được cộng đồng phòng thủ dùng**
  (AttackMate, Atomic Red Team, MITRE Caldera, Metasploit Framework bản chính thức, công cụ hệ thống sẵn có /
  LOLBin) và script do red team viết, lưu trong `red-team/`.
- Trinh sát (quét cổng/dịch vụ) **chỉ nhắm các địa chỉ trong 3.1**.
- Truy cập ban đầu vào dịch vụ đã publish của `kltn-ubuntu-1`; được cố ý cấu hình dịch vụ có lỗ hổng / mật khẩu yếu
  **trên VM nạn nhân** để làm điểm vào (ghi lại trong kịch bản).
- Leo thang đặc quyền, persistence, discovery, credential access (chỉ credential của lab), lateral movement,
  C2 về `kltn-attacker`, exfiltration **dữ liệu giả** tới `kltn-attacker`.
- Impact **chỉ đảo ngược được**: mã hoá thư mục canary `/opt/kltn-canary` (Linux) / `C:\KLTN-canary` (Windows),
  dừng service không quan trọng; có bước hoàn tác trong cùng playbook.
- Biến đổi kịch bản giữa các run (thứ tự bước, thời điểm, công cụ, host đích, obfuscation) để tăng đa dạng.
- Tải framework / repo công khai từ nguồn chính thức về `red-team/` sau khi red team đã đọc mã sẽ chạy.

## 5. Hoạt động bị cấm
- Mọi tác động lên thành phần ngoài phạm vi (3.2), kể cả quét, dò mật khẩu, khai thác, DoS.
- Chạy **mã độc thật** (sample từ MalwareBazaar, ransomware thật, worm, ...) hoặc mã từ repo không rõ nguồn chưa đọc.
- Tự viết mã độc mới có khả năng tự lây lan; phát triển kỹ thuật né tránh EDR/AV để dùng ngoài lab.
- Impact không đảo ngược được: xoá/mã hoá dữ liệu ngoài canary, wipe đĩa, phá bootloader, xoá snapshot.
- DoS / làm cạn tài nguyên (fork bomb, flood, đào coin) — máy host đã crash nhiều lần, RAM là tài nguyên nguy hiểm.
- Làm hỏng sensor/agent/pipeline (tắt auditd, Sysmon, Fluent Bit, `kltn-agent`; sửa rule audit). Kỹ thuật
  "Impair Defenses" (T1562) chỉ được chạy khi chủ lab duyệt riêng cho kịch bản đó, có bước khôi phục.
- Đưa credential thật, khoá thật, dữ liệu cá nhân thật vào lab.

## 6. Vận hành và an toàn
- **Snapshot** 3 VM nạn nhân trước mỗi run; rollback sau run (hoặc khi chủ lab yêu cầu giữ trạng thái để điều tra).
- Mỗi run có **ID** (`<scenario>-<variant>-<YYYYMMDDTHHMMZ>`), thời điểm bắt đầu/kết thúc UTC, nhật ký red team.
- **Ngưỡng dừng tự động** — dừng chiến dịch ngay, đưa attacker về trạng thái cô lập, báo chủ lab khi:
  - `MemAvailable` máy host < 4 GiB, hoặc swap dùng > 6 GiB;
  - bất kỳ service OpenStack / central nào down hoặc unhealthy;
  - phát hiện lưu lượng từ attacker hoặc nạn nhân bị xâm nhập tới địa chỉ ngoài phạm vi;
  - hành vi ngoài dự kiến không giải thích được.
- **Kill switch** (chạy trên máy host):
  ```bash
  source /etc/kolla/admin-openrc.sh
  openstack server stop kltn-attacker                       # dừng attacker
  openstack server stop kltn-ubuntu-1 kltn-ubuntu-2 kltn-windows-1   # nếu cần dừng toàn bộ range
  ```
- Không chạy đồng thời > 1 chiến dịch. Không chạy run khi đang train mô hình trên GPU cùng máy.
- Benign workload chạy liên tục trong suốt run (benign xen lẫn tấn công).

## 7. Quy tắc SOC / response
- Chính sách hiện hành: `KLTN_APPROVAL_POLICY=single_operator` (người yêu cầu được tự duyệt; lab nghiên cứu đóng).
- **Cô lập** (`kltn-quarantine`) chỉ khi alert đã **Confirmed** với bằng chứng cụ thể trong central; ghi lý do +
  event id / score id vào `execution.approval`.
- **Mở cô lập** sau khi run kết thúc hoặc host đã rollback snapshot; ghi lại.
- Response chỉ áp dụng cho host trong 3.1. Không response lên central / host vật lý.
- Mỗi sự cố ghi: thời điểm bắt đầu tấn công (từ nhật ký red team), thời điểm alert đầu tiên, thời điểm confirm,
  thời điểm cô lập, bằng chứng, kết luận TP/FP.

## 8. Checklist trước mỗi run
1. ROE đã duyệt, nhóm kịch bản đã duyệt (mục 10).
2. `attacker_provisioning = false`; từ attacker: `curl -m5 https://1.1.1.1` **thất bại**, `nc -zv -w3 172.31.250.1
   18443` **thất bại**, tới 10.30.1.x:22 **thành công**.
3. Snapshot 3 nạn nhân xong.
4. Central: hàng đợi NATS 0, archiver chạy, `events` đang nhận từ cả 3 host.
5. Host: `MemAvailable` ≥ 8 GiB, không có huấn luyện GPU chạy song song.
6. Đóng/annotate alert cũ; ghi mốc thời gian bắt đầu.

## 9. Dữ liệu và công bố
- Dataset lưu dưới `IL/dataset_3-KLTN/` (tên dự kiến), mỗi run một thư mục: telemetry thô export từ central,
  nhật ký red team, nhãn event-level + window-level, README (kịch bản, ATT&CK, split, giới hạn, mục 2).
- Chia train/val/test **theo run**; giữ ít nhất một nhóm kịch bản cho test.
- Không chứa credential/khoá thật; địa chỉ nội bộ lab được phép giữ.

## 10. Phê duyệt
| Hạng mục | Trạng thái | Người duyệt | Ngày |
|---|---|---|---|
| ROE v0.1 | ☑ ĐÃ DUYỆT | nguyen | 2026-11-18 |
| Juice Shop (web exposed) + benign web/profiles | ☑ ĐÃ DUYỆT | nguyen | 2026-11-18 |
| Nhóm kịch bản #1 (tấn công) | ☐ chưa đề xuất | | |

## 11. Nhật ký thay đổi
| Ngày | Phiên bản | Thay đổi | Bởi |
|---|---|---|---|
| 2026-11-18 | v0.1 | Bản nháp đầu; thêm `kltn-inet` + `kltn-attacker`, SG perimeter/internal | Claude (yêu cầu của nguyen) |
