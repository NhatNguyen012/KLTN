# Terraform: 2 Ubuntu + 1 Windows trên 3 subnet

Cấu hình này tạo hai máy Ubuntu 24.04 và một máy Windows 11 Enterprise LTSC
2024. Mỗi máy nằm trên một tenant network và subnet riêng. Ba subnet cùng nối
vào một router có external gateway là `public-net`; mỗi máy mặc định được cấp
một floating IP.

| Instance | OS | Network | Subnet | CIDR |
|---|---|---|---|---|
| `kltn-ubuntu-1` | Ubuntu 24.04 | `kltn-net-1` | `kltn-subnet-1` | `10.30.1.0/24` |
| `kltn-ubuntu-2` | Ubuntu 24.04 | `kltn-net-2` | `kltn-subnet-2` | `10.30.2.0/24` |
| `kltn-windows-1` | Windows 11 LTSC 2024 | `kltn-net-3` | `kltn-subnet-3` | `10.30.3.0/24` |

Ubuntu dùng image `Ubuntu-24.04` và flavor `m1.small`. Windows dùng image
`Windows-11-Enterprise-LTSC-2024`; Terraform tạo flavor `kltn.windows11` gồm
4 vCPU, 6144 MiB RAM, disk 80 GiB và yêu cầu TPM 2.0/CRB. External network là
`public-net`, keypair có sẵn là `lab-key`.

## Chuẩn bị

Terraform đọc thông tin xác thực từ các biến `OS_*` do Kolla OpenRC export; mật
khẩu không được lưu trong mã Terraform. Chạy trong cùng một shell:

```bash
source "$HOME/venvs/kolla-2026.1/bin/activate"
source /etc/kolla/admin-openrc.sh
cd /etc/kolla/inventory
export PYTHONWARNINGS="ignore"

# Compute host của lab đang được giữ disabled khi không chạy thử.
openstack compute service set --enable openstack-aio nova-compute

cd /mnt/SSD_Data/optc/Openstack/KLTN/terraform
cp terraform.tfvars.example terraform.tfvars
```

`lab-key` đã tồn tại và public key tương ứng mặc định là
`~/.ssh/openstack_ed25519.pub`. Nếu đổi sang keypair mới, đặt
`create_keypair = true`, đồng thời sửa `keypair_name` và
`ssh_public_key_path`.

## Kiểm tra và triển khai

```bash
terraform fmt -check
terraform init
terraform validate
terraform plan -out=kltn.tfplan
terraform apply kltn.tfplan
```

Sau khi apply:

```bash
terraform output
openstack server list
openstack network list
openstack subnet list
openstack router show kltn-router
```

Lấy lệnh SSH được tạo sẵn:

```bash
terraform output -json ssh_commands
```

## Tùy chỉnh và lưu ý

- Sao chép `terraform.tfvars.example` thành `terraform.tfvars`; file thật được
  gitignore để tránh commit cấu hình cục bộ.
- `nodes` bắt buộc có đúng ba phần tử, ba CIDR/network/subnet khác nhau.
- Mặc định SSH mở từ `0.0.0.0/0` để tiện cho lab AIO. Hãy giới hạn
  `ssh_source_cidr` và `rdp_source_cidr` khi dùng trong môi trường chia sẻ.
- Windows image phải có các property UEFI, Secure Boot, TPM 2.0 và VirtIO như
  mô tả tại `../windows-image/README.md`.
- Cloudbase-Init nhận metadata và `windows-user-data.ps1` qua config drive. Script
  first-boot được thiết kế để bật `TermService`, Windows Firewall cho RDP và
  ICMP echo.
- Tài khoản Cloudbase-Init hiện tại là `Admin`, không phải `Administrator`.
  Với image/config drive đã kiểm tra, plugin dùng `admin_pass` do Nova đưa vào
  config drive; mật khẩu này không được đăng ngược lên API password của Nova.
  `lab-key` là Ed25519: không coi đây là khóa RSA dùng để giải mã mật khẩu
  Windows. Không commit mật khẩu hoặc nội dung config drive vào tfvars/log/git.
- Đặt `create_floating_ips = false` nếu chỉ cần IP private/SNAT outbound.
- State nằm cục bộ trong thư mục này. Không commit `*.tfstate` vì state có thể
  chứa dữ liệu nhạy cảm.

## Kết quả smoke test 2026-10-28

Vòng `init -> validate -> plan -> apply -> destroy` đã tạo và xóa thành công
toàn bộ 24 resource. Hai Ubuntu đạt `ACTIVE`, hoàn tất cloud-init và SSH được.
Windows đạt `ACTIVE`, nhận đúng fixed IP, QEMU Guest Agent phản hồi; libvirt xác
nhận Q35/UEFI Secure Boot và TPM 2.0 CRB có secret mã hóa trong Barbican.

Lần kiểm tra này kết thúc khi `TermService` còn `STOPPED`. Đây chưa phải bằng
chứng Cloudbase-Init bị lỗi hoặc image cần rebuild; xem lần kiểm tra tiếp bên dưới.

## Chẩn đoán trực tiếp 2026-10-29

Đã tạo lại Windows từ nguyên image Glance
`8916e3cb-025e-45d8-81ba-4c4be7881f97`, dùng nguyên user-data 654 byte.
Không đổi ISO, không sửa guest để bật RDP. Các mốc giờ guest (UTC+7):

| Mốc | Bằng chứng |
|---|---|
| 13:17:49 | Windows bắt đầu specialize/OOBE |
| 13:18:33 | Hai tiến trình Cloudbase-Init dừng lâu tại import `WindowsUtils` |
| 13:22:50 | Service nạp ConfigDrive; có lỗi tài khoản/WMI trong lúc Setup chưa hoàn tất |
| Sau reboot tự động | Plugin tạo `Admin` và cấu hình mạng thành công |
| 13:23:18 | `Executing plugin 'UserDataPlugin'` |
| 13:23:26 | `User_data script ended with return code: 0` |
| 13:23:27 | `Plugins execution done` |

Phép thử import độc lập ghi nhận chờ tại `win32security`; chưa xác định nguyên
nhân sâu hơn của thời gian chờ native này. Nó tự kết thúc, không phải bằng
chứng deadlock vĩnh viễn. Sau first-boot, `TermService` là Running/Automatic,
TCP/3389 kết nối được qua floating IP, và Windows `LogonUserW` xác thực `Admin`
thành công. Chưa kiểm tra phiên desktop RDP tương tác.

`cloudbase-init` chuyển sang Stopped sau khi hoàn tất là bình thường. Không dùng
riêng trạng thái service hoặc trạng thái Nova `ACTIVE` để kết luận first-boot xong.
Chờ tối đa 15 phút và kiểm tra cổng từ máy có route tới floating IP:

```bash
python3 wait-windows-rdp.py "$(terraform output -json floating_ipv4 | python3 -c 'import json,sys; print(json.load(sys.stdin)["windows1"])')"
```

Helper kiểm tra TCP ba lần cách nhau 5 giây; nó không kiểm tra mật khẩu hay bảo
đảm mọi plugin đã hoàn tất. Khi timeout, đọc cả `cloudbase-init.log`,
`cloudbase-init-unattend.log` và `C:\Windows\Panther\UnattendGC\setupact.log`.
Nếu QEMU `guest-file-open` báo file log đang bị dùng, đọc qua PowerShell
`Get-Content`; trong specialize, PowerShell cũng có thể chờ lâu.

Lỗi tài liệu mật khẩu đã được xác nhận: log báo
`Cannot set the password in the metadata as it is not supported by this service`,
và API Nova trả mật khẩu mã hóa rỗng. ConfigDrive không có khả năng post password
như [HTTP metadata service](https://cloudbase-init.readthedocs.io/en/latest/services.html).
Trong lab hiện tại, quản trị viên có thể đọc `openstack/latest/meta_data.json`
trên ổ `config-2` bằng QEMU Guest Agent và giữ riêng trường `admin_pass` trong
file quyền 0600. Không in toàn bộ metadata ra log. Nếu muốn quy trình lấy mật
khẩu mã hóa qua Nova, cần thiết kế và kiểm thử riêng HTTP metadata + khóa RSA;
chỉ thay keypair không đủ.

## Kết quả triển khai và khắc phục Windows 11 (2026-10-29)

Hiện tại, cả 3 máy ảo (`kltn-ubuntu-1`, `kltn-ubuntu-2`, `kltn-windows-1`) đang chạy ở trạng thái **ACTIVE** và đang gửi telemetry thật về central pipeline.

### Các vấn đề đã xác định và giải pháp xử lý

1. **Windows tự động Hibernate/Sleep (`pmsuspended` / `shut off`)**:
   - *Triệu chứng:* Sau một thời gian không tương tác, Windows 11 tự động chuyển sang trạng thái `pmsuspended` trong libvirt hoặc tắt hẳn.
   - *Khắc phục:* Đã bổ sung cấu hình tắt sleep/hibernate vào [windows-user-data.ps1](windows-user-data.ps1) và hàm reconcile trong `prepare_inventory.py`:
     ```powershell
     powercfg /change standby-timeout-ac 0
     powercfg /change hibernate-timeout-ac 0
     powercfg /hibernate off
     ```

2. **WinRM HTTPS Certificate thiếu IP SAN**:
   - *Triệu chứng:* Listener mặc định của Cloudbase-Init chỉ gán Subject `CN=<hostname>`, gây lỗi xác thực TLS khi Ansible kết nối qua IP (5986).
   - *Khắc phục:* [prepare_inventory.py](../scripts/prepare_inventory.py) tự động reconcile chứng thư tự ký có SAN `IPAddress=<management_ip>`, gán thumbprint vào HTTPS listener và export chứng thư `.pem` sang `runtime/` để Ansible xác thực an toàn (không dùng `server_cert_validation: ignore`).

3. **UAC Remote Restrictions (`LocalAccountTokenFilterPolicy`)**:
   - *Triệu chứng:* Ansible báo lỗi `Task failed: ntlm: the specified credentials were rejected by the server` khi dùng tài khoản local `Admin`.
   - *Khắc phục:* Bật chính sách cho phép local administrator remote qua NTLM:
     ```powershell
     Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1 -Force
     ```

4. **Tình trạng file ISO Windows**:
   - Thư mục `/etc/kolla/images/` hiện có:
     - `windows_11_enterprise_ltsc_2024.iso` (ISO ban đầu dùng để build image hiện tại)
     - `26100.1742...CLIENT_LTSC_EVAL_x64FRE_en-us.iso` (bản Evaluation chính thức)
     - `26300.9457...CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso` (bản Enterprise Eval 26H2)
   - *Kết luận:* Image hiện tại (`Windows-11-Enterprise-LTSC-2024`, ID `8916e3cb-025e-45d8-81ba-4c4be7881f97`) đã được cấu hình và kiểm chứng hoạt động hoàn toàn ổn định (WinRM, Sysmon, Fluent Bit, RDP). **Không cần phải rebuild lại image** từ các file Evaluation trừ khi có yêu cầu chuyển đổi sang phiên bản đánh giá 90 ngày.

### Kết quả kiểm chứng thực tế

- **Ansible WinRM**: `ansible.windows.win_ping` trả về `pong` thành công.
- **Sensor Deployment**: Role `windows_sensor` cài đặt và khởi động thành công Sysmon (chữ ký số Microsoft hợp lệ) và Fluent Bit native service.
- **Telemetry Streaming**: Central PostgreSQL đã nhận đầy đủ sự kiện từ cả 7 luồng:
  - Windows: `sysmon`, `security`, `powershell`
  - Ubuntu: `audit`, `journal`
- **Smoke test**: `ansible-playbook smoke.yml -e smoke_marker=...` hoàn thành 100% trên cả 3 VM và được xác thực tồn tại trong DB.

## Dọn dẹp tài nguyên

Chỉ khi muốn xóa toàn bộ tài nguyên lab:

```bash
terraform destroy

# Khôi phục trạng thái nghỉ của lab sau khi destroy:
openstack compute service set --disable \
  --disable-reason "KLTN lab idle" openstack-aio nova-compute
```

## Collector pilot

Triển khai Ansible và central Docker theo [runbook KLTN](../README.md).
WinRM HTTPS 5986 chỉ mở cho `management_source_cidr`; inventory pin cert qua QGA.
