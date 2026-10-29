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
4 vCPU, 8192 MiB RAM, disk 80 GiB và yêu cầu TPM 2.0/CRB. External network là
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
- Cloudbase-Init tạo mật khẩu ngẫu nhiên và mã hóa nó bằng public key của
  `lab-key`. Không commit mật khẩu Administrator vào tfvars.
- Đặt `create_floating_ips = false` nếu chỉ cần IP private/SNAT outbound.
- State nằm cục bộ trong thư mục này. Không commit `*.tfstate` vì state có thể
  chứa dữ liệu nhạy cảm.

## Kết quả smoke test 2026-10-28

Vòng `init -> validate -> plan -> apply -> destroy` đã tạo và xóa thành công
toàn bộ 24 resource. Hai Ubuntu đạt `ACTIVE`, hoàn tất cloud-init và SSH được.
Windows đạt `ACTIVE`, nhận đúng fixed IP, QEMU Guest Agent phản hồi; libvirt xác
nhận Q35/UEFI Secure Boot và TPM 2.0 CRB có secret mã hóa trong Barbican.

Giới hạn còn lại: trong image Glance hiện tại, Cloudbase-Init chưa thực thi
PowerShell user-data trước khi hết thời gian smoke test, nên `TermService` vẫn
`STOPPED` và TCP/3389 chưa mở. Việc tạo/schedule/boot Windows đã qua kiểm thử,
nhưng cần sửa hoặc rebuild image Cloudbase-Init trước khi coi RDP là sẵn sàng.

Chỉ khi muốn xóa toàn bộ tài nguyên do cấu hình này quản lý:

```bash
terraform destroy

# Tùy chọn: khôi phục trạng thái nghỉ của lab sau khi destroy.
openstack compute service set --disable \
  --disable-reason "KLTN lab idle" openstack-aio nova-compute
```
