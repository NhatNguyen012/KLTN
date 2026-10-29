# Windows 11 Enterprise LTSC 2024 cloud image

This builder preserves the source ISO and creates an unattended OpenStack-ready
QCOW2 image with:

- UEFI Secure Boot firmware and TPM 2.0/CRB during installation;
- Fedora VirtIO guest tools and QEMU Guest Agent;
- Cloudbase-Init for OpenStack metadata, hostname and password injection;
- automatic BitLocker/device encryption disabled before OOBE so the reusable
  cloud disk is not sealed to the build-time TPM;
- RDP enabled; and
- a final Sysprep `/generalize /oobe /shutdown` pass.

Inputs default to `/etc/kolla/images/`. Run:

```bash
./build-windows11-qcow2.sh
```

The required packages are the Windows ISO, Fedora's direct
`virtio-win-guest-tools.exe` bundle, and the stable Cloudbase-Init x64 MSI. The
builder deliberately uses a SATA installation disk, installs all VirtIO
drivers plus QEMU Guest Agent from the bundle, and publishes an image
configured for VirtIO-SCSI in OpenStack. Downloading the much larger
`virtio-win.iso` is therefore not required.

The successful build on 2026-10-28 used these SHA-256 values:

```text
157d8365a517c40afeb3106fdd74d0836e1025debbc343f2080e1a8687607f51  windows_11_enterprise_ltsc_2024.iso
d8ae9ea1e943384ac195e012cd36f82c3161620e5fc9529be4e42e6f420e222d  virtio-win-guest-tools.exe
0e7fa42e0cbc0ce7657f85730b0c6cc7afc4087a3639df0ff51a721a0be19bd5  CloudbaseInitSetup_Stable_x64.msi
```

The local VNC console is bound only to `127.0.0.1:5909`. The final image is
published atomically as:

```text
/etc/kolla/images/windows_11_enterprise_ltsc_2024_openstack.qcow2
```

Its verified SHA-256 is
`ac11046675d95a7d35f7745ef10f78119add853aa7834458416559921929ef15`.

The build uses Microsoft's public Windows 11 Enterprise LTSC 2024 KMS client
setup key to select the ISO edition. This does not activate Windows and does not
grant a license. Supply a valid activation mechanism for deployed instances.

Recommended Glance properties:

```bash
openstack image create "Windows 11 Enterprise LTSC 2024" \
  --file /etc/kolla/images/windows_11_enterprise_ltsc_2024_openstack.qcow2 \
  --disk-format qcow2 \
  --container-format bare \
  --property os_type=windows \
  --property os_distro=windows \
  --property os_version=11 \
  --property hw_machine_type=q35 \
  --property hw_firmware_type=uefi \
  --property os_secure_boot=required \
  --property hw_disk_bus=scsi \
  --property hw_scsi_model=virtio-scsi \
  --property hw_vif_model=virtio \
  --property hw_qemu_guest_agent=yes \
  --property hw_tpm_version=2.0 \
  --property hw_tpm_model=tpm-crb
```

For a reusable flavor, set at least 4 vCPU, 6 GiB RAM and a 64 GiB root disk.
TPM properties may be moved from the image to flavor extra specs if desired.
