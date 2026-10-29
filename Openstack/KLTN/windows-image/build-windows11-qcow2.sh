#!/usr/bin/env bash
set -Eeuo pipefail

WINDOWS_ISO="${WINDOWS_ISO:-/etc/kolla/images/windows_11_enterprise_ltsc_2024.iso}"
VIRTIO_TOOLS="${VIRTIO_TOOLS:-/etc/kolla/images/virtio-win-guest-tools.exe}"
CLOUDBASE_MSI="${CLOUDBASE_MSI:-/etc/kolla/images/CloudbaseInitSetup_Stable_x64.msi}"
OUTPUT_IMAGE="${OUTPUT_IMAGE:-/etc/kolla/images/windows_11_enterprise_ltsc_2024_openstack.qcow2}"
BUILD_ROOT="${BUILD_ROOT:-/etc/kolla/images/windows11-build}"
KOLLA_LIBVIRT_IMAGE="${KOLLA_LIBVIRT_IMAGE:-192.168.2.10:4000/openstack.kolla/nova-libvirt:2026.1-ubuntu-noble}"
DISK_SIZE="${DISK_SIZE:-64G}"
VNC_DISPLAY="${VNC_DISPLAY:-9}"
MONITOR_PORT="${MONITOR_PORT:-4449}"
MIN_BUILD_BYTES="${MIN_BUILD_BYTES:-2147483648}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ASSET_DIR=""
BOOT_KEY_PID=""

cleanup() {
    if [[ -n "$BOOT_KEY_PID" ]]; then
        kill "$BOOT_KEY_PID" 2>/dev/null || true
    fi
    if [[ -n "$ASSET_DIR" && -d "$ASSET_DIR" ]]; then
        docker run --rm \
            --entrypoint /bin/sh \
            --volume "$ASSET_DIR:/cleanup" \
            "$KOLLA_LIBVIRT_IMAGE" \
            -lc 'find /cleanup -mindepth 1 -delete' >/dev/null 2>&1 || true
        rmdir -- "$ASSET_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

for command_name in docker qemu-img openssl sed sha256sum stat; do
    command -v "$command_name" >/dev/null || {
        echo "Missing required command: $command_name" >&2
        exit 1
    }
done

for required_file in "$WINDOWS_ISO" "$VIRTIO_TOOLS" "$CLOUDBASE_MSI"; do
    [[ -r "$required_file" ]] || {
        echo "Missing or unreadable input: $required_file" >&2
        exit 1
    }
done

[[ -e /dev/kvm ]] || {
    echo "/dev/kvm is unavailable" >&2
    exit 1
}

if [[ -e "$OUTPUT_IMAGE" ]]; then
    echo "Refusing to overwrite existing output: $OUTPUT_IMAGE" >&2
    exit 1
fi

mkdir -p -- "$BUILD_ROOT"
if [[ -e "$BUILD_ROOT/golden.qcow2" ]]; then
    echo "Refusing to overwrite an existing build disk: $BUILD_ROOT/golden.qcow2" >&2
    exit 1
fi

ASSET_DIR="$(mktemp -d /tmp/windows11-openstack-assets.XXXXXX)"
chmod 0700 "$ASSET_DIR"

BUILD_PASSWORD="$(openssl rand -hex 24)"
sed "s/@@BUILD_PASSWORD@@/${BUILD_PASSWORD}/g" \
    "$SCRIPT_DIR/Autounattend.xml.in" > "$ASSET_DIR/Autounattend.xml"
unset BUILD_PASSWORD

install -m 0644 "$SCRIPT_DIR/Finalize.ps1" "$ASSET_DIR/Finalize.ps1"
install -m 0644 "$CLOUDBASE_MSI" "$ASSET_DIR/CloudbaseInitSetup_Stable_x64.msi"
install -m 0644 "$VIRTIO_TOOLS" "$ASSET_DIR/virtio-win-guest-tools.exe"

qemu-img create -f qcow2 -o compat=1.1,lazy_refcounts=on "$BUILD_ROOT/golden.qcow2" "$DISK_SIZE"

docker run --rm \
    --entrypoint /bin/sh \
    --volume "$BUILD_ROOT:/work" \
    "$KOLLA_LIBVIRT_IMAGE" \
    -lc 'install -m 0644 /usr/share/OVMF/OVMF_VARS_4M.ms.fd /work/OVMF_VARS.fd'

cat > "$BUILD_ROOT/input-sha256.txt" <<EOF
$(sha256sum "$WINDOWS_ISO")
$(sha256sum "$VIRTIO_TOOLS")
$(sha256sum "$CLOUDBASE_MSI")
EOF

echo "Starting unattended Windows installation. Local VNC: 127.0.0.1:$((5900 + VNC_DISPLAY))"
echo "The VM will shut down after VirtIO, Cloudbase-Init and Sysprep complete."

# Microsoft installation media waits briefly for a key before booting. Feed
# Enter only during that early boot window through a loopback-only monitor.
(
    for _ in {1..100}; do
        if { exec 3<>"/dev/tcp/127.0.0.1/$MONITOR_PORT"; } 2>/dev/null; then
            sleep 1
            for _ in {1..14}; do
                printf 'sendkey ret\n' >&3
                sleep 0.5
            done
            exec 3>&-
            exit 0
        fi
        sleep 0.2
    done
    echo "Warning: could not connect to the local QEMU monitor to send the DVD boot key" >&2
) &
BOOT_KEY_PID=$!

docker run --rm \
    --name windows11-image-build \
    --entrypoint /bin/sh \
    --device /dev/kvm \
    --network host \
    --security-opt apparmor=unconfined \
    --volume "$WINDOWS_ISO:/images/windows.iso:ro" \
    --volume "$ASSET_DIR:/config:rw" \
    --volume "$BUILD_ROOT:/work" \
    "$KOLLA_LIBVIRT_IMAGE" \
    -lc '
        set -eu
        mkdir -p /work/swtpm
        swtpm socket \
            --tpm2 \
            --tpmstate dir=/work/swtpm \
            --ctrl type=unixio,path=/work/swtpm.sock \
            --terminate \
            --daemon
        exec qemu-system-x86_64 \
            -name windows11-image-build \
            -enable-kvm \
            -machine q35,accel=kvm,smm=on \
            -global driver=cfi.pflash01,property=secure,value=on \
            -cpu host,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_time \
            -smp 4 \
            -m 6144 \
            -rtc base=localtime,clock=host \
            -nodefaults \
            -no-user-config \
            -device virtio-rng-pci \
            -device qemu-xhci,id=xhci \
            -device ich9-ahci,id=sata0 \
            -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.ms.fd \
            -drive if=pflash,format=raw,file=/work/OVMF_VARS.fd \
            -drive file=/work/golden.qcow2,if=none,id=osdisk,format=qcow2,cache=writeback,discard=unmap \
            -device ide-hd,drive=osdisk,bus=sata0.0,bootindex=2 \
            -drive file=/images/windows.iso,if=none,id=windowscd,media=cdrom,readonly=on \
            -device ide-cd,drive=windowscd,bus=sata0.1,bootindex=1 \
            -drive file=fat:rw:/config,if=none,id=configusb,format=raw \
            -device usb-storage,drive=configusb,removable=on \
            -chardev socket,id=chrtpm,path=/work/swtpm.sock \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-crb,tpmdev=tpm0 \
            -chardev socket,id=qga0,path=/work/qga.sock,server=on,wait=off \
            -device virtio-serial-pci,id=virtio-serial0 \
            -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
            -device VGA \
            -device usb-kbd \
            -device usb-tablet \
            -vnc 127.0.0.1:'"$VNC_DISPLAY"' \
            -serial file:/work/serial.log \
            -monitor tcp:127.0.0.1:'"$MONITOR_PORT"',server=on,wait=off \
            -boot once=d,menu=on \
            -nic none
    '

wait "$BOOT_KEY_PID" || true
BOOT_KEY_PID=""

build_bytes="$(stat -c '%s' "$BUILD_ROOT/golden.qcow2")"
if (( build_bytes < MIN_BUILD_BYTES )); then
    echo "Build disk is unexpectedly small ($build_bytes bytes); refusing to publish it" >&2
    exit 1
fi

qemu-img check "$BUILD_ROOT/golden.qcow2"
qemu-img convert -p -c -f qcow2 -O qcow2 \
    -o compat=1.1,lazy_refcounts=on \
    "$BUILD_ROOT/golden.qcow2" "$OUTPUT_IMAGE.partial"
qemu-img check "$OUTPUT_IMAGE.partial"
mv -- "$OUTPUT_IMAGE.partial" "$OUTPUT_IMAGE"
sha256sum "$OUTPUT_IMAGE" > "$OUTPUT_IMAGE.sha256"
qemu-img info "$OUTPUT_IMAGE"
echo "Built image: $OUTPUT_IMAGE"
