#!/bin/bash
# Script: /usr/local/bin/fix_audit_elk.sh

echo "==== BẮT ĐẦU VÁ LỖI GHI ĐÈ KOLLA CHO ELK AUDIT ===="

# --- 1. XỬ LÝ NOVA API ---
echo "[+] Vá cấu hình Nova..."
# Ép driver = log
sudo sed -i '/^\[oslo_messaging_notifications\]$/,/^\[/{s/^driver = messagingv2$/driver = log/}' /etc/kolla/nova-api/nova.conf
# Ép use_json = true vào block [DEFAULT]
if ! grep -q "^use_json = true" /etc/kolla/nova-api/nova.conf; then
    sudo sed -i '/^\[DEFAULT\]/a use_json = true' /etc/kolla/nova-api/nova.conf
fi
# Vá block [audit]
if ! grep -q "^\[audit\]" /etc/kolla/nova-api/nova.conf; then
    echo -e '\n[audit]\nenabled = true\naudit_map_file = /var/lib/kolla/config_files/api_audit_map.conf' | sudo tee -a /etc/kolla/nova-api/nova.conf
fi

# --- 2. XỬ LÝ NEUTRON SERVER ---
echo "[+] Vá cấu hình Neutron..."
# Ép driver = log
sudo sed -i '/^\[oslo_messaging_notifications\]$/,/^\[/{s/^driver = messagingv2$/driver = log/}' /etc/kolla/neutron-server/neutron.conf
# Ép use_json = true vào block [DEFAULT]
if ! grep -q "^use_json = true" /etc/kolla/neutron-server/neutron.conf; then
    sudo sed -i '/^\[DEFAULT\]/a use_json = true' /etc/kolla/neutron-server/neutron.conf
fi
# Vá block [audit]
if ! grep -q "^\[audit\]" /etc/kolla/neutron-server/neutron.conf; then
    echo -e '\n[audit]\nenabled = true\naudit_map_file = /etc/neutron/neutron_api_audit_map.conf' | sudo tee -a /etc/kolla/neutron-server/neutron.conf
fi

# --- 3. RESTART DỊCH VỤ ---
echo "[+] Khởi động lại các container bị ảnh hưởng..."
docker restart nova_api neutron_server

echo "==== HOÀN TẤT ===="