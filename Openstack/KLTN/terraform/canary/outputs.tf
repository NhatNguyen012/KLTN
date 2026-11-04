output "canary_instance_id" {
  description = "Nova instance ID of Windows canary."
  value       = openstack_compute_instance_v2.canary.id
}

output "canary_private_ip" {
  description = "Private IP of Windows canary."
  value       = openstack_networking_port_v2.canary.all_fixed_ips[0]
}

output "canary_floating_ip" {
  description = "Floating IP of Windows canary."
  value       = openstack_networking_floatingip_v2.canary.address
}

output "rdp_endpoint" {
  description = "RDP address for Windows canary."
  value       = "${openstack_networking_floatingip_v2.canary.address}:3389"
}

output "ansible_host" {
  description = "Ansible host record for inventory generation."
  value = {
    os_type = "windows"
    host_id = openstack_compute_instance_v2.canary.id
    address = openstack_networking_floatingip_v2.canary.address
  }
}

output "ansible_hosts" {
  description = "Ansible hosts map for inventory generation compatibility."
  value = {
    "windows-canary" = {
      os_type = "windows"
      host_id = openstack_compute_instance_v2.canary.id
      address = openstack_networking_floatingip_v2.canary.address
    }
  }
}


