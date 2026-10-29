output "instance_ids" {
  description = "Nova instance IDs keyed by node key."
  value       = { for key, instance in openstack_compute_instance_v2.node : key => instance.id }
}

output "private_ipv4" {
  description = "Private IPv4 address of each instance."
  value = {
    for key, port in openstack_networking_port_v2.instance :
    key => one([for address in port.all_fixed_ips : address if can(regex("^[0-9]+\\.", address))])
  }
}

output "floating_ipv4" {
  description = "Floating IPv4 address of each instance; empty when create_floating_ips is false."
  value = {
    for key, floating_ip in openstack_networking_floatingip_v2.node :
    key => floating_ip.address
  }
}

output "network_topology" {
  description = "Network, subnet and CIDR assigned to every instance."
  value = {
    for key, node in var.nodes : key => {
      instance = node.instance_name
      os_type  = node.os_type
      network  = node.network_name
      subnet   = node.subnet_name
      cidr     = node.cidr
    }
  }
}

output "ssh_commands" {
  description = "Example SSH command for each Ubuntu floating IP."
  value = {
    for key, floating_ip in openstack_networking_floatingip_v2.node :
    key => "ssh -i ${trimsuffix(pathexpand(var.ssh_public_key_path), ".pub")} ubuntu@${floating_ip.address}"
    if var.nodes[key].os_type == "ubuntu"
  }
}

output "rdp_endpoints" {
  description = "RDP endpoint for each Windows floating IP."
  value = {
    for key, floating_ip in openstack_networking_floatingip_v2.node :
    key => "${floating_ip.address}:3389"
    if var.nodes[key].os_type == "windows"
  }
}

