data "openstack_networking_network_v2" "external" {
  name = var.external_network_name
}

data "openstack_images_image_v2" "ubuntu" {
  name        = var.ubuntu_image_name
  most_recent = true
}

data "openstack_images_image_v2" "windows" {
  name        = var.windows_image_name
  most_recent = true
}

data "openstack_compute_flavor_v2" "ubuntu" {
  name = var.ubuntu_flavor_name
}

resource "openstack_compute_flavor_v2" "windows" {
  name      = var.windows_flavor.name
  ram       = var.windows_flavor.ram_mb
  vcpus     = var.windows_flavor.vcpus
  disk      = var.windows_flavor.disk_gb
  is_public = true

  extra_specs = {
    "trait:COMPUTE_SECURITY_TPM_2_0" = "required"
    "trait:COMPUTE_SECURITY_TPM_CRB" = "required"
  }
}

resource "openstack_networking_network_v2" "node" {
  for_each = var.nodes

  name           = each.value.network_name
  admin_state_up = true
  mtu            = var.network_mtu
}

resource "openstack_networking_subnet_v2" "node" {
  for_each = var.nodes

  name            = each.value.subnet_name
  network_id      = openstack_networking_network_v2.node[each.key].id
  cidr            = each.value.cidr
  gateway_ip      = cidrhost(each.value.cidr, 1)
  ip_version      = 4
  enable_dhcp     = true
  dns_nameservers = var.dns_nameservers

  allocation_pool {
    start = each.value.allocation_pool_start
    end   = each.value.allocation_pool_end
  }
}

resource "openstack_networking_router_v2" "main" {
  name                = var.router_name
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.external.id
  enable_snat         = true
}

resource "openstack_networking_router_interface_v2" "node" {
  for_each = var.nodes

  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.node[each.key].id
}

resource "openstack_networking_secgroup_v2" "instance" {
  name        = var.security_group_name
  description = "KLTN lab: allow inbound SSH, RDP and IPv4 ICMP"
}

resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.ssh_source_cidr
  security_group_id = openstack_networking_secgroup_v2.instance.id
}

resource "openstack_networking_secgroup_rule_v2" "rdp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3389
  port_range_max    = 3389
  remote_ip_prefix  = var.rdp_source_cidr
  security_group_id = openstack_networking_secgroup_v2.instance.id
}

resource "openstack_networking_secgroup_rule_v2" "icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.instance.id
}

resource "openstack_compute_keypair_v2" "created" {
  count = var.create_keypair ? 1 : 0

  name       = var.keypair_name
  public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "openstack_networking_port_v2" "instance" {
  for_each = var.nodes

  name               = "${each.value.instance_name}-port"
  network_id         = openstack_networking_network_v2.node[each.key].id
  admin_state_up     = true
  security_group_ids = [openstack_networking_secgroup_v2.instance.id]

  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.node[each.key].id
  }
}

resource "openstack_compute_instance_v2" "node" {
  for_each = var.nodes

  name = each.value.instance_name
  image_id = (
    each.value.os_type == "windows"
    ? data.openstack_images_image_v2.windows.id
    : data.openstack_images_image_v2.ubuntu.id
  )
  flavor_id = (
    each.value.os_type == "windows"
    ? openstack_compute_flavor_v2.windows.id
    : data.openstack_compute_flavor_v2.ubuntu.id
  )
  key_pair     = var.keypair_name
  config_drive = each.value.os_type == "windows"
  user_data = (
    each.value.os_type == "windows"
    ? file("${path.module}/windows-user-data.ps1")
    : null
  )

  network {
    port = openstack_networking_port_v2.instance[each.key].id
  }

  depends_on = [
    openstack_compute_keypair_v2.created,
    openstack_networking_router_interface_v2.node,
  ]
}

resource "openstack_networking_floatingip_v2" "node" {
  for_each = var.create_floating_ips ? var.nodes : {}

  pool    = data.openstack_networking_network_v2.external.name
  port_id = openstack_networking_port_v2.instance[each.key].id

  depends_on = [openstack_networking_router_interface_v2.node]
}

