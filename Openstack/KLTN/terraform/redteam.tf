# Red-team range (red-team/ROE.md). The attacker sits on a simulated Internet segment (`kltn-inet`, RFC 5737
# TEST-NET-3) behind kltn-router; victims see its real source address, not SNAT. Security groups play the role of
# the perimeter firewall: from the outside only the exposed node's published services are reachable, while the
# three victim subnets form one flat internal LAN (lateral movement). The attacker never gets a path to public-net
# (= host br-exnat, where central lives): its floating IP exists for management only and its egress is limited to
# the range.

resource "openstack_networking_network_v2" "inet" {
  name           = var.attacker_network.network_name
  admin_state_up = true
  mtu            = var.network_mtu
}

resource "openstack_networking_subnet_v2" "inet" {
  name            = var.attacker_network.subnet_name
  network_id      = openstack_networking_network_v2.inet.id
  cidr            = var.attacker_network.cidr
  gateway_ip      = cidrhost(var.attacker_network.cidr, 1)
  ip_version      = 4
  enable_dhcp     = true
  dns_nameservers = var.dns_nameservers

  allocation_pool {
    start = cidrhost(var.attacker_network.cidr, 100)
    end   = cidrhost(var.attacker_network.cidr, 200)
  }
}

resource "openstack_networking_router_interface_v2" "inet" {
  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.inet.id
}

# Victims: flat internal LAN between the three victim subnets.
resource "openstack_networking_secgroup_v2" "internal" {
  name        = "kltn-internal-lan"
  description = "KLTN range: victims accept any traffic from the victim subnets (lateral movement)"
}

resource "openstack_networking_secgroup_rule_v2" "internal_in" {
  for_each          = toset(["tcp", "udp", "icmp"])
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = each.value
  remote_ip_prefix  = var.victim_supernet
  security_group_id = openstack_networking_secgroup_v2.internal.id
}

# Victims: services the exposed node publishes to the simulated Internet.
resource "openstack_networking_secgroup_v2" "exposed" {
  name        = "kltn-exposed"
  description = "KLTN range: published services of the Internet-facing victim"
}

resource "openstack_networking_secgroup_rule_v2" "exposed_in" {
  for_each          = toset([for p in var.exposed_tcp_ports : tostring(p)])
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = tonumber(each.value)
  port_range_max    = tonumber(each.value)
  remote_ip_prefix  = var.attacker_network.cidr
  security_group_id = openstack_networking_secgroup_v2.exposed.id
}

# Attacker: no default rules. Ingress = management SSH from the controller + callbacks from victims; egress = the
# range only, plus the Internet while attacker_provisioning is true (apt/pip/git during setup, no attack runs).
resource "openstack_networking_secgroup_v2" "attacker" {
  name                 = "kltn-attacker"
  description          = "KLTN attacker: management from controller, traffic limited to the range"
  delete_default_rules = true
}

resource "openstack_networking_secgroup_rule_v2" "attacker_mgmt_in" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.management_source_cidr
  security_group_id = openstack_networking_secgroup_v2.attacker.id
}

resource "openstack_networking_secgroup_rule_v2" "attacker_range_in" {
  for_each          = toset(["tcp", "udp", "icmp"])
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = each.value
  remote_ip_prefix  = var.victim_supernet
  security_group_id = openstack_networking_secgroup_v2.attacker.id
}

resource "openstack_networking_secgroup_rule_v2" "attacker_range_out" {
  for_each          = toset(["tcp", "udp", "icmp"])
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = each.value
  remote_ip_prefix  = var.victim_supernet
  security_group_id = openstack_networking_secgroup_v2.attacker.id
}

resource "openstack_networking_secgroup_rule_v2" "attacker_provision_out" {
  count             = var.attacker_provisioning ? 1 : 0
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.attacker.id
}

resource "openstack_networking_port_v2" "attacker" {
  name               = "${var.attacker_instance_name}-port"
  network_id         = openstack_networking_network_v2.inet.id
  admin_state_up     = true
  security_group_ids = [openstack_networking_secgroup_v2.attacker.id]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.inet.id
    ip_address = cidrhost(var.attacker_network.cidr, 66)
  }
}

data "openstack_compute_flavor_v2" "attacker" {
  name = var.attacker_flavor_name
}

resource "openstack_compute_instance_v2" "attacker" {
  name      = var.attacker_instance_name
  image_id  = data.openstack_images_image_v2.ubuntu.id
  flavor_id = data.openstack_compute_flavor_v2.attacker.id
  key_pair  = var.keypair_name

  network {
    port = openstack_networking_port_v2.attacker.id
  }

  depends_on = [openstack_networking_router_interface_v2.inet]
}

resource "openstack_networking_floatingip_v2" "attacker" {
  pool    = data.openstack_networking_network_v2.external.name
  port_id = openstack_networking_port_v2.attacker.id

  depends_on = [openstack_networking_router_interface_v2.inet]
}
