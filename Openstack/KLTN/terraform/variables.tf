variable "external_network_name" {
  description = "Name of the existing external network used by the router and floating IPs."
  type        = string
  default     = "public-net"
}

variable "ubuntu_image_name" {
  description = "Name of the existing Ubuntu Glance image."
  type        = string
  default     = "Ubuntu-24.04"
}

variable "windows_image_name" {
  description = "Name of the existing Windows 11 Glance image."
  type        = string
  default     = "Windows-11-Enterprise-LTSC-2024"
}

variable "ubuntu_flavor_name" {
  description = "Name of the existing Nova flavor used by the Ubuntu instances."
  type        = string
  default     = "m1.small"
}

variable "windows_flavor" {
  description = "Flavor created for Windows 11; the image requires at least 64 GiB disk and 4 GiB RAM."
  type = object({
    name    = string
    ram_mb  = number
    vcpus   = number
    disk_gb = number
  })
  default = {
    name    = "kltn.windows11"
    ram_mb  = 6144
    vcpus   = 4
    disk_gb = 80
  }

  validation {
    condition = (
      var.windows_flavor.ram_mb >= 4096 &&
      var.windows_flavor.vcpus >= 2 &&
      var.windows_flavor.disk_gb >= 64
    )
    error_message = "The Windows flavor needs at least 4096 MiB RAM, 2 vCPUs and 64 GiB disk."
  }
}

variable "keypair_name" {
  description = "Name of the Nova keypair assigned to all instances."
  type        = string
  default     = "lab-key"
}

variable "create_keypair" {
  description = "Create keypair_name from ssh_public_key_path. Leave false when the keypair already exists."
  type        = bool
  default     = false
}

variable "ssh_public_key_path" {
  description = "Local public-key path used only when create_keypair is true."
  type        = string
  default     = "~/.ssh/openstack_ed25519.pub"
}

variable "router_name" {
  description = "Name of the router connecting the three tenant subnets to the external network."
  type        = string
  default     = "kltn-router"
}

variable "security_group_name" {
  description = "Security group shared by the three instance ports."
  type        = string
  default     = "kltn-allow-ssh-ping"
}

variable "ssh_source_cidr" {
  description = "IPv4 CIDR allowed to SSH to the instances. Restrict this outside a lab."
  type        = string
  default     = "172.31.250.1/32"

  validation {
    condition     = can(cidrnetmask(var.ssh_source_cidr))
    error_message = "ssh_source_cidr must be a valid IPv4 CIDR."
  }
}

variable "rdp_source_cidr" {
  description = "IPv4 CIDR allowed to connect to Windows Remote Desktop. Restrict this outside a lab."
  type        = string
  default     = "172.31.250.1/32"

  validation {
    condition     = can(cidrnetmask(var.rdp_source_cidr))
    error_message = "rdp_source_cidr must be a valid IPv4 CIDR."
  }
}

variable "dns_nameservers" {
  description = "DNS resolvers advertised by DHCP on each subnet."
  type        = list(string)
  default     = ["1.1.1.1", "8.8.8.8"]
}

variable "network_mtu" {
  description = "Tenant network MTU. The Kolla AIO guide uses 1442."
  type        = number
  default     = 1442
}

variable "create_floating_ips" {
  description = "Allocate and associate one floating IP with each instance port."
  type        = bool
  default     = true
}

variable "nodes" {
  description = "Exactly three instances, each backed by its own network and IPv4 subnet."
  type = map(object({
    instance_name         = string
    os_type               = string
    network_name          = string
    subnet_name           = string
    cidr                  = string
    allocation_pool_start = string
    allocation_pool_end   = string
  }))

  default = {
    ubuntu1 = {
      instance_name         = "kltn-ubuntu-1"
      os_type               = "ubuntu"
      network_name          = "kltn-net-1"
      subnet_name           = "kltn-subnet-1"
      cidr                  = "10.30.1.0/24"
      allocation_pool_start = "10.30.1.100"
      allocation_pool_end   = "10.30.1.200"
    }
    ubuntu2 = {
      instance_name         = "kltn-ubuntu-2"
      os_type               = "ubuntu"
      network_name          = "kltn-net-2"
      subnet_name           = "kltn-subnet-2"
      cidr                  = "10.30.2.0/24"
      allocation_pool_start = "10.30.2.100"
      allocation_pool_end   = "10.30.2.200"
    }
    windows1 = {
      instance_name         = "kltn-windows-1"
      os_type               = "windows"
      network_name          = "kltn-net-3"
      subnet_name           = "kltn-subnet-3"
      cidr                  = "10.30.3.0/24"
      allocation_pool_start = "10.30.3.100"
      allocation_pool_end   = "10.30.3.200"
    }
  }

  validation {
    condition     = length(var.nodes) == 3
    error_message = "nodes must contain exactly three entries."
  }

  validation {
    condition = (
      length([for node in values(var.nodes) : node if node.os_type == "ubuntu"]) == 2 &&
      length([for node in values(var.nodes) : node if node.os_type == "windows"]) == 1
    )
    error_message = "nodes must contain exactly two Ubuntu nodes and one Windows node."
  }

  validation {
    condition     = alltrue([for node in values(var.nodes) : can(cidrnetmask(node.cidr))])
    error_message = "Every node CIDR must be a valid IPv4 CIDR."
  }

  validation {
    condition     = length(distinct([for node in values(var.nodes) : node.cidr])) == 3
    error_message = "Each node must use a different subnet CIDR."
  }

  validation {
    condition     = length(distinct([for node in values(var.nodes) : node.network_name])) == 3
    error_message = "Each node must use a different network name."
  }

  validation {
    condition     = length(distinct([for node in values(var.nodes) : node.subnet_name])) == 3
    error_message = "Each node must use a different subnet name."
  }
}


variable "management_source_cidr" {
  description = "Controller source IPv4 CIDR for WinRM HTTPS (host br-exnat in this lab)."
  type        = string
  default     = "172.31.250.1/32"
  validation {
    condition     = can(cidrnetmask(var.management_source_cidr))
    error_message = "management_source_cidr must be an IPv4 CIDR."
  }
}
