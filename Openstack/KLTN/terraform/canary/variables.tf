variable "external_network_name" {
  description = "Name of the existing external network used by the router and floating IPs."
  type        = string
  default     = "public-net"
}

variable "windows_image_name" {
  description = "Name of the existing Windows 11 Glance image."
  type        = string
  default     = "Windows-11-Enterprise-LTSC-2024"
}

variable "windows_flavor" {
  description = "Flavor created for Windows 11 canary; requires at least 4096 MiB RAM, 2 vCPUs and 64 GiB disk."
  type = object({
    name    = string
    ram_mb  = number
    vcpus   = number
    disk_gb = number
  })
  default = {
    name    = "kltn.windows11.canary"
    ram_mb  = 6144
    vcpus   = 4
    disk_gb = 80
  }
}

variable "keypair_name" {
  description = "Name of the Nova keypair assigned to instances."
  type        = string
  default     = "lab-key"
}

variable "router_name" {
  description = "Name of the router connecting the canary subnet to the external network."
  type        = string
  default     = "kltn-canary-router"
}

variable "security_group_name" {
  description = "Security group for the Windows canary instance."
  type        = string
  default     = "kltn-canary-secgroup"
}

variable "rdp_source_cidr" {
  description = "IPv4 CIDR allowed to connect to Windows Remote Desktop."
  type        = string
  default     = "172.31.250.1/32"
}

variable "management_source_cidr" {
  description = "Controller source IPv4 CIDR for WinRM HTTPS (host br-exnat in this lab)."
  type        = string
  default     = "172.31.250.1/32"
}

variable "dns_nameservers" {
  description = "DNS resolvers advertised by DHCP on the canary subnet."
  type        = list(string)
  default     = ["1.1.1.1", "8.8.8.8"]
}

variable "network_mtu" {
  description = "Tenant network MTU."
  type        = number
  default     = 1442
}

variable "canary_node" {
  description = "Single Windows Canary instance definition."
  type = object({
    instance_name         = string
    network_name          = string
    subnet_name           = string
    cidr                  = string
    allocation_pool_start = string
    allocation_pool_end   = string
  })
  default = {
    instance_name         = "kltn-windows-canary"
    network_name          = "kltn-canary-net"
    subnet_name           = "kltn-canary-subnet"
    cidr                  = "10.30.10.0/24"
    allocation_pool_start = "10.30.10.100"
    allocation_pool_end   = "10.30.10.200"
  }
}

