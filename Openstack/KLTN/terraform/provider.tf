# Authentication is intentionally read from the OS_* variables exported by
# /etc/kolla/admin-openrc.sh. Do not put OpenStack passwords in Terraform files.
provider "openstack" {
}

