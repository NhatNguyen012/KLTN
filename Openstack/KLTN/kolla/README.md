# Kolla-Ansible settings for Windows 11

Windows 11 guests use UEFI Secure Boot and a TPM 2.0 CRB device. Merge
`windows11.yml` into `/etc/kolla/globals.yml`, then mirror any newly enabled
service images into the configured registry before deployment.

This installation uses `docker_registry: 192.168.2.10:4000`. Do not stop or
disable that registry: Kolla pulls every service image from it. The safe flow
for a service image which is not present locally is:

```bash
docker pull quay.io/openstack.kolla/<image>:2026.1-ubuntu-noble
docker tag quay.io/openstack.kolla/<image>:2026.1-ubuntu-noble \
  192.168.2.10:4000/openstack.kolla/<image>:2026.1-ubuntu-noble
docker push 192.168.2.10:4000/openstack.kolla/<image>:2026.1-ubuntu-noble
```

For Barbican, repeat the flow for `barbican-api`,
`barbican-keystone-listener`, and `barbican-worker`. Then run from the Kolla
virtual environment:

```bash
kolla-ansible -i all-in-one prechecks --tags barbican,nova
kolla-ansible -i all-in-one deploy --tags loadbalancer
kolla-ansible -i all-in-one deploy --tags barbican
kolla-ansible -i all-in-one deploy --tags nova
```

The load-balancer pass reloads HAProxy and ProxySQL with the new Barbican API
and database routes. On this AIO host, a targeted Nova deployment may fail only
at the final scheduler HUP because the deployment user cannot signal the host
PID. If the Nova containers and service list are healthy, signal the container
directly:

```bash
docker kill --signal HUP nova_scheduler
```
