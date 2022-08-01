#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# Clean up yum caches to reduce the image size
yum clean all
rm -rf /var/cache/yum

# Clean up files to reduce confusion during debug
rm -rf \
    /var-old \
    /var/lib/docker-old \
    /var/log-old \
    /var/log/audit-old \
    /home-old \
    /etc/packer \
    /etc/hostname \
    /etc/machine-id \
    /etc/resolv.conf \
    /etc/ssh/ssh_host* \
    /home/ec2-user/.ssh/authorized_keys \
    /root/.ssh/authorized_keys \
    /var/lib/cloud/data \
    /var/lib/cloud/instance \
    /var/lib/cloud/instances \
    /var/lib/cloud/sem \
    /var/lib/dhclient/* \
    /var/lib/dhcp/dhclient.* \
    /var/lib/yum/history \
    /var/log/cloud-init-output.log \
    /var/log/cloud-init.log \
    /var/log/secure \
    /var/log/wtmp

touch /etc/machine-id
