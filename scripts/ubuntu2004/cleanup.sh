#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# Clean up files to reduce confusion during debug
apt-get -y clean

rm -rf \
    /var-old \
    /var/log-old \
    /var/log/audit-old \
    /home-old \
    /etc/packer \
    /var/lib/docker-old 

touch /etc/machine-id
