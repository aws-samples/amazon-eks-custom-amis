#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

source /etc/packer/files/functions.sh

# wait for cloud-init to finish
wait_for_cloudinit

# upgrade the operating system
yum update -y && yum autoremove -y
yum install -y parted system-lsb-core

# enable the epel release
amazon-linux-extras install epel -y

echo "ensure secondary disk is mounted to proper locations"
partition_disks /dev/nvme2n1

echo "configuring /etc/environment"
configure_http_proxy
configure_docker_environment
configure_kubelet_environment

echo "rebooting the instance"
reboot
