#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# upgrade the operating system
yum update -y && yum autoremove -y
yum install -y parted system-lsb-core

# enable the epel release
amazon-linux-extras install epel -y

echo "rebooting the instance"
reboot
