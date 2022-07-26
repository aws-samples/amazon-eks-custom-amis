#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

source /tmp/functions.sh

# ensure the directory is created
mkdir -p /etc/systemd/system/docker.service.d
mkdir -p /etc/docker

DOCKER_SELINUX_ENABLED="false"

if selinuxenabled; then
  # enable container selinux boolean
  setsebool container_manage_cgroup on

  # enable SELinux in the docker daemon
  DOCKER_SELINUX_ENABLED="true"
fi

cat > /etc/docker/daemon.json <<EOF
{
  "bridge": "none",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "10"
  },
  "icc": false,
  "iptables": true,
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 200,
      "Soft": 100
    },
    "nofile": {
      "Name": "nproc",
      "Hard": 2048,
      "Soft": 1024
    }
  },
  "live-restore": true,
  "userland-proxy": false,
  "max-concurrent-downloads": 10,
  "experimental": false,
  "insecure-registries": [],
  "selinux-enabled": ${DOCKER_SELINUX_ENABLED}
}
EOF

chown root:root /etc/docker/daemon.json

configure_docker_environment

systemctl daemon-reload
systemctl enable docker && systemctl start docker
