#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

source /etc/packer/files/functions.sh

ARCH=$(get_arch)

if (is_rhel && is_rhel_7) || (is_centos && is_centos_7); then

  yum remove -y \
    docker \
    docker-client \
    docker-client-latest \
    docker-common \
    docker-latest \
    docker-latest-logrotate \
    docker-logrotate \
    docker-selinux \
    docker-engine-selinux \
    docker-engine

  yum install -y device-mapper-persistent-data lvm2 yum-utils
  yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  sed -i 's/\$releasever/7/g' /etc/yum.repos.d/docker-ce.repo
  yum install -y docker-ce docker-ce-cli containerd.io

elif (is_rhel && is_rhel_8) || (is_centos && is_centos_8); then

  dnf remove -y \
    docker \
    docker-client \
    docker-client-latest \
    docker-common \
    docker-latest \
    docker-latest-logrotate \
    docker-logrotate \
    docker-selinux \
    docker-engine-selinux \
    docker-engine

  dnf install -y device-mapper-persistent-data lvm2
  dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
  dnf install -y docker-ce docker-ce-cli containerd.io

elif is_ubuntu; then

  apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
  add-apt-repository "deb [arch=${ARCH}] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io

else

  echo "could not install docker, operating system not found!"
  exit 1

fi

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

