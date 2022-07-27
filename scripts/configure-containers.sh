#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# Configure docker service
docker_dir="/etc/systemd/system/docker.service.d"
docker_env_file="${docker_dir}/environment.conf"

mkdir -p "${docker_dir}"
echo "[Service]" >> "${docker_env_file}"
echo "EnvironmentFile=/etc/environment" >> "${docker_env_file}"

# Configure kubelet service
kubelet_dir="/etc/systemd/system/kubelet.service.d"
kubelet_env_file="${kubelet_dir}/environment.conf"

mkdir -p "${kubelet_dir}"
echo "[Service]" >> "${kubelet_env_file}"
echo "EnvironmentFile=/etc/environment" >> "${kubelet_env_file}"
