#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# Configure containerd service
containerd_dir="/etc/systemd/system/containerd.service.d"
containerd_env_file="${containerd_dir}/environment.conf"

mkdir -p "${containerd_dir}"
echo "[Service]" >> "${containerd_env_file}"
echo "EnvironmentFile=/etc/environment" >> "${containerd_env_file}"

# Configure kubelet service
kubelet_dir="/etc/systemd/system/kubelet.service.d"
kubelet_env_file="${kubelet_dir}/environment.conf"

mkdir -p "${kubelet_dir}"
echo "[Service]" >> "${kubelet_env_file}"
echo "EnvironmentFile=/etc/environment" >> "${kubelet_env_file}"
