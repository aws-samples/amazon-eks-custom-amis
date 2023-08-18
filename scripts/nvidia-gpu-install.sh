#!/usr/bin/env bash

set -x

# https://docs.nvidia.com/datacenter/tesla/index.html
NVIDIA_DRIVER_VERSION=${NVIDIA_DRIVER_VERSION:-"535.86.10"}

# CUDA toolkit https://docs.nvidia.com/datacenter/tesla/drivers/index.html#cuda-drivers
CUDA_TOOLKIT_PACKAGE=${CUDA_TOOLKIT_PACKAGE:-cuda-toolkit-12-2}

# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/efa-verify.html
EFA_INSTALLER_VERSION=${EFA_INSTALLER_VERSION:-"1.25.0"}

# https://www.open-mpi.org/software/hwloc/v2.9/
MPI_HWLOC_VERSION=${MPI_HWLOC_VERSION:-"2.9.2"}

# https://github.com/aws/aws-ofi-nccl/releases
AWS_OFI_NCCL_VERSION=${AWS_OFI_NCCL_VERSION:-"1.7.1"}

# Remove existing NVIDIA driver if present
if yum list installed 2>/dev/null | grep -q "^nvidia-driver"; then
    yum erase -y nvidia-driver-* -q
    rm /etc/yum.repos.d/amzn2-nvidia.rep
fi

yum install gcc10 rsync dkms -y -q
cd /tmp

# CUDA tooklit - can be installed on host or deployed in container
if ${INSTALL_NVIDIA_CONTAINER_TOOLKIT:-true}; then
  yum-config-manager --add-repo https://developer.download.nvidia.com/compute/cuda/repos/rhel7/x86_64/cuda-rhel7.repo
  yum clean all -q
  yum install libglvnd-glx ${CUDA_TOOLKIT_PACKAGE} -y -q
fi

# EFA - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/efa-start.html
# EFA installer wants CUDA to be available first and it installs kernel-devel wich the NVIDIA driver requires
curl -s -O https://efa-installer.amazonaws.com/aws-efa-installer-${EFA_INSTALLER_VERSION}.tar.gz
tar -xf aws-efa-installer-${EFA_INSTALLER_VERSION}.tar.gz && cd aws-efa-installer
./efa_installer.sh -y -g
cd /tmp
rm -rf /aws-efa-installer*
# Validate
/opt/amazon/efa/bin/fi_info fi_info -p efa -t FI_EP_RDM

# NVIDIA driver
wget -q -O NVIDIA-Linux-driver.run "https://us.download.nvidia.com/tesla/${NVIDIA_DRIVER_VERSION}/NVIDIA-Linux-x86_64-${NVIDIA_DRIVER_VERSION}.run"
CC=gcc10-cc sh NVIDIA-Linux-driver.run -s -a --ui=none
rm NVIDIA-Linux-driver.run

# Install FabricManager
curl -s -O https://developer.download.nvidia.com/compute/nvidia-driver/redist/fabricmanager/linux-x86_64/fabricmanager-linux-x86_64-${NVIDIA_DRIVER_VERSION}-archive.tar.xz
tar -xf fabricmanager-linux-x86_64-${NVIDIA_DRIVER_VERSION}-archive.tar.xz
rsync -al fabricmanager-linux-x86_64-${NVIDIA_DRIVER_VERSION}-archive/ /usr/ --exclude LICENSE
mv /usr/systemd/nvidia-fabricmanager.service /usr/lib/systemd/system
systemctl enable nvidia-fabricmanager
rm -rf fabricmanager-linux*

# NVIDIA container toolkit - can be installed on host or deployed in container
if ${INSTALL_NVIDIA_CONTAINER_TOOLKIT:-true}; then
  DISTRIBUTION=$(. /etc/os-release;echo $ID$VERSION_ID)
  curl -s -L https://nvidia.github.io/nvidia-docker/${DISTRIBUTION}/nvidia-docker.repo | tee /etc/yum.repos.d/nvidia-docker.repo
  yum install -y nvidia-container-toolkit -q
fi

# Setup EFA device plugin

# hwloc - https://www.open-mpi.org/projects/hwloc/tutorials/20120702-POA-hwloc-tutorial.html
wget -q https://download.open-mpi.org/release/hwloc/v${MPI_HWLOC_VERSION::-2}/hwloc-${MPI_HWLOC_VERSION}.tar.gz
tar xf hwloc-${MPI_HWLOC_VERSION}.tar.gz && cd hwloc-${MPI_HWLOC_VERSION}
./configure
make -s
make install -s
cd /tmp
rm -rf hwloc-${MPI_HWLOC_VERSION}*

# aws-ofi-nccl plugin - https://github.com/aws/aws-ofi-nccl
yum install autoconf automake libtool -y -q
cd /tmp
wget -q https://github.com/aws/aws-ofi-nccl/releases/download/v${AWS_OFI_NCCL_VERSION}-aws/aws-ofi-nccl-${AWS_OFI_NCCL_VERSION}-aws.tar.gz
tar xf aws-ofi-nccl-${AWS_OFI_NCCL_VERSION}-aws.tar.gz && cd ./aws-ofi-nccl-${AWS_OFI_NCCL_VERSION}-aws
./autogen.sh
./configure --with-libfabric=/opt/amazon/efa/ --with-cuda=/usr/local/cuda/ --with-mpi=/opt/amazon/openmpi/
make -s
make install -s
cd /tmp
rm -rf aws-ofi-nccl-${AWS_OFI_NCCL_VERSION}*

# Setup NCCL

# NCCL https://github.com/NVIDIA/nccl
wget -q -O nccl.zip https://github.com/NVIDIA/nccl/archive/refs/heads/master.zip
unzip -qq nccl.zip && cd nccl-master
make -j src.build -s
make pkg.redhat.build -s
rpm -ivh build/pkg/rpm/x86_64/*.rpm
cd /tmp
rm -rf nccl*
