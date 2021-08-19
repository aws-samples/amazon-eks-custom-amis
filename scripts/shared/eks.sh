#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

source /etc/packer/files/functions.sh

################################################################################
### Machine Architecture #######################################################
################################################################################
ARCH=$(get_arch)

# install dependencies

if (is_rhel && is_rhel_8) || (is_centos && is_centos_8); then

    dnf install -y \
        conntrack \
        curl \
        nfs-utils \
        socat \
        unzip

elif (is_rhel && is_rhel_7) || (is_centos && is_centos_7); then

    yum install -y \
        conntrack \
        curl \
        nfs-utils \
        socat \
        unzip

elif is_ubuntu; then

    apt-get install -y \
        conntrack \
        curl \
        socat \
        unzip \
        nfs-common

else

    echo "Could not install EKS dependencies, OS not supported!"
    exit 1

fi

################################################################################
### iptables ###################################################################
################################################################################
install_iptables_restore

################################################################################
### Logrotate ##################################################################
################################################################################

curl -sL -o /etc/logrotate.d/kube-proxy https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/logrotate-kube-proxy
curl -sL -o /etc/logrotate.conf https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/logrotate.conf
chown root:root /etc/logrotate.d/kube-proxy
chown root:root /etc/logrotate.conf
mkdir -p /var/log/journal

################################################################################
### Kubernetes #################################################################
################################################################################

mkdir -p /etc/kubernetes/manifests
mkdir -p /var/lib/kubernetes
mkdir -p /var/lib/kubelet
mkdir -p /opt/cni/bin

echo "Downloading binaries from: s3://$BINARY_BUCKET_NAME"
S3_DOMAIN="amazonaws.com"
if [ "$BINARY_BUCKET_REGION" = "cn-north-1" ] || [ "$BINARY_BUCKET_REGION" = "cn-northwest-1" ]; then
    S3_DOMAIN="amazonaws.com.cn"
elif [ "$BINARY_BUCKET_REGION" = "us-iso-east-1" ]; then
    S3_DOMAIN="c2s.ic.gov"
elif [ "$BINARY_BUCKET_REGION" = "us-isob-east-1" ]; then
    S3_DOMAIN="sc2s.sgov.gov"
fi

S3_URL_BASE="https://$BINARY_BUCKET_NAME.s3.$BINARY_BUCKET_REGION.$S3_DOMAIN/$KUBERNETES_VERSION/$KUBERNETES_BUILD_DATE/bin/linux/$ARCH"
S3_PATH="s3://$BINARY_BUCKET_NAME/$KUBERNETES_VERSION/$KUBERNETES_BUILD_DATE/bin/linux/$ARCH"

BINARIES=(
    kubelet
    aws-iam-authenticator
)

for binary in ${BINARIES[*]} ; do
    echo "AWS cli missing - using wget to fetch binaries from s3. Note: This won't work for private bucket."
    curl -sL -o $binary $S3_URL_BASE/$binary
    curl -sL -o $binary.sha256 $S3_URL_BASE/$binary.sha256

    sha256sum -c $binary.sha256
    chmod +x $binary
    mv $binary /usr/bin/
done

# Since CNI 0.7.0, all releases are done in the plugins repo.
CNI_PLUGIN_FILENAME="cni-plugins-linux-${ARCH}-${CNI_PLUGIN_VERSION}"

curl -sL -o "${CNI_PLUGIN_FILENAME}.tgz" "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/${CNI_PLUGIN_FILENAME}.tgz"
curl -sL -o "${CNI_PLUGIN_FILENAME}.tgz.sha512" "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/${CNI_PLUGIN_FILENAME}.tgz.sha512"

sha512sum -c "${CNI_PLUGIN_FILENAME}.tgz.sha512"
rm "${CNI_PLUGIN_FILENAME}.tgz.sha512"

tar -xvf "${CNI_PLUGIN_FILENAME}.tgz" -C /opt/cni/bin
rm "${CNI_PLUGIN_FILENAME}.tgz"

rm ./*.sha256

mkdir -p /etc/kubernetes/kubelet
mkdir -p /etc/systemd/system/kubelet.service.d

curl -sL -o /var/lib/kubelet/kubeconfig https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/kubelet-kubeconfig
chown root:root /var/lib/kubelet/kubeconfig

curl -sL -o /etc/systemd/system/kubelet.service https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/kubelet.service
chown root:root /etc/systemd/system/kubelet.service

curl -sL -o /etc/kubernetes/kubelet/kubelet-config.json https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/kubelet-config.json
chown root:root /etc/kubernetes/kubelet/kubelet-config.json

configure_kubelet_environment

systemctl daemon-reload && systemctl disable kubelet

################################################################################
### EKS ########################################################################
################################################################################

mkdir -p /etc/eks
curl -sL -o /etc/eks/eni-max-pods.txt https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/eni-max-pods.txt
curl -sL -o /etc/eks/bootstrap.sh https://raw.githubusercontent.com/awslabs/amazon-eks-ami/ff309f19/files/bootstrap.sh
chmod +x /etc/eks/bootstrap.sh

################################################################################
### Stuff required by "protectKernelDefaults=true" #############################
################################################################################

cat > /etc/sysctl.d/99-amazon.conf <<EOF
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
EOF

# relabel the operating system now that all bits are installed
touch /.autorelabel
reboot
