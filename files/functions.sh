#!/usr/bin/env bash

wait_for_cloudinit() {
    while [ ! -f /var/lib/cloud/instance/boot-finished ]; do echo 'Waiting for cloud-init...'; sleep 5; done
}

install_awscliv2() {
    curl -o awscliv2.zip "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip"
    unzip awscliv2.zip
    ./aws/install -i /usr/local/aws-cli -b /usr/bin
    rm -f awscliv2.zip
}

is_amazonlinux2() {
    [[ $(lsb_release -sd) == "\"Amazon Linux"* ]]
}

is_ubuntu() {
    [[ $(lsb_release -sd) == "Ubuntu"* ]]
}

is_ubuntu_18() {
    [[ $(lsb_release -sr) == "18"* ]]
}

is_ubuntu_20() {
    [[ $(lsb_release -sr) = "20"* ]]
}

is_rhel() {
    [[ $(lsb_release -sd) == "\"Red Hat"* ]]
}

is_rhel_7() {
    [[ $(lsb_release -sr) == "7"* ]]
}

is_rhel_8() {
    [[ $(lsb_release -sr) == "8"* ]]
}

is_centos() {
    [[ $(lsb_release -sd) == "\"CentOS"* ]]
}

is_centos_7() {
    [[ $(lsb_release -sr) == "7"* ]]
}

is_centos_8() {
    [[ $(lsb_release -sr) == "8"* ]]
}

install_ssmagent() {

    if is_ubuntu; then
        snap install amazon-ssm-agent --classic
        systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
        systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service
    else
        yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
        systemctl enable amazon-ssm-agent && systemctl start amazon-ssm-agent
    fi

}

install_openscap() {

    if is_rhel || is_centos; then
        echo "installing OpenSCAP on Red Hat Enterprise Linux..."
        yum install -y openscap openscap-scanner scap-security-guide
    elif is_amazonlinux2; then
        echo "installing OpenSCAP on Amazon Linux 2..."
        yum install -y openscap openscap-scanner scap-security-guide
    elif is_ubuntu; then
        echo "installing OpenSCAP on Ubuntu..."
        apt-get install -y libopenscap8 ssg-debian ssg-debderived
    else
        echo "operating system not supported with OpenSCAP..."
        exit 1
    fi
}

install_jq() {
    curl -sL -o /usr/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
    chmod +x /usr/bin/jq
}

oscap_generate_fix() {
    local oscap_source=$1
    local oscap_profile=$2
    local oscap_tailoring_file=${3:-}

    echo "attempting to install OpenSCAP..."
    install_openscap

    if [ ! -z "${oscap_tailoring_file}" ]; then

        echo "generating hardening script using ${oscap_profile} from ${oscap_tailoring_file} based on ${oscap_source}..."
        oscap xccdf generate fix \
            --output /etc/packer/hardening.sh \
            --tailoring-file $oscap_tailoring_file \
            --profile $oscap_profile \
            --fetch-remote-resources $oscap_source

    else

        echo "generating hardening script using ${oscap_profile} from ${oscap_source}..."
        oscap xccdf generate fix \
            --output /etc/packer/hardening.sh \
            --profile $oscap_profile \
            --fetch-remote-resources $oscap_source
    fi
}

migrate_and_mount_disk() {
  local DISK_NAME=$1
  local FOLDER_PATH=$2
  local TEMP_PATH="/mnt${FOLDER_PATH}"
  local OLD_PATH="${FOLDER_PATH}-old"

  echo "applying ext4 filesystem to ${DISK_NAME}"
  mkfs -t ext4 ${DISK_NAME}

  if [ -d "${FOLDER_PATH}" ]; then

    echo "making temporary mount point for ${TEMP_PATH}"
    mkdir -p ${TEMP_PATH}

    echo "mounting ${DISK_NAME} to ${TEMP_PATH}"
    mount ${DISK_NAME} ${TEMP_PATH}

    echo "migrating existing content to the temp location"
    cp -Rax ${FOLDER_PATH}/* ${TEMP_PATH}

    echo "migrate existing folder to old location"
    mv ${FOLDER_PATH} ${OLD_PATH}

    echo "unmounting ${DISK_NAME}"
    umount ${DISK_NAME}

  fi

  echo "recreate ${FOLDER_PATH}"
  mkdir -p ${FOLDER_PATH}

  echo "updating /etc/fstab with UUID of ${DISK_NAME} and ${FOLDER_PATH}"
  echo "UUID=$(blkid -s UUID -o value ${DISK_NAME}) ${FOLDER_PATH} ext4 defaults,nofail 0 1" >> /etc/fstab

  echo "mounting disk to system"
  mount -a
}

partition_disks() {
    local disk_name=$1

    echo "show all disks on the system"
    lsblk

    echo "partition ${disk_name} into 5 parts for /var, /var/log, /var/log/audit, /home, /var/lib/docker"
    parted -a optimal -s $disk_name \
        mklabel gpt \
        mkpart var ext4 0% 20% \
        mkpart varlog ext4 20% 40% \
        mkpart varlogaudit ext4 40% 60% \
        mkpart home ext4 60% 70% \
        mkpart varlibdocker ext4 70% 90%

    echo "waiting for disks to settle"
    sleep 5

    echo "migrating /var, /var/log, /var/log/audit, /home, /var/lib/docker to new partitions"
    migrate_and_mount_disk "${disk_name}p1" /var
    migrate_and_mount_disk "${disk_name}p2" /var/log
    migrate_and_mount_disk "${disk_name}p3" /var/log/audit
    migrate_and_mount_disk "${disk_name}p4" /home
    migrate_and_mount_disk "${disk_name}p5" /var/lib/docker
}

configure_http_proxy() {
    touch /etc/environment

    if [ -z "${HTTP_PROXY}" ]; then
        echo "http_proxy=${HTTP_PROXY}" >> /etc/environment
        echo "HTTP_PROXY=${HTTP_PROXY}" >> /etc/environment
    fi

    if [ -z "${HTTPS_PROXY}" ]; then
        echo "https_proxy=${HTTPS_PROXY}" >> /etc/environment
        echo "HTTPS_PROXY=${HTTPS_PROXY}" >> /etc/environment
    fi

    if [ -z "${NO_PROXY}" ]; then
        echo "no_proxy=${NO_PROXY}" >> /etc/environment
        echo "NO_PROXY=${NO_PROXY}" >> /etc/environment
    fi
}

enable_fips() {

    if is_rhel_7; then

        # install dependencies
        yum install -y dracut-fips-aesni dracut-fips

        # we will configure FIPS ourselves as the generated STIG locks the OS
        # configure dracut-fips
        dracut -f

        # udpate the kernel settings
        grubby --update-kernel=ALL --args="fips=1"

        # configure this to meet the stig checker
        sed -i "/^GRUB_CMDLINE_LINUX/ s/\"$/ fips=1\"/" /etc/default/grub

        # set the ssh ciphers
        sed -i 's/^Cipher.*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/' /etc/ssh/sshd_config
        sed -i 's/^MACs.*/MACs hmac-sha2-256,hmac-sha2-512/' /etc/ssh/sshd_config

    elif is_rhel_8; then
        fips-mode-setup --enable
    else
        echo "FIPS 140-2 is not supported on this operating system."
    fi

}
