#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

################################################################
# Migrate existing folder to a new partition
#
# Globals:
#   None
# Arguments:
#   1 - the path of the disk or partition
#   2 - the folder path to migration
#   3 - the mount options to use.
# Outputs:
#   None
################################################################
migrate_and_mount_disk() {
    local disk_name=$1
    local folder_path=$2
    local mount_options=$3
    local temp_path="/mnt${folder_path}"
    local old_path="${folder_path}-old"

    # install an ext4 filesystem to the disk
    mkfs -t ext4 ${disk_name}

    # check if the folder already exists
    if [ -d "${folder_path}" ]; then
        FILE=$(ls -A ${folder_path})
        >&2 echo $FILE
        mkdir -p ${temp_path}
        mount ${disk_name} ${temp_path}
        # Empty folder give error on /*
        if [ ! -z "$FILE" ]; then
            cp -Rax ${folder_path}/* ${temp_path}
        fi
    fi

    # create the folder
    mkdir -p ${folder_path}

    # add the mount point to fstab and mount the disk
    echo "UUID=$(blkid -s UUID -o value ${disk_name}) ${folder_path} ext4 ${mount_options} 0 1" >> /etc/fstab
    mount -a

    # if selinux is enabled restore the objects on it
    if selinuxenabled; then
        restorecon -R ${folder_path}
    fi
}

disk_name='/dev/nvme1n1'

# partition the disk
parted -a optimal -s $disk_name \
    mklabel gpt \
    mkpart var ext4 0% 20% \
    mkpart varlog ext4 20% 40% \
    mkpart varlogaudit ext4 40% 60% \
    mkpart home ext4 60% 70% \
    mkpart varlibdocker ext4 70% 90%

# wait for the disks to settle
sleep 5

# migrate and mount the existing
migrate_and_mount_disk "${disk_name}p1" /var            defaults,nofail,nodev
migrate_and_mount_disk "${disk_name}p2" /var/log        defaults,nofail,nodev,nosuid
migrate_and_mount_disk "${disk_name}p3" /var/log/audit  defaults,nofail,nodev,nosuid
migrate_and_mount_disk "${disk_name}p4" /home           defaults,nofail,nodev,nosuid

# Create folder instead of starting/stopping docker daemon
mkdir -p /var/lib/docker
chown -R root:docker /var/lib/docker
migrate_and_mount_disk "${disk_name}p5" /var/lib/docker defaults,nofail
