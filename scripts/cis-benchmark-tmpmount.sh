#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit
echo "1.1.2 - 1.1.5 - ensure /tmp is configured noexec,nodev,nosuid options set on  /tmp partition"
systemctl unmask tmp.mount && systemctl enable tmp.mount

cat > /etc/systemd/system/local-fs.target.wants/tmp.mount <<EOF
[Unit]
Description=Temporary Directory
Documentation=man:hier(7) 
Documentation=http://www.freedesktop.org/wiki/Software/systemd/APIFileSystems
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
  
[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid

# Make 'systemctl enable tmp.mount' work:
[Install]
WantedBy=local-fs.target
EOF

systemctl daemon-reload && systemctl restart tmp.mount
