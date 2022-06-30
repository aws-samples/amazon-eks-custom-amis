#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

tmpfs_and_mount() {
  FOLDER_PATH=$1

  mkdir -p ${FOLDER_PATH}
  echo "tmpfs ${FOLDER_PATH} tmpfs mode=1777,strictatime,noexec,nodev,nosuid 0 0" >> /etc/fstab
  mount -a
}

unload_module() {
  local fsname=$1

  rmmod "${fsname}" || true
  mkdir -p /etc/modprobe.d/
  echo "install ${fsname} /bin/true" > "/etc/modprobe.d/${fsname}.conf"
}

systemd_disable() {
  local service_name=$1

  if systemctl is-enabled $service_name; then
    systemctl disable $service_name
  fi
}

yum_remove() {
  local package_name=$1

  if rpm -q $package_name; then
    yum remove -y $package_name
  fi
}

sysctl_entry() {
  local entry=$1

  echo "$entry" >> /etc/sysctl.d/cis.conf
  systctl -w $entry
}

set_conf_value() {
  local key=$1
  local value=$2
  local file=$3

  sed -i "s/^\(${key}\s*=\s*\).*$/\1${value}/" $file
}

check_ipv6() {
    [ -n "$passing" ] && passing=""
    [ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disable=1)" ] && passing="true"
    grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" /etc/sysctl.conf \
    /etc/sysctl.d/*.conf && grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" \
    /etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl net.ipv6.conf.all.disable_ipv6 | \
    grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && \
    sysctl net.ipv6.conf.default.disable_ipv6 | \
    grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && passing="true" 
    if [ "$passing" = true ] ; then 
        echo "IPv6 is disabled on the system" 
    else 
        echo "IPv6 is enabled on the system" 
    fi
}
####### Version 2.0.0 CIS Amazon Linux 2 Benchmark

echo "1.1.1.1 - ensure mounting of cramfs filesystems is disabled"
unload_module cramfs

echo "1.1.1.2 - ensure mounting of squashfs filesystems is disabled"
unload_module squashfs

echo "1.1.1.3 - ensure mounting of udf filesystems is disabled"
unload_module udf

echo "1.1.2 - 1.1.5 - ensure /tmp is configured nodev,nosuid,noexec options set on  /tmp partition"
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
EOF

systemctl daemon-reload && systemctl restart tmp.mount

echo "1.1.6 - 1.1.9 - Ensure /dev/shm is configured noexec,nodev,nosuid options for /dev/shm"
echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" >> /etc/fstab
mount -o remount,noexec,nodev,nosuid /dev/shm

echo "1.1.10 - ensure separate partition exists for /var"
findmnt /var

echo "1.1.11 - 1.1.14 - ensure separate partition exists for /var/tmp nodev, nosuid, noexec option set"
tmpfs_and_mount /var/tmp

echo '1.1.15 Ensure separate partition exists for /var/log'
findmnt /var/log

echo '1.1.16 Ensure separate partition exists for /var/log/audit'
findmnt /var/log/audit

echo '1.1.17 Ensure separate partition exists for /home'
findmnt /home

echo "1.1.18 Ensure /home partition includes the nodev option"
findmnt /home | grep -Ev '\bnodev\b' 
 
echo "1.1.19 Ensure removable media partitions include noexec option"
#!/usr/bin/bash 
 
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/1/ {print $2}'); do  
   findmnt -n "$rmpo" | grep -Ev "\bnoexec\b" 
done 
echo "1.1.20 Ensure nodev option set on removable media partitions"
#!/usr/bin/bash 
 
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/1/ {print $2}'); do  
   findmnt -n "$rmpo" | grep -Ev "\bnodev\b" 
done 
echo "1.1.21 Ensure nosuid option set on removable media partitions "
#!/usr/bin/bash 
 
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/1/ {print $2}'); do  
   findmnt -n "$rmpo" | grep -Ev "\bnosuid\b" 
done 

echo "1.1.22 Ensure sticky bit is set on all world-writable directories "
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

echo "1.1.23 Disable Automounting"
systemctl --now mask autofs 

echo "1.1.24 Disable USB Storage"
unload_module usb-storage

echo "1.2.1 Ensure GPG keys are configured (Manual)"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

echo "1.2.2 Ensure package manager repositories are configured (Manual)"
yum repolist

echo "1.2.3 Ensure gpgcheck is globally activated (Automated)"
grep ^\s*gpgcheck /etc/yum.conf 
grep -P '^\h*gpgcheck=[^1\n\r]+\b(\h+.*)?$' /etc/yum.conf /etc/yum.repos.d/*.repo 
 

echo "1.3.1 Ensure AIDE is installed (Automated)"
yum install aide  
aide --init 
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

echo "1.3.2 Ensure filesystem integrity is regularly checked (Automated)"
cat /etc/systemd/system/aidecheck.service<<EOF
[Unit] 
Description=Aide Check 
 
[Service] 
Type=simple 
ExecStart=/usr/sbin/aide --check 
 
[Install] 
WantedBy=multi-user.target 
EOF

cat /etc/systemd/system/aidecheck.timer<<EOF
[Unit] 
Description=Aide check every day at 5AM 
 
[Timer] 
OnCalendar=*-*-* 05:00:00 
Unit=aidecheck.service 
 
[Install] 
WantedBy=multi-user.target 
EOF

chown root:root /etc/systemd/system/aidecheck.* 
chmod 0644 /etc/systemd/system/aidecheck.* 
 
systemctl daemon-reload 
 
systemctl enable aidecheck.service 
systemctl --now enable aidecheck.timer

echo "1.4.1 Ensure permissions on bootloader config are configured (Automated)"
chown root:root /boot/grub2/grub.cfg 
test -f /boot/grub2/user.cfg && chown root:root /boot/grub2/user.cfg 
chmod og-rwx /boot/grub2/grub.cfg 
test -f /boot/grub2/user.cfg && chmod og-rwx /boot/grub2/user.cfg 

echo "1.4.2 Ensure authentication required for single user mode (Automated)"
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service 
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service 
 
ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block 
default"","Edit /usr/lib/systemd/system/rescue.service and 
/usr/lib/systemd/system/emergency.service and set ExecStart to use /sbin/sulogin or 
/usr/sbin/sulogin: 
ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block 
default""

echo "1.5.1 Ensure core dumps are restricted (Automated),"
echo "* hard core 0" >> /etc/security/cis.conf
sysctl_entry "fs.suid_dumpable=0"

echo "1.5.2 Ensure XD/NX support is enabled (Automated),"
journalctl | grep 'protection: active' 
 
# kernel: NX (Execute Disable) protection: active 

echo "1.5.3 Ensure address space layout randomization (ASLR) is enabled (Automated)"
sysctl_entry "kernel.randomize_va_space=2"
 
echo "1.5.4 Ensure prelink is not installed (Automated)"
rpm -q prelink

echo "1.6.1.1 Ensure SELinux is installed (Automated)"
rpm -q libselinux 
 
echo "1.6.1.2 Ensure SELinux is not disabled in bootloader configuration (Automated)"
# IF check passes return PASSED 
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT') 
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*') 
if [ -f "$efidir"/grub.cfg ]; then 
   grep "^\s*linux" "$efidir"/grub.cfg | grep -Eq "(selinux=0|enforcing=0)" && \ 
echo "FAILED: \"$()\" exists" || echo "PASSED" 
elif [ -f "$gbdir"/grub.cfg ]; then 
   grep "^\s*linux" "$gbdir"/grub.cfg | grep -Eq "(selinux=0|enforcing=0)" && \ 
echo "FAILED: \"$()\" exists" || echo "PASSED" 
else 
   echo "FAILED" 
fi

echo "1.6.1.3 Ensure SELinux policy is configured (Automated)"
grep SELINUXTYPE= /etc/selinux/config 
sestatus | grep 'Loaded policy' 

echo "1.6.1.4 Ensure the SELinux mode is enforcing or permissive (Automated)"
setenforce 1 
Edit the /etc/selinux/config file to set the SELINUX parameter: 
sed -i -e 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

echo "1.6.1.5 Ensure the SELinux mode is enforcing (Automated)"
Run the following command to verify SELinux's current mode: 
getenforce 

grep -i SELINUX=enforcing /etc/selinux/config 
 
echo "1.6.1.6 Ensure no unconfined services exist (Automated)"
ps -eZ | grep unconfined_service_t

echo "1.6.1.7 Ensure SETroubleshoot is not installed (Automated)"
rpm -q setroubleshoot 
 
echo "1.6.1.8 Ensure the MCS Translation Service (mcstrans) is not installed"
rpm -q mcstrans 
 
echo "1.7.1 Ensure message of the day is configured properly (Automated)"
cat /etc/motd 
grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd

echo "1.7.2 Ensure local login warning banner is configured properly (Automated)"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

echo "1.7.3 Ensure remote login warning banner is configured properly (Automated)"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

echo "1.7.4 Ensure permissions on /etc/motd are configured (Automated)"
stat /etc/motd
stat -L /etc/motd 
 
echo "1.7.5 Ensure permissions on /etc/issue are configured (Automated)"
stat /etc/issue 
 
echo "1.7.6 Ensure permissions on /etc/issue.net are configured (Automated)"
stat /etc/issue.net 
 
echo "1.8 Ensure updates, patches, and additional security software are installed (Manual)"
yum update -y

echo "2.1.1.1 Ensure time synchronization is in use (Manual)"
rpm -q chrony ntp 
 
echo "2.1.1.2 Ensure chrony is configured (Automated)"
grep -E "^(server|pool)" /etc/chrony.conf 
sed -i -e "s/OPTIONS=\".*\"/OPTIONS=\"-u chrony\"/" /etc/sysconfig/chronyd
systemctl daemon-reload 
 
echo "2.1.1.3 Ensure ntp is configured (Automated)"
echo "Skipped chrony is used"

echo "2.1.2 Ensure X11 Server components are not installed (Automated)"
rpm -qa xorg-x11-server*

echo "2.1.3 Ensure Avahi Server is not installed (Automated)"
rpm -q avahi-autoipd avahi
 
echo "2.1.4 Ensure CUPS is not installed (Automated)"
rpm -q cups
 
echo "2.1.5 Ensure DHCP Server is not installed (Automated)"
rpm -q dhcp
 
echo "2.1.6 Ensure LDAP server is not installed (Automated)"
rpm -q openldap-servers

echo "2.1.7 Ensure DNS Server is not installed (Automated)"
rpm -q bind
 
echo "2.1.8 Ensure FTP Server is not installed (Automated)"
rpm -q vsftpd
 
echo "2.1.9 Ensure HTTP server is not installed (Automated)"
rpm -q httpd 
 
echo "2.1.10 Ensure IMAP and POP3 server is not installed (Automated)"
rpm -q dovecot
 
echo "2.1.11 Ensure Samba is not installed (Automated)"
rpm -q samba
 
echo "2.1.12 Ensure HTTP Proxy Server is not installed (Automated),"
rpm -q squid
 
echo "2.1.13 Ensure net-snmp is not installed (Automated)"
rpm -q net-snmp 
 
echo "2.1.14 Ensure NIS server is not installed (Automated)"
rpm -q ypserv 
 
echo "2.1.15 Ensure telnet-server is not installed (Automated)"
rpm -q telnet-server 
 
echo "2.1.16 Ensure mail transfer agent is configured for local-only mode (Automated)"
ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'
 
echo "2.1.17 Ensure nfs-utils is not installed or the nfs-server service is masked (Automated)"
yum remove nfs-utils 

echo "2.1.18 Ensure rpcbind is not installed or the rpcbind services are masked (Automated)"
systemctl --now mask rpcbind 
systemctl --now mask rpcbind.socket 

echo "2.1.19 Ensure rsync is not installed or the rsyncd service is masked (Automated)"
yum remove rsync 

echo "2.2.1 Ensure NIS Client is not installed (Automated)"
rpm -q ypbind 
 
2.2.2 Ensure rsh client is not installed (Automated)"
rpm -q rsh 
 
echo "2.2.3 Ensure talk client is not installed (Automated)"
rpm -q talk
 
echo "2.2.4 Ensure telnet client is not installed (Automated)"
rpm -q telnet
 
echo "2.2.5 Ensure LDAP client is not installed (Automated)"
rpm -q openldap-clients 
 
echo "2.3 Ensure nonessential services are removed or masked (Manual)"
lsof -i -P -n | grep -v "(ESTABLISHED)" 

echo "3.1.1 Disable IPv6 (Manual)"
sysctl_entry "net.ipv6.conf.all.disable_ipv6=1"
sysctl_entry "net.ipv6.conf.default.disable_ipv6=1"
sysctl -w net.ipv6.route.flush=1

echo "3.1.2 Ensure wireless interfaces are disabled (Automated)"
if command -v nmcli >/dev/null 2>&1 ; then
   if nmcli radio all | grep -Eq '\s*\S+\s+disabled\s+\S+\s+disabled\b'; then
      echo "Wireless is not enabled"
   else
      nmcli radio all
   fi
elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
   t=0
   mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless |
xargs -0 dirname); do basename "$(readlink -f
"$driverdir"/device/driver/module)";done | sort -u)
   for dm in $mname; do
      if grep -Eq "^\s*install\s+$dm\s+/bin/(true|false)"
/etc/modprobe.d/*.conf; then
         /bin/true
      else
         echo "$dm is not disabled"
         t=1
      fi
   done
   [ "$t" -eq 0 ] && echo "Wireless is not enabled"
else
   echo "Wireless is not enabled"
fi

echo "3.2.1 Ensure IP forwarding is disabled (Automated),"
sysctl net.ipv4.ip_forward 
 
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 
 
check_ipv6

echo "3.2.2 Ensure packet redirect sending is disabled (Automated)"
sysctl_entry "net.ipv4.conf.all.send_redirects=0"
sysctl_entry "net.ipv4.conf.default.send_redirects=0"
sysctl -w net.ipv4.route.flush=1

echo "3.3.1 Ensure source routed packets are not accepted (Automated)"Run the following commands and verify output matches: 
sysctl net.ipv4.conf.all.accept_source_route 
sysctl net.ipv4.conf.default.accept_source_route 
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 

grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf 

check_ipv6

echo "3.3.2 Ensure ICMP redirects are not accepted (Automated)"

sysctl_entry "net.ipv4.conf.all.accept_redirects=0"
sysctl_entry "net.ipv4.conf.default.accept_redirects=0"
sysctl -w net.ipv4.route.flush=1"

echo "3.3.3 Ensure secure ICMP redirects are not accepted (Automated),"
sysctl_entry "net.ipv4.conf.all.secure_redirects=0"
sysctl_entry "net.ipv4.conf.default.secure_redirects=0"
sysctl -w net.ipv4.route.flush=1

echo "3.3.4 Ensure suspicious packets are logged (Automated)


sysctl_entry "net.ipv4.conf.all.log_martians=1"
sysctl_entry "net.ipv4.conf.default.log_martians=1"
sysctl -w net.ipv4.route.flush=1

echo "3.3.5 Ensure broadcast ICMP requests are ignored (Automated)"
sysctl_entry "net.ipv4.icmp_echo_ignore_broadcasts=1"
sysctl -w net.ipv4.route.flush=1

echo "3.3.6 Ensure bogus ICMP responses are ignored (Automated)"
sysctl_entry "net.ipv4.icmp_ignore_bogus_error_responses=1"
sysctl -w net.ipv4.route.flush=1

echo "3.3.7 Ensure Reverse Path Filtering is enabled (Automated)"Run the following commands and verify output matches: 
sysctl_entry "net.ipv4.conf.all.rp_filter=1"
sysctl_entry "net.ipv4.conf.default.rp_filter=1"
sysctl -w net.ipv4.route.flush=1

echo "3.3.8 Ensure TCP SYN Cookies is enabled (Automated),"Run the following commands and verify output matches: 
sysctl_entry "net.ipv4.tcp_syncookies=1"
sysctl -w net.ipv4.route.flush=1

echo "3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)"
check_ipv6

echo "3.4.1 Ensure DCCP is disabled (Automated)"
unload_module dccp
 
echo "3.4.2 Ensure SCTP is disabled (Automated)"
unload_module sctp 

echo "3.5.1.1 Ensure firewalld is installed (Automated)"
yum install firewalld iptables

echo "3.5.1.2 Ensure iptables-services not installed with firewalld (Automated)"
rpm -q iptables-services
 
echo "3.5.1.3 Ensure nftables either not installed or masked with firewalld (Automated)"
rpm -q nftables 

echo "3.5.1.4 Ensure firewalld service enabled and running (Automated)"
systemctl unmask firewalld 
systemctl --now enable firewalld

echo "3.5.1.5 Ensure firewalld default zone is set (Automated)"
firewall-cmd --get-default-zone

echo "3.5.1.6 Ensure network interfaces are assigned to appropriate zone (Manual)"
firewall-cmd --zone=public --change-interface=eth0 # CHECK

echo "3.5.1.7 Ensure firewalld drops unnecessary services and ports (Manual)"
firewall-cmd --get-active-zones | awk '!/:/ {print $1}' | while read ZN; do firewall-cmd --list-all --zone=$ZN; done

echo "3.5.2.1 Ensure nftables is installed (Automated)"
echo "pass-over for firewalld"
 
echo "3.5.2.2 Ensure firewalld is either not installed or masked with nftables (Automated)"
echo "pass-over for firewalld"

echo "3.5.2.3 Ensure iptables-services not installed with nftables (Automated)"
echo "pass-over for firewalld"
 
echo "3.5.2.4 Ensure iptables are flushed with nftables (Manual),"
echo "pass-over for firewalld"

echo "3.5.2.5 Ensure an nftables table exists (Automated)"
echo "pass-over for firewalld"

echo "3.5.2.6 Ensure nftables base chains exist (Automated)"
echo "pass-over for firewalld"

echo "3.5.2.7 Ensure nftables loopback traffic is configured (Automated)"
echo "pass-over for firewalld"

echo "3.5.2.8 Ensure nftables outbound and established connections are configured (Manual)"
echo "pass-over for firewalld"

echo "3.5.2.9 Ensure nftables default deny firewall policy (Automated)"
echo "pass-over for firewalld"

echo "3.5.2.10 Ensure nftables service is enabled (Automated)"
echo "pass-over for firewalld"

echo "3.5.2.11 Ensure nftables rules are permanent (Automated)"
echo "pass-over for firewalld"

echo "3.5.3.1.1 Ensure iptables packages are installed (Automated),"
echo "skip for firewalld"

echo "3.5.3.1.2 Ensure nftables is not installed with iptables (Automated)"
echo "skip for firewalld"

echo "3.5.3.1.3 Ensure firewalld is either not installed or masked with iptables"
echo "skip for firewalld"

echo "3.5.3.2.1 Ensure iptables loopback traffic is configured (Automated)"
echo "skip for firewalld"

echo "3.5.3.2.3 Ensure iptables rules exist for all open ports (Automated),"
echo "skip for firewalld"

echo "3.5.3.2.4 Ensure iptables default deny firewall policy (Automated),"
echo "skip for firewalld"

echo "3.5.3.2.5 Ensure iptables rules are saved (Automated),"
echo "skip for firewalld"

echo "3.5.3.2.6 Ensure iptables is enabled and running (Automated),"
echo "skip for firewalld"

echo "3.5.3.3.1 Ensure ip6tables loopback traffic is configured (Automated),"
check_ipv6

echo "3.5.3.3.2 Ensure ip6tables outbound and established connections are configured (Manual)"
check_ipv6

echo "3.5.3.3.3 Ensure ip6tables firewall rules exist for all open ports (Automated)"
check_ipv6

echo "3.5.3.3.4 Ensure ip6tables default deny firewall policy (Automated)"
check_ipv6

echo "3.5.3.3.5 Ensure ip6tables rules are saved (Automated)"
check_ipv6

echo "3.5.3.3.6 Ensure ip6tables is enabled and running (Automated)"
check_ipv6

echo "4.1.1.1 Ensure auditd is installed (Automated)"
rpm -q audit audit-libs 

echo "4.1.1.2 Ensure auditd service is enabled and running (Automated)"
systemctl is-enabled auditd 
 
echo "4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)"
# CHECK, this script doesn't sound right
# IF check passes return PASSED 
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT') 
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*') 
if [ -f "$efidir"/grub.cfg ]; then 
   grep "^\s*linux" "$efidir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED" 
elif [ -f "$gbdir"/grub.cfg ]; then 
   grep "^\s*linux" "$gbdir"/grub.cfg | grep -Evq "audit=1\b" && echo "FAILED" || echo "PASSED" 
else 
   echo "FAILED" 
fi

echo "4.1.2.1 Ensure audit log storage size is configured (Automated)"
grep max_log_file /etc/audit/auditd.conf 
 
echo "4.1.2.2 Ensure audit logs are not automatically deleted (Automated),"
sed -i -e "s/max_log_file_action = .*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf

echo "4.1.2.3 Ensure system is disabled when audit logs are full (Automated)"
sed -i -e "s/space_left_action = .*/space_left_action = email/" /etc/audit/auditd.conf
sed -i -e "s/action_mail_acct = .*/action_mail_acct = root/" /etc/audit/auditd.conf
sed -i -e "s/admin_space_left_action = .*/admin_space_left_action = halt/" /etc/audit/auditd.conf

echo "4.1.2.4 Ensure audit_backlog_limit is sufficient (Automated)"
echo "GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\"" >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

echo "4.1.3 Ensure events that modify date and time information are collected (Automated)"

cat > /etc/audit/rules.d/50-time_change.rules<<EOF
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change 
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

echo "4.1.4 Ensure events that modify user/group information are collected (Automated)"
cat > /etc/audit/rules.d/50-identity.rules <<EOF
-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity 
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity
EOF

echo "4.1.5 Ensure events that modify the system's network environment are collected (Automated)"
cat > /etc/audit/rules.d/50-system_local.rules <<EOF
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale 
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale
EOF

echo "4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)"
cat > /etc/audit/rules.d/50-MAC_policy.rules <<EOF
-w /etc/selinux/ -p wa -k MAC-policy 
-w /usr/share/selinux/ -p wa -k MAC-policy
EOF

echo "4.1.7 Ensure login and logout events are collected (Automated)"
cat > /etc/audit/rules.d/50-logins.rules <<EOF
-w /var/log/lastlog -p wa -k logins 
-w /var/run/faillock/ -p wa -k logins
EOF

echo "4.1.8 Ensure session initiation information is collected (Automated)"
cat > /etc/audit/rules.d/50-session.rules <<EOF
-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k logins 
-w /var/log/btmp -p wa -k logins
EOF

echo "4.1.9 Ensure discretionary access control permission modification events are collected (Automated)"
cat > /etc/audit/rules.d/50-perm_mod.rules <<EOF
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF

echo "4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Automated)"
cat > /etc/audit/rules.d/50-access.rules <<EOF
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
EOF

echo "4.1.11 Ensure use of privileged commands is collected (Automated)"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/50-privileged.rules
#TODO Other partitions?

echo "4.1.12 Ensure successful file system mounts are collected (Automated)"

cat > /etc/audit/rules.d/50-mounts.rules <<EOF
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
EOF

echo "4.1.13 Ensure file deletion events by users are collected (Automated)"
cat > /etc/audit/rules.d/50-deletion.rules <<EOF
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete 
EOF

echo "4.1.14 Ensure changes to system administration scope (sudoers) is collected (Automated)"
cat > /etc/audit/rules.d/50-scope.rules <<EOF
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

echo "4.1.15 Ensure system administrator command executions (sudo) are collected (Automated)"
cat > /etc/audit/rules.d/50-modules.rules <<EOF
-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules 
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

echo "4.1.17 Ensure the audit configuration is immutable (Automated)"
cat > /etc/audit/rules.d/99-finalize.rules <<EOF
-e 2
EOF

echo "4.2.1.1 Ensure rsyslog is installed (Automated),"
rpm -q rsyslog 
 
echo "4.2.1.2 Ensure rsyslog Service is enabled and running (Automated),"
systemctl is-enabled rsyslog 
 
echo "4.2.1.3 Ensure rsyslog default file permissions configured (Automated)"
echo "\$FileCreateMode 0640" >> /etc/rsyslog.d/cis.conf

echo "4.2.1.4 Ensure logging is configured (Manual),"
ls -l /var/log/,
systemctl restart rsyslog 

echo "4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Automated)"
grep -E '^\s*([^#]+\s+)?action\(([^#]+\s+)?\btarget=\"?[^#"]+\"?\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
#CHECK

echo "4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Manual)"
grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 

echo "4.2.2.1 Ensure journald is configured to send logs to rsyslog (Automated)"
echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf

echo "4.2.2.2 Ensure journald is configured to compress large log files (Automated)"
echo "Compress=yes" >> /etc/systemd/journald.conf

echo "4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Automated)"
echo "Storage=persistent" >> /etc/systemd/journald.conf

echo "4.2.3 Ensure logrotate is configured (Manual)"
echo "Review /etc/logrotate.conf and /etc/logrotate.d/* and verify logs are rotated according to site policy."

echo "4.2.4 Ensure permissions on all logfiles are configured (Manual)"
find /var/log -type f -perm /g+wx,o+rwx  -exec ls -l {} \; 
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + 

5.1.1 Ensure cron daemon is enabled and running (Automated),"If cron is installed: 
Run the following commands to verify cron is enabled and running: 
# systemctl is-enabled crond 
 
enabled 
# systemctl status crond | grep 'Active: active (running) ' 
 
Active: active (running) since <Day Date Time>","Run the following command to enable and start cron: 
# systemctl --now enable crond 
OR 
Run the following command to remove cron: 
# yum remove cronie"
5.1.2 Ensure permissions on /etc/crontab are configured (Automated),"If cron is installed: 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other: 
# stat /etc/crontab 
 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on /etc/crontab: 
# chown root:root /etc/crontab 
 
# chmod u-x,og-rwx /etc/crontab 
OR 
Run the following command to remove cron: 
# yum remove cronie"
"5.1.3 Ensure permissions on /etc/cron.hourly are configured 
(Automated)","If cron is installed: 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other : 
# stat /etc/cron.hourly/ 
 
Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on the /etc/cron.hourly/ 
directory: 
# chown root:root /etc/cron.hourly/ 
 
# chmod og-rwx /etc/cron.hourly/ 
OR 
Run the following command to remove cron 
# yum remove cronie"
5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated),"If cron is installed: 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other : 
# stat /etc/cron.daily/ 
 
Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on /etc/cron.daily 
directory: 
# chown root:root /etc/cron.daily 
 
# chmod og-rwx /etc/cron.daily 
OR 
Run the following command to remove cron: 
# yum remove cronie"
"5.1.5 Ensure permissions on /etc/cron.weekly are configured 
(Automated)","If cron is installed 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other : 
# stat /etc/cron.weekly 
 
Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on /etc/cron.weekly/ 
directory: 
# chown root:root /etc/cron.weekly/ 
 
# chmod og-rwx /etc/cron.weekly/ 
OR 
Run the following command to remove cron: 
# yum remove cronie"
"5.1.6 Ensure permissions on /etc/cron.monthly are configured 
(Automated)","If cron is installed: 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other: 
# stat /etc/cron.monthly/ 
 
Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on /etc/cron.monthly 
directory: 
# chown root:root /etc/cron.monthly 
 
# chmod og-rwx /etc/cron.monthly 
OR 
Run the following command to remove cron: 
# yum remove cronie"
5.1.7 Ensure permissions on /etc/cron.d are configured (Automated),"If cron is installed: 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other : 
# stat /etc/cron.d 
 
Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on /etc/cron.d directory: 
# chown root:root /etc/cron.d 
 
# chmod og-rwx /etc/cron.d 
OR 
Run the following command to remove cron: 
# yum remove cronie"
5.1.8 Ensure cron is restricted to authorized users (Automated),"If cron is installed: 
Run the following command and verify /etc/cron.deny does not exist: 
# stat /etc/cron.deny 
 
stat: cannot stat `/etc/cron.deny': No such file or directory 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other for /etc/cron.allow: 
# stat /etc/cron.allow 
 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following command to remove /etc/cron.deny: 
# rm /etc/cron.deny 
Run the following command to create /etc/cron.allow 
# touch /etc/cron.allow 
Run the following commands to set the owner and permissions on /etc/cron.allow: 
# chown root:root /etc/cron.allow 
 
# chmod u-x,og-rwx /etc/cron.allow 
OR 
Run the following command to remove cron 
# yum remove cronie"
5.1.9 Ensure at is restricted to authorized users (Automated),"If at is installed: 
Run the following command and verify /etc/at.deny does not exist: 
# stat /etc/at.deny 
 
stat: cannot stat `/etc/at.deny': No such file or directory 
Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other for /etc/at.allow: 
# stat /etc/at.allow 
 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following command to remove /etc/at.deny: 
# rm /etc/at.deny 
Run the following command to create /etc/at.allow 
# touch /etc/at.allow 
Run the following commands to set the owner and permissions on /etc/at.allow: 
# chown root:root /etc/at.allow 
 
# chmod u-x,og-rwx /etc/at.allow 
OR 
Run the following command to remove at: 
# yum remove at"
5.2.1 Ensure sudo is installed (Automated),"Verify that sudo in installed. 
Run the following command: 
# rpm -q sudo 
 
sudo-<VERSION>","Run the following command to install sudo. 
# yum install sudo 
References: 
1. SUDO(8)"
5.2.2 Ensure sudo commands use pty (Automated),"Verify that sudo can only run other commands from a pseudo-pty 
Run the following command: 
# grep -Ei '^\s*Defaults\s+([^#]\S+,\s*)?use_pty\b' /etc/sudoers 
/etc/sudoers.d/* 
 
Defaults use_pty","Edit the file /etc/sudoers or a file in /etc/sudoers.d/ with visudo or visudo -f <PATH 
TO FILE> and add the following line: 
Defaults use_pty 
References: 
1. SUDO(8)"
5.2.3 Ensure sudo log file exists (Automated),"Verify that sudo has a custom log file configured 
Run the following command: 
# grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(")?[^#;]+(")?' 
/etc/sudoers /etc/sudoers.d/* 
 
Defaults logfile="/var/log/sudo.log"","edit the file /etc/sudoers or a file in /etc/sudoers.d/ with visudo or visudo -f <PATH 
TO FILE> and add the following line: 
Defaults  logfile="<PATH TO CUSTOM LOG FILE>" 
Example: 
Defaults  logfile="/var/log/sudo.log""
"5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured 
(Automated)","Run the following command and verify Uid and Gid are both 0/root and Access does not 
grant permissions to group or other: 
# stat /etc/ssh/sshd_config 
 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set ownership and permissions on /etc/ssh/sshd_config: 
# chown root:root /etc/ssh/sshd_config 
 
# chmod og-rwx /etc/ssh/sshd_config 
Default Value: 
Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)"
"5.3.2 Ensure permissions on SSH private host key files are configured 
(Automated)","Run the following command and verify Uid is 0/root and Gid is 0/root and permissions are 
0600 or more restrictive: 
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \; 
Example Output: 
  File: '/etc/ssh/ssh_host_rsa_key' 
  Size: 1675            Blocks: 8          IO Block: 4096   regular file 
Device: 801h/2049d      Inode: 794321      Links: 1 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2021-03-01 06:25:08.633246149 -0800 
Modify: 2021-01-29 06:42:16.001324236 -0800 
Change: 2021-01-29 06:42:16.001324236 -0800 
 Birth: - 
  File: '/etc/ssh/ssh_host_ecdsa_key' 
  Size: 227             Blocks: 8          IO Block: 4096   regular file 
Device: 801h/2049d      Inode: 794325      Links: 1 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2021-03-01 06:25:08.633246149 -0800 
Modify: 2021-01-29 06:42:16.173327263 -0800 
Change: 2021-01-29 06:42:16.173327263 -0800 
 Birth: - 
  File: '/etc/ssh/ssh_host_ed25519_key' 
  Size: 399             Blocks: 8          IO Block: 4096   regular file 
Device: 801h/2049d      Inode: 794327      Links: 1 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2021-03-01 06:25:08.633246149 -0800 
Modify: 2021-01-29 06:42:16.185327474 -0800 
Change: 2021-01-29 06:42:16.185327474 -0800 
 Birth: - 
  File: '/etc/ssh/ssh_host_dsa_key' 
  Size: 672             Blocks: 8          IO Block: 4096   regular file 
Device: 801h/2049d      Inode: 794323      Links: 1 
Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2021-03-01 06:25:08.645246255 -0800 
Modify: 2021-01-29 06:42:16.161327052 -0800 
Change: 2021-01-29 06:42:16.161327052 -0800 
 Birth: -","Run the following commands to set permissions, ownership, and group on the private SSH 
host key files: 
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} 
\; 
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx 
{} \;"
"5.3.3 Ensure permissions on SSH public host key files are configured 
(Automated)","Run the following command and verify Access does not grant write or execute permissions 
to group or other for all returned files: 
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \; 
Example Output: 
  File: ‘/etc/ssh/ssh_host_rsa_key.pub’ 
  Size: 382             Blocks: 8          IO Block: 4096   regular file 
Device: ca01h/51713d    Inode: 8631758     Links: 1 
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2018-10-22 18:24:56.861750616 +0000 
Modify: 2018-10-22 18:24:56.861750616 +0000 
Change: 2018-10-22 18:24:56.881750616 +0000 
 Birth: - 
  File: ‘/etc/ssh/ssh_host_ecdsa_key.pub’ 
  Size: 162             Blocks: 8          IO Block: 4096   regular file 
Device: ca01h/51713d    Inode: 8631761     Links: 1 
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2018-10-22 18:24:56.897750616 +0000 
Modify: 2018-10-22 18:24:56.897750616 +0000 
Change: 2018-10-22 18:24:56.917750616 +0000 
 Birth: - 
  File: ‘/etc/ssh/ssh_host_ed25519_key.pub’ 
  Size: 82              Blocks: 8          IO Block: 4096   regular file 
Device: ca01h/51713d    Inode: 8631763     Links: 1 
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root) 
Access: 2018-10-22 18:24:56.945750616 +0000 
Modify: 2018-10-22 18:24:56.945750616 +0000 
Change: 2018-10-22 18:24:56.961750616 +0000 
 Birth: -","Run the following commands to set permissions and ownership on the SSH host public key 
files 
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-
wx {} \; 
# find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown 
root:root {} \; 
Default Value: 
Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)"
5.3.4 Ensure SSH access is limited (Automated),"Run the following commands and verify the output: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -Pi 
'^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' 
 
# grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' 
/etc/ssh/sshd_config 
Verify that the output of both commands matches at least one of the following lines: 
allowusers <userlist> 
allowgroups <grouplist> 
denyusers <userlist> 
denygroups <grouplist>","Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows: 
AllowUsers <userlist> 
OR 
AllowGroups <grouplist> 
OR 
DenyUsers <userlist> 
OR 
DenyGroups <grouplist> 
Default Value: 
None 
References: 
1. SSHD_CONFIG(5)"
5.3.5 Ensure SSH LogLevel is appropriate (Automated),"Run the following command and verify that output matches loglevel VERBOSE or loglevel 
INFO: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep loglevel 
 
loglevel VERBOSE or loglevel INFO 
Run the following command and verify the output matches: 
# grep -i 'loglevel' /etc/ssh/sshd_config | grep -Evi '(VERBOSE|INFO)' 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
LogLevel VERBOSE 
OR 
LogLevel INFO 
Default Value: 
LogLevel INFO 
References: 
1. https://www.ssh.com/ssh/sshd_config/"
5.3.6 Ensure SSH X11 forwarding is disabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -i x11forwarding 
 
x11forwarding no 
Run the following command and verify that the output matches: 
# grep -Ei '^\s*x11forwarding\s+yes' /etc/ssh/sshd_config 
 
Nothing is returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
X11Forwarding no 
Default Value: 
X11Forwarding yes"
5.3.7 Ensure SSH MaxAuthTries is set to 4 or less (Automated),"Run the following command and verify that output MaxAuthTries is 4 or less: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep maxauthtries 
 
maxauthtries 4 
Run the following command and verify that the output: 
# grep -Ei '^\s*maxauthtries\s+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config 
 
Nothing is returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
MaxAuthTries 4 
Default Value: 
MaxAuthTries 6 
References: 
1. SSHD_CONFIG(5)"
5.3.8 Ensure SSH IgnoreRhosts is enabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep ignorerhosts 
 
ignorerhosts yes 
Run the following command and verify the output: 
# grep -Ei '^\s*ignorerhosts\s+no\b' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
IgnoreRhosts yes 
Default Value: 
IgnoreRhosts yes 
References: 
1. SSHD_CONFIG(5)"
5.3.9 Ensure SSH HostbasedAuthentication is disabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep hostbasedauthentication 
 
hostbasedauthentication no 
Run the following command and verify the output matches: 
# grep -Ei '^\s*HostbasedAuthentication\s+yes' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
HostbasedAuthentication no 
Default Value: 
HostbasedAuthentication no 
References: 
1. SSHD_CONFIG(5)"
5.3.10 Ensure SSH root login is disabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep permitrootlogin 
 
permitrootlogin no 
Run the following command and verify the output: 
# grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
PermitRootLogin no 
Default Value: 
PermitRootLogin without-password 
References: 
1. SSHD_CONFIG(5)"
5.3.11 Ensure SSH PermitEmptyPasswords is disabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep permitemptypasswords 
 
permitemptypasswords no 
Run the following command and verify the output: 
# grep -Ei '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
PermitEmptyPasswords no 
Default Value: 
PermitEmptyPasswords no 
References: 
1. SSHD_CONFIG(5)"
5.3.12 Ensure SSH PermitUserEnvironment is disabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep permituserenvironment 
 
permituserenvironment no 
Run the following command and verify the output: 
# grep -Ei '^\s*PermitUserEnvironment\s+yes' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
PermitUserEnvironment no 
Default Value: 
PermitUserEnvironment no 
References: 
1. SSHD_CONFIG(5)"
5.3.13 Ensure only strong Ciphers are used (Automated),"Run the following command and verify the output: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -Ei '^\s*ciphers\s+([^#]+,)?(3des-
cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-
cbc|cast128-cbc|rijndael-cbc@lysator.liu.se)\b' 
 
Nothing should be returned 
Run the following command and verify the output: 
grep -Ei '^\s*ciphers\s+([^#]+,)?(3des-cbc|aes128-cbc|aes192-cbc|aes256-
cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-
cbc@lysator.liu.se)\b' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file add/modify the Ciphers line to contain a comma 
separated list of the site approved ciphers 
Example: 
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-
gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr 
Default Value: 
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-
gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-
cbc,blowfish-cbc,cast128-cbc,3des-cbc 
References: 
1. https://nvd.nist.gov/vuln/detail/CVE-2016-2183 
2. https://nvd.nist.gov/vuln/detail/CVE-2015-2808 
3. https://www.kb.cert.org/vuls/id/565052 
4. https://www.openssh.com/txt/cbc.adv 
5. https://nvd.nist.gov/vuln/detail/CVE-2008-5161 
6. https://nvd.nist.gov/vuln/detail/CVE-2013-4548 
7. https://www.kb.cert.org/vuls/id/565052 
8. https://www.openssh.com/txt/cbc.adv 
9. SSHD_CONFIG(5)"
5.3.14 Ensure only strong MAC algorithms are used (Automated),"Run the following command and verify the output: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -Ei '^\s*macs\s+([^#]+,)?(hmac-
md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-
64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-
ripemd160-etm@openssh\.com|hmac-sha1-etm@openssh\.com|hmac-sha1-96-
etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b' 
 
Nothing should be returned 
Run the following command and verify the output: 
# grep -Ei '^\s*macs\s+([^#]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-
sha1|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-
etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-
etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-
128-etm@openssh\.com)\b' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma 
separated list of the site approved MACs 
Example: 
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-
512,hmac-sha2-256 
Default Value: 
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-
etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-
etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-
256,hmac-sha2-512,hmac-sha1,hmac-sha1-etm@openssh.com 
References: 
1. More information on SSH downgrade attacks can be found here: 
http://www.mitls.org/pages/attacks/SLOTH 
2. SSHD_CONFIG(5)"
"5.3.15 Ensure only strong Key Exchange algorithms are used 
(Automated)","Run the following command and verify the output: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -Ei 
'^\s*kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-hellman-
group14-sha1|diffie-hellman-group-exchange-sha1)\b' 
 
Nothing should be returned 
Run the following command and verify the output: 
# grep -Ei '^\s*kexalgorithms\s+([^#]+,)?(diffie-hellman-group1-sha1|diffie-
hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b' 
/etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file add/modify the KexAlgorithms line to contain a comma 
separated list of the site approved key exchange algorithms 
Example: 
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-
nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-
sha256 
Default Value: 
kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-
nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-
sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 
References: 
1. SSHD_CONFIG(5) 
Additional Information: 
Weak Key Exchange Algorithms: 
diffie-hellman-group1-sha1 
diffie-hellman-group14-sha1 
diffie-hellman-group-exchange-sha1 
Key Exchange algorithms supported by OpenSSH 7.4p1: 
curve25519-sha256 
curve25519-sha256@libssh.org 
diffie-hellman-group1-sha1 
diffie-hellman-group14-sha1 
diffie-hellman-group-exchange-sha1 
diffie-hellman-group-exchange-sha256 
ecdh-sha2-nistp256 
ecdh-sha2-nistp384 
ecdh-sha2-nistp521 
Key Exchange algorithms currently FIPS 140-2 approved: 
ecdh-sha2-nistp256,ecdh-sha2-nistp384 
ecdh-sha2-nistp521 
diffie-hellman-group-exchange-sha256 
diffie-hellman-group16-sha512 
diffie-hellman-group18-sha512 
diffie-hellman-group14-sha256"
5.3.16 Ensure SSH Idle Timeout Interval is configured (Automated),"Run the following commands and verify ClientAliveInterval is between 1 and 900: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep clientaliveinterval 
 
clientaliveinterval 900 
Run the following command and verify ClientAliveCountMax is 0: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep clientalivecountmax 
 
clientalivecountmax 3 
Run the following commands and verify the output: 
# grep -Ei '^\s*ClientAliveInterval\s+(0|9[0-9][1-9]|[1-9][0-9][0-9][0-
9]+|1[6-9]m|[2-9][0-9]m|[1-9][0-9][0-9]+m)\b' /etc/ssh/sshd_config 
 
Nothing should be returned 
 
# grep -Ei '^\s*ClientAliveCountMax\s+([1-9]|[1-9][0-9]+)\b' 
/etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameters according to site policy. This 
should include ClientAliveInterval between 1 and 900 and ClientAliveCountMax of 0: 
ClientAliveInterval 900 
 
ClientAliveCountMax 0 
Default Value: 
ClientAliveInterval 0 
ClientAliveCountMax 3 
References: 
1. https://man.openbsd.org/sshd_config"
"5.3.17 Ensure SSH LoginGraceTime is set to one minute or less 
(Automated)","Run the following command and verify that output LoginGraceTime is between 1 and 60 
seconds or 1m: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep logingracetime 
 
logingracetime 60 
Run the following command and verify the output: 
# grep -Ei '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-
9]+|[^1]m)' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
LoginGraceTime 60"
5.3.18 Ensure SSH warning banner is configured (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep banner 
 
banner /etc/issue.net","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
Banner /etc/issue.net 
References: 
1. SSHD_CONFIG(5)"
5.3.19 Ensure SSH PAM is enabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -i usepam 
 
usepam yes 
Run the following command and verify the output: 
# grep -Ei '^\s*UsePAM\s+no' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
UsePAM yes"
5.3.20 Ensure SSH AllowTcpForwarding is disabled (Automated),"Run the following command and verify that output matches: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding 
 
allowtcpforwarding no 
Run the following command and verify the output: 
# grep -Ei '^\s*AllowTcpForwarding\s+yes' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
AllowTcpForwarding no 
Default Value: 
AllowTcpForwarding yes 
References: 
1. https://www.ssh.com/ssh/tunneling/example 
2. SSHD_CONFIG(5)"
5.3.21 Ensure SSH MaxStartups is configured (Automated),"Run the following command and verify that output MaxStartups is 10:30:60 or more 
restrictive: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -i maxstartups 
 
maxstartups 10:30:60 
Run the following command and verify the output: 
# grep -Ei '^\s*maxstartups\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-
9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-
9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
maxstartups 10:30:60 
Default Value: 
MaxStartups 10:30:100"
5.3.22 Ensure SSH MaxSessions is limited (Automated),"Run the following command and verify that output MaxSessions is 10 or less: 
# sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) 
/etc/hosts | awk '{print $1}')" | grep -i maxsessions 
 
maxsessions 10 
Run the following command and verify the output: 
grep -Ei '^\s*MaxSessions\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' 
/etc/ssh/sshd_config 
 
Nothing should be returned","Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
MaxSessions 10 
Default Value: 
MaxSessions 10 
References: 
1. SSHD_CONFIG(5)"
"5.4.1 Ensure password creation requirements are configured 
(Automated)","Verify password creation requirements conform to organization policy. 
Run the following command to verify the minimum password length is 14 or more 
characters. 
# grep '^\s*minlen\s*' /etc/security/pwquality.conf 
 
minlen = 14 
Run one of the following commands to verify the required password complexity: 
# grep '^\s*minclass\s*' /etc/security/pwquality.conf 
 
minclass = 4 
OR 
# grep -E '^\s*[duol]credit\s*' /etc/security/pwquality.conf 
 
dcredit = -1 
ucredit = -1 
lcredit = -1 
ocredit = -1 
Run the following commands to verify the files: /etc/pam.d/password-auth and 
/etc/pam.d/system-auth include try_first_pass and retry=3 on the password 
requisite pam_pwquality.so line. 
# grep -P 
'^\s*password\s+(?:requisite|required)\s+pam_pwquality\.so\s+(?:\S+\s+)*(?!\2
)(retry=[1-3]|try_first_pass)\s+(?:\S+\s+)*(?!\1)(retry=[1-
3]|try_first_pass)\s*(?:\s+\S+\s*)*(?:\s+#.*)?$' /etc/pam.d/password-auth 
 
password    requisite     pam_pwquality.so try_first_pass retry=3 
# grep -P 
'^\s*password\s+(?:requisite|required)\s+pam_pwquality\.so\s+(?:\S+\s+)*(?!\2
)(retry=[1-3]|try_first_pass)\s+(?:\S+\s+)*(?!\1)(retry=[1-
3]|try_first_pass)\s*(?:\s+\S+\s*)*(?:\s+#.*)?$' /etc/pam.d/system-auth 
 
password    requisite     pam_pwquality.so try_first_pass retry=3","Edit the file /etc/security/pwquality.conf and add or modify the following line for 
password length to conform to site policy 
minlen = 14 
Edit the file /etc/security/pwquality.conf and add or modify the following line for 
password complexity to conform to site policy 
minclass = 4 
OR 
dcredit = -1 
ucredit = -1 
ocredit = -1 
lcredit = -1 
Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the 
appropriate options for pam_pwquality.so and to conform to site policy: 
password requisite pam_pwquality.so try_first_pass retry=3"
"5.4.2 Ensure lockout for failed password attempts is configured 
(Automated)","Verify password lockouts are configured. Ensure that the deny=_n_ follows local site policy. 
This should not exceed deny=5. 
If pam_failock.so is used: 
Run the following commands: 
# grep -E '^\s*auth\s+\S+\s+pam_(faillock|unix)\.so' /etc/pam.d/system-auth 
/etc/pam.d/password-auth 
Verify the output includes the following lines: 
/etc/pam.d/system-auth:auth        required      pam_faillock.so preauth 
silent audit deny=5 unlock_time=900 
/etc/pam.d/system-auth:auth        sufficient    pam_unix.so nullok 
try_first_pass 
/etc/pam.d/system-auth:auth        [default=die] pam_faillock.so authfail 
audit deny=5 unlock_time=900 
/etc/pam.d/password-auth:auth        required      pam_faillock.so preauth 
silent audit deny=5 unlock_time=900 
/etc/pam.d/password-auth:auth        sufficient    pam_unix.so nullok 
try_first_pass 
/etc/pam.d/password-auth:auth        [default=die] pam_faillock.so authfail 
audit deny=5 unlock_time=900 
# grep -E '^\s*account\s+required\s+pam_faillock.so\s*' /etc/pam.d/system-
auth /etc/pam.d/password-auth 
Verify the output includes the following lines: 
/etc/pam.d/system-auth:account     required      pam_faillock.so 
/etc/pam.d/password-auth:account     required      pam_faillock.so 
OR 
If pam_tally2.so is used: 
Run the following commands: 
# grep -E '^\s*auth\s+\S+\s+pam_(tally2|unix)\.so' /etc/pam.d/system-auth 
/etc/pam.d/password-auth 
Verify the output includes the following lines:","Edit the files /etc/pam.d/system-auth and /etc/pam.d/password-auth and add the 
following lines: 
Modify the deny= and unlock_time= parameters to conform to local site policy, Not to be 
greater than deny=5 
To use pam_faillock.so module, add the following lines to the auth section: 
auth        required      pam_faillock.so preauth silent audit deny=5 
unlock_time=900 
auth        [default=die] pam_faillock.so authfail audit deny=5 
unlock_time=900 
The auth sections should look similar to the following example: 
Note: The ordering on the lines in the auth section is important. The preauth line needs to 
below the line auth required pam_env.so and above all password validation lines. The 
authfail line needs to be after all password validation lines such as pam_sss.so. Incorrect 
order can cause you to be locked out of the system 
Example: 
auth        required      pam_env.so 
auth        required      pam_faillock.so preauth silent audit deny=5 
unlock_time=900 # <- Under "auth required pam_env.so" 
auth        sufficient    pam_unix.so nullok try_first_pass 
auth        [default=die] pam_faillock.so authfail audit deny=5 
unlock_time=900 # <- Last auth line before "auth requisite  
pam_succeed_if.so" 
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success 
auth        required      pam_deny.so 
Add the following line to the account section:"
5.4.3 Ensure password hashing algorithm is SHA-512 (Automated),"Run the following command to verify the sha512 option is included: 
# grep -P 
'^\h*password\h+(sufficient|requisite|required)\h+pam_unix\.so\h+([^#\n\r]+)?
sha512(\h+.*)?$' /etc/pam.d/system-auth /etc/pam.d/password-auth 
 
/etc/pam.d/system-auth:password    sufficient    pam_unix.so sha512 shadow 
nullok try_first_pass use_authtok 
/etc/pam.d/password-auth:password    sufficient    pam_unix.so sha512 shadow 
nullok try_first_pass use_authtok","Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include sha512 
option and remove the md5 option for pam_unix.so: 
password sufficient pam_unix.so sha512 
Note: 
 
Any system accounts that need to be expired should be carefully done separately by the 
system administrator to prevent any potential problems. 
 
If it is determined that the password algorithm being used is not SHA-512, once it is 
changed, it is recommended that all user ID's be immediately expired and forced to 
change their passwords on next login, In accordance with local site policies. 
 
To accomplish this, the following command can be used. 
o This command intentionally does not affect the root account. The root 
account's password will also need to be changed. 
# awk -F: '( $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $1 !~ 
/^(nfs)?nobody$/ && $1 != "root" ) { print $1 }' /etc/passwd | xargs -n 1 
chage -d 0"
5.4.4 Ensure password reuse is limited (Automated),"Verify remembered password history follows local site policy, not to be less than 5. 
If pam_pwhistory.so is used: 
Run the following command: 
# grep -P 
'^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+([^#]+\s+)*remembe
r=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth 
 
/etc/pam.d/system-auth:password    required      pam_pwhistory.so remember=5 
/etc/pam.d/password-auth:password    required      pam_pwhistory.so 
remember=5 
OR If pam_unix.so is used: 
Run the following command: 
# grep -P 
'^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*r
emember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-
auth 
 
/etc/pam.d/system-auth:password    sufficient      pam_unix.so remember=5 
/etc/pam.d/password-auth:password    sufficient      pam_unix.so remember=5","Edit both the /etc/pam.d/password-auth and /etc/pam.d/system-auth files to include the 
remember option and conform to site policy as shown: 
Note: Add or modify the line containing the pam_pwhistory.so after the first occurrence of 
password requisite: 
password    required      pam_pwhistory.so remember=5 
Example: (Second line is modified) 
password    requisite     pam_pwquality.so try_first_pass local_users_only 
authtok_type= 
password    required      pam_pwhistory.so use_authtok remember=5 retry=3  
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass 
use_authtok 
password    required      pam_deny.so 
Additional Information: 
 
This setting only applies to local accounts. 
 
This option is configured with the remember=n module option in 
/etc/pam.d/system-auth and /etc/pam.d/password-auth  
 
This option can be set with either one of the two following modules:  
o 
pam_pwhistory.so - This is the newer recommended method included in the 
remediation section. 
o 
pam_unix.so - This is the older method, and is included in the audit to 
account for legacy configurations."
5.5.1.1 Ensure password expiration is 365 days or less (Automated),"Run the following command and verify PASS_MAX_DAYS conforms to site policy (no more 
than 365 days): 
# grep ^\s*PASS_MAX_DAYS /etc/login.defs 
 
PASS_MAX_DAYS 365 
Run the following command and Review list of users and PASS_MAX_DAYS to verify that all 
users' PASS_MAX_DAYS conforms to site policy (no more than 365 days): 
# grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5 
 
<user>:<PASS_MAX_DAYS>","Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs : 
PASS_MAX_DAYS 365 
Modify user parameters for all users with a password set to match: 
# chage --maxdays 365 <user>"
"5.5.1.2 Ensure minimum days between password changes is configured 
(Automated)","Run the following command and verify PASS_MIN_DAYS conforms to site policy (no less than 
1 day): 
# grep ^\s*PASS_MIN_DAYS /etc/login.defs 
 
PASS_MIN_DAYS 1 
Run the following command and Review list of users and PAS_MIN_DAYS to Verify that all 
users' PAS_MIN_DAYS conforms to site policy (no less than 1 day): 
# grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4 
 
<user>:<PASS_MIN_DAYS>","Set the PASS_MIN_DAYS parameter to 1 in /etc/login.defs : 
PASS_MIN_DAYS 1 
Modify user parameters for all users with a password set to match: 
# chage --mindays 1 <user>"
"5.5.1.3 Ensure password expiration warning days is 7 or more 
(Automated)","Run the following command and verify PASS_WARN_AGE conforms to site policy (No less than 
7 days): 
# grep ^\s*PASS_WARN_AGE /etc/login.defs 
 
PASS_WARN_AGE 7 
Verify all users with a password have their number of days of warning before password 
expires set to 7 or more: 
Run the following command and Review list of users and PASS_WARN_AGE to verify that all 
users' PASS_WARN_AGE conforms to site policy (No less than 7 days): 
# grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6 
 
<user>:<PASS_WARN_AGE>","Set the PASS_WARN_AGE parameter to 7 in /etc/login.defs : 
PASS_WARN_AGE 7 
Modify user parameters for all users with a password set to match: 
# chage --warndays 7 <user>"
5.5.1.4 Ensure inactive password lock is 30 days or less (Automated),"Run the following command and verify INACTIVE conforms to sire policy (no more than 30 
days): 
# useradd -D | grep INACTIVE 
 
INACTIVE=30 
Verify all users with a password have Password inactive no more than 30 days after 
password expires: 
Run the following command and Review list of users and INACTIVE to verify that all users' 
INACTIVE conforms to site policy (no more than 30 days): 
# grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7 
 
<user>:<INACTIVE>","Run the following command to set the default password inactivity period to 30 days: 
# useradd -D -f 30 
Modify user parameters for all users with a password set to match: 
# chage --inactive 30 <user>"
"5.5.1.5 Ensure all users last password change date is in the past 
(Automated)","Run the following command and verify nothing is returned 
# for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep 
'^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --
list $usr | grep '^Last password change' | cut -d: -f2)"; done","Investigate any users with a password change date in the future and correct them. Locking 
the account, expiring the password, or resetting the password manually may be 
appropriate."
5.5.2 Ensure system accounts are secured (Automated),"Run the following commands and verify no results are returned: 
awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && 
$1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && 
$7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd 
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' 
/etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | 
awk '($2!="L" && $2!="LK") {print $1}'","Run the commands appropriate for your distribution: 
Set the shell for any accounts returned by the audit to nologin: 
# usermod -s $(which nologin) <user> 
Lock any non root accounts returned by the audit: 
# usermod -L <user> 
The following command will set all system accounts to a non login shell: 
awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && 
$1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && 
$7!="'"$(which nologin)"'" && $7!="/bin/false" && $7!="/usr/bin/false") 
{print $1}' /etc/passwd | while read -r user; do usermod -s "$(which 
nologin)" "$user"; done 
The following command will automatically lock not root system accounts: 
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' 
/etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | 
awk '($2!="L" && $2!="LK") {print $1}' | while read -r user; do usermod -L 
"$user"; done"
5.5.3 Ensure default group for the root account is GID 0 (Automated),"Run the following command and verify the result is 0 : 
# grep "^root:" /etc/passwd | cut -f4 -d: 
 
0","Run the following command to set the root user default group to GID 0 : 
# usermod -g 0 root"
5.5.4 Ensure default user shell timeout is configured (Automated),"Run the following script to verify that TMOUT is configured to: include a timeout of no more 
than 900 seconds, to be readonly, to be exported, and is not being changed to a longer 
timeout. 
#!/bin/bash 
 
output1="" output2="" 
[ -f /etc/bashrc ] && BRC="/etc/bashrc" 
for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do 
   grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' 
"$f" && grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-
8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && grep -Pq 
'^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-
9]|[1-9]))\b' "$f" && output1="$f" 
done 
grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' 
/etc/profile /etc/profile.d/*.sh "$BRC" && output2=$(grep -Ps 
'^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' 
/etc/profile /etc/profile.d/*.sh $BRC) 
if [ -n "$output1" ] && [ -z "$output2" ]; then 
   echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n" 
else 
   [ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n" 
   [ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured 
in: \"$output2\"\n" 
fi","Review /etc/bashrc, /etc/profile, and all files ending in *.sh in the /etc/profile.d/ 
directory and remove or edit all TMOUT=_n_ entries to follow local site policy. TMOUT should 
not exceed 900 or be equal to 0. 
Configure TMOUT in one of the following files: 
 
A file in the /etc/profile.d/ directory ending in .sh 
 
/etc/profile 
 
/etc/bashrc 
TMOUT configuration examples: 
 
As multiple lines: 
TMOUT=900 
readonly TMOUT 
export TMOUT 
 
As a single line: 
readonly TMOUT=900 ; export TMOUT"
5.5.5 Ensure default user umask is configured (Automated),"Run the following to verify: 
 
A default user umask is set to enforce a newly created directories' permissions to be 
750 (drwxr-x---), and a newly created file's permissions be 640 (rw-r-----), or 
more restrictive 
 
No less restrictive System Wide umask is set 
Run the following script to verify that a default user umask is set enforcing a newly created 
directories's permissions to be 750 (drwxr-x---), and a newly created file's permissions be 
640 (rw-r-----), or more restrictive: 
#!/bin/bash 
 
passing="" 
grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' /etc/login.defs && grep 
-Eqi '^\s*USERGROUPS_ENAB\s*"?no"?\b' /etc/login.defs && grep -Eq 
'^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' 
/etc/pam.d/common-session && passing=true 
grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-
7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* 
/etc/bashrc* && passing=true 
[ "$passing" = true ] && echo "Default user umask is set" 
Verify output is: "Default user umask is set" 
Run the following to verify that no less restrictive system wide umask is set: 
# grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-
6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-
6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(
,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bashrc* 
 
No file should be returned","Review /etc/bashrc, /etc/profile, and all files ending in *.sh in the /etc/profile.d/ directory 
and remove or edit all umask entries to follow local site policy. Any remaining entries 
should be: umask 027, umask u=rwx,g=rx,o= or more restrictive. 
Configure umask in one of the following files: 
 
A file in the /etc/profile.d/ directory ending in .sh 
 
/etc/profile 
 
/etc/bashrc 
Example: 
# vi /etc/profile.d/set_umask.sh 
 
umask 027 
Run the following command and remove or modify the umask of any returned files: 
# grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-
6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-
6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(
,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bashrc* 
Follow one of the following methods to set the default user umask: 
Edit /etc/login.defs and edit the UMASK and USERGROUPS_ENAB lines as follows: 
UMASK 027 
 
USERGROUPS_ENAB no 
Edit the files /etc/pam.d/password-auth and /etc/pam.d/system-auth and add or edit the 
following: 
session     optional      pam_umask.so 
OR Configure umask in one of the following files: 
 
A file in the /etc/profile.d/ directory ending in .sh 
 
/etc/profile 
 
/etc/bashrc 
Example: /etc/profile.d/set_umask.sh 
umask 027 
Note: this method only applies to bash and shell. If other shells are supported on the 
system, it is recommended that their configuration files also are checked."
5.6 Ensure root login is restricted to system console (Manual),# cat /etc/securetty,Remove entries for any consoles that are not in a physically secure location.
5.7 Ensure access to the su command is restricted (Automated),"Run the following command and verify the output matches the line: 
# grep -Pi 
'^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)
(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\
h+.*)?$' /etc/pam.d/su 
 
auth required pam_wheel.so use_uid group=<group_name> 
Run the following command and verify that the group specified in <group_name> contains 
no users: 
# grep <group_name> /etc/group 
 
<group_name>:x:<GID>: 
There should be no users listed after the Group ID field.","Create an empty group that will be specified for use of the su command. The group should 
be named according to site policy. 
Example: 
# groupadd sugroup 
Add the following line to the /etc/pam.d/su file, specifying the empty group: 
auth required pam_wheel.so use_uid group=sugroup"
6.1.1 Audit system file permissions (Manual),"Run the following command to review all installed packages. Note that this may be very 
time consuming and may be best scheduled via the cron utility. It is recommended that the 
output of this command be redirected to a file that can be reviewed later. This command 
will ignore configuration files due to the extreme likelihood that they will change. 
# rpm -Va --nomtime --nosize --nomd5 --nolinkto --noconfig > <filename>","Investigate the results to ensure any discrepancies found are understood and support 
proper secure operation of the system. 
References: 
1. https://docs.fedoraproject.org/en-US/fedora/rawhide/system-administrators-
guide/RPM/#s2-rpm-verifying"
6.1.2 Ensure permissions on /etc/passwd are configured (Automated),"Run the following command and verify Uid and Gid are both 0/root and Access is 644 or 
more restrictive: 
# stat /etc/passwd 
 
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/passwd : 
# chown root:root /etc/passwd 
# chmod u-x,g-wx,o-wx /etc/passwd"
6.1.3 Ensure permissions on /etc/passwd- are configured (Automated),"Run the following command and verify Uid and Gid are both 0/root and Access is 644 or 
more restrictive: 
# stat /etc/passwd- 
 
Access: (0644/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/passwd- : 
# chown root:root /etc/passwd- 
 
# chmod u-x,go-wx /etc/passwd-"
6.1.4 Ensure permissions on /etc/shadow are configured (Automated),"Run the following command and verify Uid and Gid are 0/root , and Access is 0000 : 
# stat /etc/shadow 
 
Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/shadow : 
# chown root:root /etc/shadow 
 
# chmod 0000 /etc/shadow"
6.1.5 Ensure permissions on /etc/shadow- are configured (Automated),"Run the following command and verify Uid is 0/root, Gid is 0/root and Access is 0000 : 
# stat /etc/shadow- 
 
Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/shadow- : 
# chown root:root /etc/shadow- 
# chmod 0000 /etc/shadow-"
6.1.6 Ensure permissions on /etc/gshadow- are configured (Automated),"Run the following command and verify verify Uid is 0/root, Gid is 0/root and Access is 
0000 : 
# stat /etc/gshadow- 
 
Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/gshadow- : 
# chown root:root /etc/gshadow- 
 
# chmod 0000 /etc/gshadow-"
6.1.7 Ensure permissions on /etc/gshadow are configured (Automated),"Run the following command and verify Uid is 0/root, Gid is 0/root and Access is 0000 : 
# stat /etc/gshadow 
 
Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/gshadow : 
# chown root:root /etc/gshadow 
 
# chmod 0000 /etc/gshadow"
6.1.8 Ensure permissions on /etc/group are configured (Automated),"Run the following command and verify Uid and Gid are both 0/root and Access is 644 or 
more restrictive: 
# stat /etc/group 
 
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/group : 
# chown root:root /etc/group 
 
# chmod u-x,g-wx,o-wx /etc/group"
6.1.9 Ensure permissions on /etc/group- are configured (Automated),"Run the following command and verify Uid and Gid are both 0/root and Access is 644 or 
more restrictive: 
# stat /etc/group- 
 
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)","Run the following commands to set owner, group, and permissions on /etc/group-: 
# chown root:root /etc/group- 
 
# chmod u-x,go-wx /etc/group-"
6.1.10 Ensure no world writable files exist (Automated),"Run the following command and verify no files are returned: 
# df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev 
-type f -perm -0002 
The command above only searches local filesystems, there may still be compromised items 
on network mounted partitions. Additionally the --local option to df is not universal to all 
versions, it can be omitted to search all filesystems on a system including network mounted 
filesystems or the following command can be run manually for each partition: 
# find <partition> -xdev -type f -perm -0002","Removing write access for the "other" category ( chmod o-w <filename> ) is advisable, but 
always consult relevant vendor documentation to avoid breaking any application 
dependencies on a given file."
6.1.11 Ensure no unowned files or directories exist (Automated),"Run the following command and verify no files are returned: 
# df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev 
-nouser 
The command above only searches local filesystems, there may still be compromised items 
on network mounted partitions. Additionally the --local option to df is not universal to all 
versions, it can be omitted to search all filesystems on a system including network mounted 
filesystems or the following command can be run manually for each partition: 
# find <partition> -xdev -nouser","Locate files that are owned by users or groups not listed in the system configuration files, 
and reset the ownership of these files to some active user on the system as appropriate."
6.1.12 Ensure no ungrouped files or directories exist (Automated),"Run the following command and verify no files are returned: 
# df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev 
-nogroup 
The command above only searches local filesystems, there may still be compromised items 
on network mounted partitions. Additionally the --local option to df is not universal to all 
versions, it can be omitted to search all filesystems on a system including network mounted 
filesystems or the following command can be run manually for each partition: 
# find <partition> -xdev -nogroup","Locate files that are owned by users or groups not listed in the system configuration files, 
and reset the ownership of these files to some active user on the system as appropriate."
6.1.13 Audit SUID executables (Manual),"Run the following command to list SUID files: 
# df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev 
-type f -perm -4000 
The command above only searches local filesystems, there may still be compromised items 
on network mounted partitions. Additionally the --local option to df is not universal to all 
versions, it can be omitted to search all filesystems on a system including network mounted 
filesystems or the following command can be run manually for each partition: 
# find <partition> -xdev -type f -perm -4000","Ensure that no rogue SUID programs have been introduced into the system. Review the 
files returned by the action in the Audit section and confirm the integrity of these binaries."
6.1.14 Audit SGID executables (Manual),"Run the following command to list SGID files: 
# df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev 
-type f -perm -2000 
The command above only searches local filesystems, there may still be compromised items 
on network mounted partitions. Additionally the --local option to df is not universal to all 
versions, it can be omitted to search all filesystems on a system including network mounted 
filesystems or the following command can be run manually for each partition: 
# find <partition> -xdev -type f -perm -2000","Ensure that no rogue SGID programs have been introduced into the system. Review the 
files returned by the action in the Audit section and confirm the integrity of these binaries."
"6.2.1 Ensure accounts in /etc/passwd use shadowed passwords 
(Automated)","Run the following command and verify that no output is returned: 
# awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' 
/etc/passwd","If any accounts in the /etc/passwd file do not have a single x in the password field, run the 
following command to set these accounts to use shadowed passwords: 
# sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd 
Investigate to determine if the account is logged in and what it is being used for, to 
determine if it needs to be forced off."
6.2.2 Ensure /etc/shadow password fields are not empty (Automated),"Run the following command and verify that no output is returned: 
# awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow","If any accounts in the /etc/shadow file do not have a password, run the following command 
to lock the account until it can be determined why it does not have a password: 
# passwd -l <username> 
Also, check to see if the account is logged in and investigate what it is being used for to 
determine if it needs to be forced off."
6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash 
 
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do 
  grep -q -P "^.*?:[^:]*:$i:" /etc/group 
  if [ $? -ne 0 ]; then 
    echo "Group $i is referenced by /etc/passwd but does not exist in 
/etc/group" 
  fi 
done","Analyze the output of the Audit step above and perform the appropriate action to correct 
any discrepancies found."
6.2.4 Ensure shadow group is empty (Automated),"Run the following commands and verify no results are returned: 
# awk -F: '($1=="shadow") {print $NF}' /etc/group 
# awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" 
'($4==GID) {print $1}' /etc/passwd","Run the following command to remove all users from the shadow group 
# sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group 
Change the primary group of any users with shadow as their primary group. 
# usermod -g <primary group> <user>"
6.2.5 Ensure no duplicate user names exist (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash 
 
cut -d: -f1 /etc/passwd | sort | uniq -d | while read x; do 
   echo "Duplicate login name ${x} in /etc/passwd" 
done","Based on the results of the audit script, establish unique user names for the users. File 
ownerships will automatically reflect the change as long as the users have unique UIDs."
6.2.6 Ensure no duplicate group names exist (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash 
 
cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do 
   echo "Duplicate group name ${x} in /etc/group" 
done","Based on the results of the audit script, establish unique names for the user groups. File 
group ownerships will automatically reflect the change as long as the groups have unique 
GIDs."
6.2.7 Ensure no duplicate UIDs exist (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash 
 
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read -r x; do 
   [ -z "$x" ] && break 
   set - "$x" 
   if [ "$1" -gt 1 ]; then 
      users=$(awk -F: '($3 == n) { print $1 }' n="$2" /etc/passwd | xargs) 
      echo "Duplicate UID ($2): $users" 
   fi 
done","Based on the results of the audit script, establish unique UIDs and review all files owned by 
the shared UIDs to determine which UID they are supposed to belong to."
6.2.8 Ensure no duplicate GIDs exist (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash  
 
cut -d: -f3 /etc/group | sort | uniq -d | while read -r x; do 
   echo "Duplicate GID ($x) in /etc/group" 
done","Based on the results of the audit script, establish unique GIDs and review all files owned by 
the shared GID to determine which group they are supposed to belong to. 
Additional Information: 
You can also use the grpck command to check for other inconsistencies in the /etc/group 
file."
6.2.9 Ensure root is the only UID 0 account (Automated),"Run the following command and verify that only "root" is returned: 
# awk -F: '($3 == 0) { print $1 }' /etc/passwd 
 
root",Remove any users other than root with UID 0 or assign them a new UID if appropriate.
6.2.10 Ensure root PATH Integrity (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash 
 
RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)" 
echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory 
(::)" 
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)" 
for x in $(echo "$RPCV" | tr ":" " "); do 
   if [ -d "$x" ]; then 
      ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working 
directory (.)"} 
      $3 != "root" {print $9, "is not owned by root"} 
      substr($1,6,1) != "-" {print $9, "is group writable"} 
      substr($1,9,1) != "-" {print $9, "is world writable"}' 
   else 
      echo "$x is not a directory" 
   fi 
done",Correct or justify any items discovered in the Audit step.
6.2.11 Ensure all users' home directories exist (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ ! -d "$dir" ]; then 
      echo "User: \"$user\" home directory: \"$dir\" does not exist." 
   fi 
done 
Note: The audit script checks all users with interactive shells except halt, sync, shutdown, and 
nfsnobody.","If any users' home directories do not exist, create them and make sure the respective user 
owns the directory. Users without an assigned home directory should be removed or 
assigned a home directory as appropriate. 
The following script will create a home directory for users with an interactive shell whose 
home directory doesn't exist: 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ ! -d "$dir" ]; then 
      mkdir "$dir" 
      chmod g-w,o-wrx "$dir" 
      chown "$user" "$dir" 
   fi 
done"
6.2.12 Ensure users own their home directories (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash  
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ ! -d "$dir" ]; then 
      echo "User: \"$user\" home directory: \"$dir\" does not exist." 
   else 
      owner=$(stat -L -c "%U" "$dir") 
      if [ "$owner" != "$user" ]; then 
         echo "User: \"$user\" home directory: \"$dir\" is owned by 
\"$owner\"" 
      fi 
   fi 
done","Change the ownership of any home directories that are not owned by the defined user to 
the correct user. 
The following script will create missing home directories, set the owner, and set the 
permissions for interactive users' home directories: 
#!/bin/bash  
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ ! -d "$dir" ]; then 
      echo "User: \"$user\" home directory: \"$dir\" does not exist, creating 
home directory" 
      mkdir "$dir" 
      chmod g-w,o-rwx "$dir" 
      chown "$user" "$dir" 
   else 
      owner=$(stat -L -c "%U" "$dir") 
      if [ "$owner" != "$user" ]; then 
         chmod g-w,o-rwx "$dir" 
         chown "$user" "$dir" 
      fi 
   fi 
done"
"6.2.13 Ensure users' home directories permissions are 750 or more 
restrictive (Automated)","Run the following script and verify no results are returned: 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) 
{print $1 " " $6}' /etc/passwd | while read -r user dir; do 
   if [ ! -d "$dir" ]; then 
      echo "User: \"$user\" home directory: \"$dir\" doesn't exist" 
   else 
      dirperm=$(stat -L -c "%A" "$dir") 
      if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | 
cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo 
"$dirperm" | cut -c10)" != "-" ]; then 
         echo "User: \"$user\" home directory: \"$dir\" has permissions: 
\"$(stat -L -c "%a" "$dir")\"" 
      fi 
   fi 
done","Making global modifications to user home directories without alerting the user community 
can result in unexpected outages and unhappy users. Therefore, it is recommended that a 
monitoring policy be established to report user file permissions and determine the action 
to be taken in accordance with site policy. 
The following script can be used to remove permissions is excess of 750 from users' home 
directories: 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) 
{print $6}' /etc/passwd | while read -r dir; do 
   if [ -d "$dir" ]; then 
      dirperm=$(stat -L -c "%A" "$dir") 
      if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | 
cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo 
"$dirperm" | cut -c10)" != "-" ]; then 
         chmod g-w,o-rwx "$dir" 
      fi 
   fi 
done"
"6.2.14 Ensure users' dot files are not group or world writable 
(Automated)","Run the following script and verify no results are returned: 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ -d "$dir" ]; then 
      for file in "$dir"/.*; do 
         if [ ! -h "$file" ] && [ -f "$file" ]; then 
            fileperm=$(stat -L -c "%A" "$file") 
            if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo 
"$fileperm" | cut -c9)" != "-" ]; then 
               echo "User: \"$user\" file: \"$file\" has permissions: 
\"$fileperm\"" 
            fi 
         fi 
      done 
   fi 
done","Making global modifications to users' files without alerting the user community can result 
in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring 
policy be established to report user dot file permissions and determine the action to be 
taken in accordance with site policy. 
The following script will remove excessive permissions on dot files within interactive 
users' home directories. 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $6 }' /etc/passwd | while read -r dir; do 
   if [ -d "$dir" ]; then 
      for file in "$dir"/.*; do 
         if [ ! -h "$file" ] && [ -f "$file" ]; then 
            fileperm=$(stat -L -c "%A" "$file") 
            if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo 
"$fileperm" | cut -c9)" != "-" ]; then 
               chmod go-w "$file" 
            fi 
         fi 
      done 
   fi 
done"
6.2.15 Ensure no users have .forward files (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash  
 
awk -F: '($1!~/(root|halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ -d "$dir" ]; then 
      file="$dir/.forward" 
      if [ ! -h "$file" ] && [ -f "$file" ]; then  
         echo "User: \"$user\" file: \"$file\" exists" 
      fi 
   fi 
done","Making global modifications to users' files without alerting the user community can result 
in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring 
policy be established to report user .forward files and determine the action to be taken in 
accordance with site policy. 
The following script will remove .forward files from interactive users' home directories 
#!/bin/bash  
 
awk -F: '($1!~/(root|halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $6 }' /etc/passwd | while read -r dir; do 
   if [ -d "$dir" ]; then 
      file="$dir/.forward" 
      [ ! -h "$file" ] && [ -f "$file" ] && rm -r "$file" 
   fi 
done"
6.2.16 Ensure no users have .netrc files (Automated),"Run the following script. This script will return: 
 
FAILED: for any .netrc file with permissions less restrictive than 600 
 
WARNING: for any .netrc files that exist in interactive users' home directories. 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ -d "$dir" ]; then 
      file="$dir/.netrc" 
      if [ ! -h "$file" ] && [ -f "$file" ]; then 
         if stat -L -c "%A" "$file" | cut -c4-10 |  grep -Eq '[^-]+'; then 
            echo "FAILED: User: \"$user\" file: \"$file\" exists with 
permissions: \"$(stat -L -c "%a" "$file")\", remove file or excessive 
permissions" 
         else 
            echo "WARNING: User: \"$user\" file: \"$file\" exists with 
permissions: \"$(stat -L -c "%a" "$file")\", remove file unless required" 
         fi 
      fi 
   fi 
done 
Verify: 
 
Any lines beginning with FAILED: - File should be removed unless deemed 
necessary, in accordance with local site policy, and permissions are updated to be 
600 or more restrictive 
 
Any lines beginning with WARNING: - File should be removed unless deemed 
necessary, and in accordance with local site policy","Making global modifications to users' files without alerting the user community can result 
in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring 
policy be established to report user .netrc files and determine the action to be taken in 
accordance with site policy. 
The following script will remove .netrc files from interactive users' home directories 
#!/bin/bash 
 
awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $6 }'  /etc/passwd | while read -r dir; do 
   if [ -d "$dir" ]; then 
      file="$dir/.netrc" 
      [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file" 
   fi 
done 
Additional Information: 
While the complete removal of .netrc files is recommended, if any are required on the 
system secure permissions must be applied."
6.2.17 Ensure no users have .rhosts files (Automated),"Run the following script and verify no results are returned: 
#!/bin/bash  
 
awk -F: '($1!~/(root|halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $1 " " $6 }' /etc/passwd | while read -r user dir; do 
   if [ -d "$dir" ]; then 
      file="$dir/.rhosts" 
      if [ ! -h "$file" ] && [ -f "$file" ]; then  
         echo "User: \"$user\" file: \"$file\" exists" 
      fi 
   fi 
done","Making global modifications to users' files without alerting the user community can result 
in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring 
policy be established to report user .rhosts files and determine the action to be taken in 
accordance with site policy. 
The following script will remove .rhosts files from interactive users' home directories 
#!/bin/bash  
 
awk -F: '($1!~/(root|halt|sync|shutdown|nfsnobody)/ && 
$7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { 
print $6 }' /etc/passwd | while read -r dir; do 
   if [ -d "$dir" ]; then 
      file="$dir/.rhosts" 
      [ ! -h "$file" ] && [ -f "$file" ] && rm -r "$file" 
   fi 
done"