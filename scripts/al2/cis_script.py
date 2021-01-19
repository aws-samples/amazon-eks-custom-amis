#!/usr/bin/env python

import argparse
import logging
import os
import re
from subprocess import CalledProcessError, check_output
import pkg_resources


__file_history__ = {}
__backup_enabled__ = True

def set_backup_enabled(flag):
    global __backup_enabled__
    __backup_enabled__ = flag

def exec_shell(cmd):
    """Executes consecutive shell commands."""
    if isinstance(cmd, str):
        cmd = [cmd]

    command_string = ' && '.join(cmd)

    logging.debug('Executing "%s"...', command_string)
    return check_output(command_string, shell=True)


def ensure_backed_up(path):
    """Backs up a file at the specified path unless it is already backed up"""
    global __file_history__
    global __backup_enabled__

    if not __backup_enabled__:
        return

    if path not in __file_history__ and os.path.isfile(path):
        backup_path = '{}.bak'.format(path)
        logging.info('Backing up %s into %s...', path, backup_path)
        exec_shell('cp {} {}'.format(path, backup_path))
        __file_history__[path] = True


class Service:
    """Represents a system service."""

    def __init__(self, name):
        self.name = name

    def exists(self):
        """Checks if the specified service exists."""
        try:
            exec_shell(['chkconfig --list {} &> /dev/null'.format(self.name)])
        except CalledProcessError:
            return False
        return True

    def enable(self):
        """Set the service to be started on startup."""
        if self.exists():
            exec_shell(['chkconfig {} on'.format(self.name)])

    def disable(self):
        """Set the service not to be started on startup."""
        if self.exists():
            exec_shell(['chkconfig {} off'.format(self.name)])


class Package:
    """Represents a yum package"""

    @staticmethod
    def update_all():
        """Updates all installed packages"""
        exec_shell(['yum --exclude=docker --exclude=containerd\*  update -y'])

    def __init__(self, name):
        self.name = name

    def exists(self):
        """Checks if the specified package is installed."""
        try:
            exec_shell(
                ['yum -q list installed {} &> /dev/null'.format(self.name)])
        except CalledProcessError:
            return False

        return True

    def install(self):
        """Installs the package."""
        if not self.exists():
            exec_shell(['yum install -y {}'.format(self.name)])

    def remove(self):
        """Removes the package."""
        if self.exists():
            exec_shell(['yum remove -y {}'.format(self.name)])


class File:
    """Represents a general file"""

    def __init__(self, path):
        self.path = path

    def write(self, content):
        """Writes a content into the ile"""
        ensure_backed_up(self.path)
        with open(self.path, 'w') as f:
            f.write(content)


class PropertyFile:
    """Represents a property file which contains a collection of key / value pairs"""

    def __init__(self, path, sep):
        self.path = path
        self.sep = sep
        self.params = {}

    def override(self, params):
        """Updates key / value pairs to be overridden"""
        for key, value in params.items():
            self.params[key] = value
        return self

    def write(self):
        """Writes a content with overridden key / value pairs into disk"""
        params = self.params.copy()
        content = ''

        if os.path.isfile(self.path):
            with open(self.path, 'r') as f:
                for line in f:
                    for key, value in params.items():
                        if line.startswith('{}{}'.format(key, self.sep)):
                            if value is not None:
                                line = '{}{}{}\n'.format(key, self.sep, value)
                            else:
                                line = ''
                            params.pop(key)
                    content += line

        for key, value in params.items():
            if value is not None:
                content += '\n{}{}{}'.format(key, self.sep, value)

        ensure_backed_up(self.path)
        with open(self.path, 'w') as f:
            f.write(content)


def get_string_asset(path):
    """Returns the content of the specified asset file"""
    return pkg_resources.resource_string(__name__, 'assets/{}'.format(path))


def disable_unused_filesystems():
    """1.1.1 Disable unused filesystems"""
    filesystems = [
        'cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf', 'vfat'
    ]

    prop = PropertyFile('/etc/modprobe.d/CIS.conf', ' ')
    for filesystem in filesystems:
        prop.override({'install {}'.format(filesystem): '/bin/true'})
    prop.write()


def ensure_sticky_bit():
    """1.1.18 Ensure sticky bit is set on all world - writable directories"""
    try:
        return exec_shell(['df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t'])
    except CalledProcessError:
        return 1


def disable_automounting():
    """1.1.19 Disable Automounting"""
    Service('autofs').disable()


def enable_aide():
    """1.3 Filesystem Integrity Checking"""

    cron_job = '0 5 * * * /usr/sbin/aide --check'

    Package('aide').install()

    return exec_shell([
        'aide --init',
        'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
        '(crontab -u root -l 2>/dev/null | grep -v /usr/sbin/aide; echo "{}") | crontab -'.format(cron_job)
    ])


def secure_boot_settings():
    """1.4 Secure Boot Settings"""

    if os.path.isfile('/boot/grub/menu.lst'):
        exec_shell([
            'chown root:root /boot/grub/menu.lst',
            'chmod og-rwx /boot/grub/menu.lst'
        ])

    PropertyFile('/etc/sysconfig/init', '=').override({
        'SINGLE': '/sbin/sulogin',
        'PROMPT': 'no'
    }).write()


def apply_process_hardenings():
    """1.5 Additional Process Hardening"""
    # 1.5.1 Ensure core dumps are restricted
    PropertyFile('/etc/security/limits.conf', ' ').override({
        '* hard core': '0'
    }).write()

    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'fs.suid_dumpable': '0',
    }).write()

    # 1.5.3 Ensure address space layout randomization (ASLR) is enable
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'kernel.randomize_va_space': '2'
    }).write()

    # 1.5.4 Ensure prelink is disabled
    Package('prelink').remove()


def ensure_updated():
    """1.8 Ensure updates, patches, and additional security software are installed"""
    Package.update_all()


def disable_inetd_services():
    """2.1 inetd Services"""
    services = [
        'chargen-dgram', 'chargen-stream', 'daytime-dgram', 'daytime-stream',
        'discard-dgram', 'discard-stream', 'echo-dgram', 'echo-stream',
        'time-dgram', 'time-stream', 'rexec', 'rlogin', 'rsh', 'talk',
        'telnet', 'tftp', 'rsync', 'xinetd'
    ]

    for srv in services:
        Service(srv).disable()


def configure_time_synchronization(upstream, chrony=True):
    """2.2.1 Time Synchronization"""
    configure_chrony(upstream)


def configure_chrony(upstream):
    """2.2.1 Time Synchronization"""

    # 2.2.1.1 Ensure time synchronization is in use
    Package('ntp').remove()
    Package('chrony').install()

    # 2.2.1.3 Ensure chrony is configured
    PropertyFile('/etc/chrony.conf', ' ').override({
        'server': upstream
    }).write()

    PropertyFile('/etc/sysconfig/chronyd', '=').override({
        'OPTIONS': '"-u chrony"'
    }).write()

    exec_shell([
        'chkconfig chronyd on',
    ])


def remove_x11_packages():
    """2.2.2 Ensure X Window System is not installed"""
    Package('xorg-x11*').remove()


def disable_special_services():
    """2.2.3 - 2.2.14, 2.2.16"""
    services = [
        'avahi-daemon', 'cups',
        'dhcpd', 'slapd', 'nfs', 'rpcbind', 'named', 'vsftpd',
        'httpd', 'dovecot', 'smb', 'squid', 'snmpd', 'ypserv'
    ]

    for srv in services:
        Service(srv).disable()


def remove_insecure_clients():
    """2.3 Service Clients"""
    packages = [
        'ypbind', 'rsh', 'talk',
        'telnet', 'openldap-clients'
    ]

    for package in packages:
        Package(package).remove()


def configure_host_network_params():
    """3.1 Network Parameters(Host Only)"""
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'net.ipv4.ip_forward': '0',
        'net.ipv4.conf.all.send_redirects': '0',
        'net.ipv4.conf.default.send_redirects': '0',
    }).write()


def configure_network_params():
    """3.2 Network Parameters(Host and Router)"""
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'net.ipv4.conf.all.accept_source_route': '0',
        'net.ipv4.conf.default.accept_source_route': '0',
        'net.ipv6.conf.all.accept_source_route' : '0',
        'net.ipv6.conf.default.accept_source_route': '0',
        'net.ipv4.conf.all.accept_redirects': '0',
        'net.ipv4.conf.default.accept_redirects': '0',
        'net.ipv4.conf.all.secure_redirects': '0',
        'net.ipv4.conf.default.secure_redirects': '0',
        'net.ipv4.conf.all.log_martians': '1',
        'net.ipv4.conf.default.log_martians': '1',
        'net.ipv4.icmp_echo_ignore_broadcasts': '1',
        'net.ipv4.icmp_ignore_bogus_error_responses': '1',
        'net.ipv4.conf.all.rp_filter': '1',
        'net.ipv4.conf.default.rp_filter': '1',
        'net.ipv4.tcp_syncookies': '1'
    }).write()


def configure_ipv6_params():
    """3.3 IPv6"""
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'net.ipv6.conf.all.accept_ra': '0',
        'net.ipv6.conf.default.accept_ra': '0',
        'net.ipv6.conf.all.accept_redirects': '0',
        'net.ipv6.conf.default.accept_redirects': '0'
    }).write()

    # # 3.3.3 Ensure IPv6 is disabled
    # PropertyFile('/etc/modprobe.d/CIS.conf', ' ').override({
    #     'options ipv6': 'disable=1'
    # }).write()

def configure_log_file_permissions():
    """4.2.4 Ensure permissions on all logfiles are configured"""
    exec_shell([r'find /var/log -type f -exec chmod g-wx,o-rwx {} +'])


def configure_cron():
    """5.1 Configure cron"""
    # 5.1.1 Ensure cron daemon is enabled
    Service('crond').enable()

    # 5.1.2 - 5.1.8
    exec_shell([
        'chown root:root /etc/crontab',
        'chmod og-rwx /etc/crontab',
        'chown root:root /etc/cron.hourly',
        'chmod og-rwx /etc/cron.hourly',
        'chown root:root /etc/cron.daily',
        'chmod og-rwx /etc/cron.daily',
        'chown root:root /etc/cron.weekly',
        'chmod og-rwx /etc/cron.weekly',
        'chown root:root /etc/cron.monthly',
        'chmod og-rwx /etc/cron.monthly',
        'chown root:root /etc/cron.d',
        'chmod og-rwx /etc/cron.d',
        'rm -f /etc/cron.deny',
        'rm -f /etc/at.deny',
        'touch /etc/cron.allow',
        'touch /etc/at.allow',
        'chmod og-rwx /etc/cron.allow',
        'chmod og-rwx /etc/at.allow',
        'chown root:root /etc/cron.allow',
        'chown root:root /etc/at.allow'
    ])


def configure_sshd():
    """5.2 SSH Server Configuration"""
    # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
    exec_shell([
        'chown root:root /etc/ssh/sshd_config',
        'chmod og-rwx /etc/ssh/sshd_config'
    ])

    # 5.2.2 - 5.2.16
    PropertyFile('/etc/ssh/sshd_config', ' ').override({
        'Protocol': '2',
        'LogLevel': 'INFO',
        'X11Forwarding': 'no',
        'MaxAuthTries': '4',
        'IgnoreRhosts': 'yes',
        'HostbasedAuthentication': 'no',
        'PermitRootLogin': 'no',
        'PermitEmptyPasswords': 'no',
        'PermitUserEnvironment': 'no',
        'Ciphers': 'aes256-ctr,aes192-ctr,aes128-ctr',
        'MACs': 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',
        'ClientAliveInterval': '300',
        'ClientAliveCountMax': '0',
        'LoginGraceTime': '60',
        'AllowUsers': 'ec2-user',
        'Banner': '/etc/issue.net'
    }).write()

def configure_password_parmas():
    """5.4.1 Set Shadow Password Suite Parameters"""
    PropertyFile('/etc/login.defs', '\t').override({
        'PASS_MAX_DAYS': '90',
        'PASS_MIN_DAYS': '7',
        'PASS_WARN_AGE': '7'
    }).write()

    exec_shell([
        'useradd -D -f 30'
    ])


def configure_umask():
    """5.4.3, 5.4.4"""
    umask_reg = r'^(\s*)umask\s+[0-7]+(\s*)$'

    bashrc = exec_shell([
        'cat /etc/bashrc | sed -E "s/{}/\\1umask 027\\2/g"'.format(umask_reg)
    ])
    File('/etc/bashrc').write(bashrc)

    profile = exec_shell([
        'cat /etc/profile | sed -E "s/{}/\\1umask 027\\2/g"'.format(
            umask_reg)
    ])
    File('/etc/profile').write(profile)


def main():
    parser = argparse.ArgumentParser(
        description='A script to harden Amazon Linux instance.')

    # The Amazon Time Sync Service is available through NTP
    # at the 169.254.169.123 IP address for any instance running in a VPC.
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
    parser.add_argument('--time', metavar='<time server>', default ='169.254.169.123',
                        help='Specify the upstream time server.')
    parser.add_argument('--chrony', action='store', type=bool, default=True,
                        help='Use chrony for time synchronization')
    parser.add_argument('--no-backup', action='store_true',
                        help='Automatic config backup is disabled')
    parser.add_argument('--clients', nargs='+', metavar='<allowed clients>',
                        help='Specify a comma separated list of hostnames and host IP addresses.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display details including debugging output etc.')
    parser.add_argument('--disable-tcp-wrappers', action='store_true',
                        help='disable tcp-wrappers')
    parser.add_argument('--disable-pam', action='store_true',
                        help='disable pam')
    parser.add_argument('--disable-iptables', action='store_true',
                        help='disable iptables')
    parser.add_argument('--disable-mount-options', action='store_true',
                        help='disable set mount options')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARN)

    logging.info(
        '[Config] Upstream time server is set as "%s"', args.time)
    if args.chrony:
        logging.info(
            '[Config] chrony will be used for time synchronization')
    else:
        logging.info(
            '[Config] ntp will be used for time synchronization')
    if args.clients:
        logging.info('[Config] Allowed clients are set as %s',
            args.clients)

    if args.no_backup:
        logging.info('[Config] Automatic config backup is disabled')
        set_backup_enabled(False)

    # 1 Initial Setup
    disable_unused_filesystems()
    ensure_sticky_bit()
    disable_automounting()
    enable_aide()
    secure_boot_settings()
    apply_process_hardenings()
    ensure_updated()

    # 2 Services
    disable_inetd_services()
    configure_time_synchronization(args.time, chrony=args.chrony)
    remove_x11_packages()
    disable_special_services()
    remove_insecure_clients()

    # 3 Network Configuration
    configure_host_network_params()
    configure_network_params()
    configure_ipv6_params()

    # 4 Logging and Auditing
    configure_log_file_permissions()

    # 5 Access, Authentication and Authorization
    configure_cron()
    configure_sshd()
    configure_password_parmas()
    configure_umask()


if __name__ == '__main__':
    main()
