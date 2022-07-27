#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# enable dod stig
if [ "${HARDENING_FLAG}" = "nist" ]; then

    # install and enable fips modules
    yum install -y dracut-fips openssl
    dracut -f

    # edit /etc/default/grub to add fips=1 to GRUB_CMDLINE_LINUX_DEFAULT
    sed -i 's/^\(GRUB_CMDLINE_LINUX_DEFAULT=.*\)"$/\1 fips=1"/' /etc/default/grub

    # rebuild grub
    grub2-mkconfig -o /etc/grub2.cfg
fi
