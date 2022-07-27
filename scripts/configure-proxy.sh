#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

# Configure the host with HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
# by setting values in /etc/environment

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
