#!/usr/bin/env bash

set -o pipefail
set -o nounset
set -o errexit

source /etc/packer/files/functions.sh

case $HARDENING_FLAG in
  cis)
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_cis"
    ;;
  
  cui)
    enable_fips
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_cui"
    ;;

  e8)
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_e8"
    ;;

  hipaa)
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_hipaa"
    ;;

  ospp)
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_ospp"
    ;;

  pci-dss)
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_pci-dss"
    ;;

  stig)
    enable_fips
    oscap_generate_fix "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml" "xccdf_org.ssgproject.content_profile_stig" "/etc/packer/files/ssg-rhel7-ds-tailoring.xml"
    ;;
  
  *)
    echo "unsupported hardening profile"
esac

if [ -f /etc/packer/hardening.sh ]; then
  bash /etc/packer/hardening.sh
fi

if [ -f /etc/packer/hardening.sh ]; then
  bash /etc/packer/hardening.sh
fi

