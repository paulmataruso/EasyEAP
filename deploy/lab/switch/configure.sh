#!/bin/sh
# configure.sh <community|-> [<v3 user> <auth key> <priv key> <auth: SHA|SHA-256> <priv: AES|AES-256>]
# Writes snmpd's configuration the way the switch's generated block would set it up, then restarts snmpd.
set -eu
community="$1"
{
  echo "agentAddress udp:161"
  echo "sysName lab-sw1"
  echo "sysDescr Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)"
  echo "sysObjectID .1.3.6.1.4.1.9.1.2494"
  echo "engineID easyeap-lab-sw1"
  echo "view easyeapro included .1.3.6.1.2.1.1"
  echo "view easyeapro included .1.3.6.1.2.1.2.2.1"
  echo "view easyeapro included .1.3.6.1.2.1.31.1.1.1"
  echo "view easyeapro included .1.3.6.1.2.1.47.1.1.1.1"
  echo "view easyeapro included .1.3.6.1.4.1.9.9.656"
  echo "view easyeapro included .1.3.6.1.4.1.9.9.548"
  [ "$community" != "-" ] && echo "rocommunity $community default -V easyeapro"
  if [ $# -ge 6 ]; then
    echo "createUser $2 $5 \"$3\" $6 \"$4\""
    echo "rouser $2 priv -V easyeapro"
  fi
  for base in .1.3.6.1.2.1.2.2 .1.3.6.1.2.1.31.1.1 .1.3.6.1.2.1.47.1.1.1 .1.3.6.1.4.1.9.9.656 .1.3.6.1.4.1.9.9.548; do
    echo "pass_persist $base /usr/bin/python3 /lab/switch.py"
  done
} > /lab/data/snmpd.conf.new
mv /lab/data/snmpd.conf.new /lab/data/snmpd.conf
rm -f /var/lib/net-snmp/snmpd.conf   # forget users created by an earlier configuration
[ -f /run/snmpd.pid ] && kill "$(cat /run/snmpd.pid)" 2>/dev/null || true
