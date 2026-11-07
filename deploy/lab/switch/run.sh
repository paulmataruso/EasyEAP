#!/bin/sh
# Keep snmpd running; configure.sh rewrites the configuration and stops it, and this loop starts it again.
[ -f /lab/data/snmpd.conf ] || cat > /lab/data/snmpd.conf <<'CONF'
agentAddress udp:161
CONF
while true; do
  /usr/sbin/snmpd -f -Lo -C -p /run/snmpd.pid -c /lab/data/snmpd.conf -I -ifTable,ifXTable,interfaces,entPhysicalTable,entity,systemstats,ip-mib/ipSystemStatsTable || true
  sleep 1
done
