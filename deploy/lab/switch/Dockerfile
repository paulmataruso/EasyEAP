# EasyEAP lab: a pretend Cisco Catalyst for the switch audit's end-to-end test. net-snmp's snmpd answers SNMPv2c and
# SNMPv3 (its own, independent USM implementation); a pass_persist script serves the Catalyst tables EasyEAP reads
# (IF-MIB ports, ENTITY-MIB chassis, CISCO-AUTH-FRAMEWORK-MIB, CISCO-ERR-DISABLE-MIB) from /lab/data/dataset.json,
# which the test rewrites to stage each finding. Test use only.
FROM alpine:3.22
RUN apk add --no-cache net-snmp python3
COPY switch.py run.sh configure.sh /lab/
RUN mkdir -p /lab/data /var/lib/net-snmp && chmod +x /lab/run.sh /lab/configure.sh
ENTRYPOINT ["/bin/sh", "/lab/run.sh"]
