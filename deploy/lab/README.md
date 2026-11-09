# EasyEAP lab profile

Test-only services for trying EasyEAP without hardware:

* `easyeap-lab-ad`: Samba AD DC (`LAB.EASYEAP.TEST`, LDAPS on 636 with a self-signed certificate) seeded with
  users and groups (Alice/IT Dept, Bob/Staff, Carol/Contractors, Dave disabled, Nina via nested Network Team → IT Dept).
  Bind DN `svc-easyeap@lab.easyeap.test`, password `Svc-Read-0nly-Lab!` (lab only).
* `easyeap-lab-client`: `eapol_test` (wpa_supplicant) acting as a Wi-Fi client and controller.
* `easyeap-lab-switch`: a pretend Cisco Catalyst for the switch audit: net-snmp's `snmpd` answering SNMPv2c and
  SNMPv3, with a `pass_persist` script serving the IF-MIB, ENTITY-MIB, CISCO-AUTH-FRAMEWORK-MIB and
  CISCO-ERR-DISABLE-MIB rows in `/lab/data/dataset.json`. `/lab/configure.sh <community> [<user> <auth key> <priv key>
  SHA-256 AES]` sets the credentials the way the generated monitoring block would.

Start with `docker compose --profile lab up -d`, then see DEVELOPMENT.md → "EAP-TLS simulation".
Never enable the lab profile on a production host.
