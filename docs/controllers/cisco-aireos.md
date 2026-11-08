# Cisco AireOS WLC 8.x

Replace `<easyeap-radius-ip>`, `<shared-secret-you-saved>` and `<wlan-id>`. If the tenant uses dedicated ports,
replace 1812/1813 with the ports on its RADIUS screen.

## CLI

```
# EasyEAP: Cisco AireOS WLC 8.x
config radius auth add 1 <easyeap-radius-ip> 1812 ascii <shared-secret-you-saved>
config radius auth rfc3576 enable 1
config radius acct add 1 <easyeap-radius-ip> 1813 ascii <shared-secret-you-saved>
config wlan disable <wlan-id>
config wlan security wpa akm 802.1x enable <wlan-id>
config wlan radius_server auth add <wlan-id> 1
config wlan radius_server acct add <wlan-id> 1
config wlan aaa-override enable <wlan-id>
config wlan enable <wlan-id>
```

Server index `1` is an example. Use a free index if 1 is taken.

## GUI equivalent

1. **Security → AAA → RADIUS → Authentication:** add the server and turn on **Support for CoA** (RFC 3576).
2. **Security → AAA → RADIUS → Accounting:** add the same server on the accounting port.
3. **WLANs → (your SSID) → Security → Layer 2:** WPA2/WPA3 with 802.1X. **AAA Servers:** select the server.
4. **WLANs → (your SSID) → Advanced:** turn on **Allow AAA Override**.

AireOS accepts CoA on UDP 3799, which is EasyEAP's default for this controller type.

## Checks

- Every VLAN EasyEAP assigns has a dynamic interface on the WLC (or an interface group), and the AP switch ports
  carry it.
- The WLC sources RADIUS from its management interface; that's the address to register in EasyEAP.
- `show client detail <mac>` shows the assigned VLAN after authentication.

## Syslog

EasyEAP can keep the controller's log and show it live (Investigate → Device syslog), decoded where it can: client
association, authentication (with SSID and IP), failures, exclusions and disassociation (with the reason). AireOS
(and the vWLC) sends syslog to **UDP 514 only**, so the EasyEAP server must publish 514 (`install.sh` does when the
port is free; see DEPLOYMENT.md). In **RADIUS**, select the controller, then **Syslog from …** → **Keep syslog from this
device**. In the web interface: Management → Logs → Config, Syslog Server IP Address: EasyEAP's address, Add, Syslog
Level: Informational, Apply, then Save Configuration. The client messages are off until turned on, which only the CLI
does; these lines set everything:

```
config logging syslog host <EasyEAP's address>
config logging syslog level informational
config logging syslog facility client authentication enable
config logging syslog facility client authfail enable
config logging syslog facility client deauthenticate enable
config logging syslog facility client excluded enable
config logging syslog facility client associate enable
config logging syslog facility client disassociate enable
save config
```

The controller sends from its management interface, as it does RADIUS. To stop: `config logging syslog host
<EasyEAP's address> delete` (the panel has the full list).
