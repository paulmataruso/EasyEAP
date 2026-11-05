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
