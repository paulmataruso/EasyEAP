# Cisco Catalyst 9800 (IOS-XE 17.x)

The console's RADIUS screen generates this configuration with the tenant's values filled in. Replace the
placeholders in angle brackets:

| Placeholder | Value |
|---|---|
| `<easyeap-radius-ip>` | The RADIUS address (`EASYEAP_RADIUS_ADDRESS`), as the controller reaches it |
| `<shared-secret-you-saved>` | The secret shown once when you added the controller in EasyEAP |
| `<wlan-id>` | A free WLAN ID |
| `<policy-profile>` | The policy profile tagged to the SSID's access points |
| `<default-vlan>` | The VLAN clients use before RADIUS assigns one |

## CLI

```
! EasyEAP: Catalyst 9800 (IOS-XE 17.x)
aaa new-model
dot1x system-auth-control
radius server EASYEAP-<TENANT>
 address ipv4 <easyeap-radius-ip> auth-port 1812 acct-port 1813
 key 0 <shared-secret-you-saved>
!
aaa group server radius EASYEAP
 server name EASYEAP-<TENANT>
 deadtime 5
!
aaa authentication dot1x EASYEAP-AUTH group EASYEAP
aaa authorization network EASYEAP-AUTHZ group EASYEAP
aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP
!
! Change of Authorization (lets EasyEAP disconnect revoked devices). The 9800 listens on UDP 1700 by default.
aaa server radius dynamic-author
 client <easyeap-radius-ip> server-key 0 <shared-secret-you-saved>
 auth-type any
!
wlan Corp-WiFi <wlan-id> Corp-WiFi
 security dot1x authentication-list EASYEAP-AUTH
 security wpa akm dot1x
 no security wpa akm psk
 shutdown
 no shutdown
!
wireless profile policy <policy-profile>
 aaa-override
 accounting-list EASYEAP-ACCT
 vlan <default-vlan>
 no shutdown
```

If the tenant uses dedicated ports, replace 1812/1813 with the ports on its RADIUS screen.

## GUI equivalent

1. **Configuration → Security → AAA → Servers/Groups:** add the RADIUS server and the server group.
2. **Configuration → Tags & Profiles → WLANs:** set Layer 2 security to WPA2/WPA3 with 802.1X, and the
   authentication list to `EASYEAP-AUTH`.
3. **Configuration → Tags & Profiles → Policy:** turn on **AAA Override** so the RADIUS VLAN is applied, and set the
   accounting list.
4. **Configuration → Security → AAA → AAA Advanced:** add EasyEAP as a dynamic-author (CoA) client.
5. In EasyEAP, set this controller's CoA port to **1700** unless you changed it on the 9800.

## Checks

- Each VLAN in the tenant's policy exists on the controller (or its interface group) and on the AP switch ports.
- The source address the 9800 uses for RADIUS (its wireless management interface, unless you set
  `ip radius source-interface`) is the address registered in EasyEAP.
- `show wireless client mac-address <mac> detail` shows the VLAN EasyEAP assigned.
- `test aaa` can't test EAP-TLS. Use a real device and read the EasyEAP Authentication log.
