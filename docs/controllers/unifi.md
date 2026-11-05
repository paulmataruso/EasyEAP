# UniFi Network

UniFi is configured in the UniFi Network application. There is no CLI snippet.

1. **Settings → Profiles → RADIUS → Create New.**
2. **Authentication servers:** the EasyEAP RADIUS address, port 1812 (or the tenant's dedicated authentication
   port), and the shared secret you saved when you added the controller in EasyEAP.
3. **Enable RADIUS accounting:** the same address, port 1813 (or the dedicated accounting port), and the same secret.
4. Turn on **RADIUS assigned VLAN for wireless network**. This applies the VLAN EasyEAP returns.
5. **Settings → WiFi → (your SSID):** security protocol WPA2/WPA3 Enterprise; RADIUS profile = the profile above.
6. Create each VLAN EasyEAP can assign as a network (**Settings → Networks**) so the access points carry it.

## Things to know

- **Source address.** Requests come from each access point (or from the gateway, depending on version and
  topology), not from a central controller. Register the address EasyEAP actually sees. The Authentication log shows
  unknown-client drops in the RADIUS service log if the address is wrong.
- **CoA.** UniFi does not accept Disconnect-Requests from an external RADIUS server in every version. Leave CoA off
  for UniFi clients in EasyEAP unless you have verified it. A revoked device that is already connected then stays
  connected until it re-authenticates (the tenant's `Session-Timeout`, 8 hours by default). New connections are refused
  once RADIUS applies the revocation.
- **Fast roaming.** If you enable fast roaming (802.11r), roaming devices can skip full EAP until their key
  cache expires. Weigh this against how quickly you need revocations to bite.
