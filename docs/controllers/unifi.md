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

## Wired 802.1X on UniFi switches

The same RADIUS profile serves UniFi switch ports. In EasyEAP, either add the switch (**Add → Switch → UniFi**) or,
if the gateway or controller address is already registered for Wi-Fi, choose **Turn on wired for an existing
registration** in the same wizard. Requests from UniFi often come from the gateway, so one registration usually
serves both networks.

1. **Settings → Profiles → RADIUS →** the EasyEAP profile: turn on **RADIUS Assigned VLAN for Wired Network**.
2. **Settings → Networks → Global Switch Settings** (Ports Manager in older versions) **→ 802.1X Control:** on,
   RADIUS profile = the EasyEAP profile, **Fallback VLAN** = the VLAN the ports use today.
3. **Devices → the switch → Port Manager:** set **one** test port's 802.1X Control to **Auto**. Leave every other
   port on **Force Authorized**.
4. Plug in a test device with an EasyEAP certificate. The wizard shows its first request.
5. Then set more ports to Auto. Never the uplink or ports with access points.

### Monitor mode and enforcing on UniFi

UniFi has no open-port mode like Cisco's. EasyEAP's monitor mode for a UniFi registration is the fallback VLAN set
to the ports' current VLAN, with EasyEAP sending no VLAN: rejected and 802.1X-less devices land where they were.
To **enforce**, set the Fallback VLAN to a restricted network (internet only, or nothing), because rejected devices
land there too, and reconnect devices so they re-authenticate. Back to monitor mode: set it back.

### Not verified on UniFi hardware

EasyEAP's tests haven't run against a UniFi switch. Unverified: whether UniFi switches accept CoA (leave CoA off),
how often they re-authenticate, and which `NAS-Port-Type` they send. If a UniFi switch sends no port type, EasyEAP
counts a request with no SSID as wired. Check the first requests' **Network** column says Wired.

