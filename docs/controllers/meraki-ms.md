# Cisco Meraki MS switches (wired 802.1X)

Meraki switches are configured in the Meraki Dashboard, so EasyEAP gives Dashboard steps instead of a configuration.
Add the switch from the tenant's **RADIUS** screen: **Add → Switch → Meraki MS**, with the switch's management (LAN) IP
as its address (or its Alternate Management Interface IP, if you set one): that's where its RADIUS requests come from.
A range covers several switches.

**Not verified on Meraki hardware.** The steps follow Meraki's "MS Switch Access Policies (802.1X)" and "Change of
Authorization with RADIUS (CoA) on MS" articles (research notes, [plan](../plans/cisco-platforms.md) §6.5).

## Monitor mode

| Model | Monitor mode |
|---|---|
| MS130 or MS150 on MS 18 or later | The access policy's **Authentication mode: Open**, with a pre-authentication policy that allows everything. Devices keep their access whatever EasyEAP answers. |
| Every other MS | No open mode. EasyEAP monitors **from its own side**: with **Hybrid authentication**, a device that fails 802.1X, or doesn't start it within 8 seconds, falls back to its MAC address, and EasyEAP accepts every MAC request from the switch (no VLAN) while it's in monitor mode, logging what it would decide. MAC authentication is always on. |

In both cases the access policy's **critical VLAN** is the ports' own VLAN during monitor mode, so an EasyEAP outage
closes nothing. Meraki MS (other than the MS390) offers no critical VLAN on **Multi-Auth** ports: choose Multi-Host or
Single-Host where devices must keep working while EasyEAP is unreachable.

## The access policy

1. Switching → Configure → Access policies → Add an access policy, named EasyEAP.
2. RADIUS server: EasyEAP's address, port 1812, the shared secret. **RADIUS testing: off** (Meraki tests with the user
   `meraki_8021x_test`, which EasyEAP refuses).
3. RADIUS accounting: on, port 1813, the same secret.
4. **RADIUS CoA support: off.** Meraki needs a session ID in each answer that EasyEAP doesn't send yet, so revoking a
   certificate doesn't end a Meraki port's session; the device is refused at its next authentication.
5. Host mode from the port plan. Access policy type: **Hybrid authentication** (802.1X, then the MAC address).
6. Critical VLAN: the ports' VLAN. Guest and failed-authentication VLANs: empty for now.
7. Switch ports: set the access policy on **one test port** first, plug in a device with an EasyEAP certificate, and
   watch for its first request on the switch's panel. Then more ports.

**Enforce**: MS130/MS150 switch the policy to **Closed**; other models set the critical VLAN the plan chose. EasyEAP
stops accepting MAC requests it would refuse, and sends VLANs. Cycle the ports (Disabled, then Enabled) so devices
re-authenticate.

## What isn't available on Meraki

No admin logins over TACACS+, no switch audit (Meraki exposes no 802.1X data over SNMP), and no CoA (above). EasyEAP
doesn't require Message-Authenticator from Meraki switches; requests carrying Proxy-State without it are still
dropped.

## Syslog

Meraki switches can send their event log: Dashboard → Network-wide → General → Reporting → Syslog servers → Add a
syslog server, EasyEAP's address and port 5514, role Switch event log. Then, in **RADIUS**, select the switch, then
**Syslog from …** → **Keep syslog from this device**. Each switch sends from its own address. Messages appear live in
Investigate → Device syslog; EasyEAP doesn't decode Meraki's format into sessions yet.
