# Switch audit (SNMP)

EasyEAP can read a Cisco Catalyst switch's own view of its ports and 802.1X/MAB sessions over SNMP, read-only, and
compare it with what EasyEAP decided and sent. Where they differ you get a **finding**: a port the plan protects that
isn't protected, a device the switch authorized that EasyEAP never accepted, a session in the wrong VLAN, a device that
kept its access after EasyEAP revoked it. Findings are evidence only: nothing here changes the switch or a RADIUS
decision.

The console has the same steps with your values filled in: **RADIUS → Switches →** a switch **→ Switch audit**. Where
this page and the console differ, the console is current.

> **Not yet verified on switch hardware.** The audit is tested end to end against net-snmp's SNMP agent (its own,
> independent SNMPv3 implementation) serving a Catalyst-like set of tables, not against a real Catalyst. Which IOS-XE
> releases implement the 802.1X tables over SNMP isn't documented by Cisco for every release: EasyEAP checks, and says
> when a switch doesn't (see "Capability check").

## What's supported

| Switch | Audit |
|---|---|
| Cisco Catalyst (IOS-XE, classic IOS) with CISCO-AUTH-FRAMEWORK-MIB | Every check below. |
| Cisco Catalyst without it | Reachability, a replaced switch, err-disabled ports. |
| UniFi, others | No. UniFi switches publish no 802.1X MIB; a UniFi Network API audit may come later. |

## How it works

A separate container, `easyeap-collector`, polls each monitored switch every 15 minutes by default (5 to 60). It reads:

- **Ports** (IF-MIB): name, description, up/down.
- **802.1X on each port** (CISCO-AUTH-FRAMEWORK-MIB, `cafPortConfigTable`): whether the port authenticates (`auto`) or
  is forced open, and whether it lets traffic through before authentication (open access, which is what monitor mode
  uses).
- **Sessions** (`cafSessionTable` and `cafSessionMethodsInfoTable`): each device's MAC, method (802.1X or MAB),
  status, assigned VLAN, and whether the switch admitted it by itself while RADIUS was unreachable (critical
  authentication).
- **Err-disabled ports** (CISCO-ERR-DISABLE-MIB) and the cause.
- **The switch itself** (system group, ENTITY-MIB): model, IOS-XE version, serial number, and the SNMPv3 engine ID.

One switch is polled at a time per thread, at most eight at once, each poll bounded to two minutes. A switch whose poll
takes more than a minute is polled half as often, and its audit says so. A switch with more than 4,000 sessions is
read up to that many; findings for devices past the cut are left as they were.

## Set it up

You need the **radius:secrets** permission (Tenant administrator): setting up shows the SNMP credentials once.

1. **Switch audit → Set up monitoring.** Enter the switch's **management address** (EasyEAP fills in the RADIUS
   address when the switch is registered by a single address), choose the version and how often to poll.
   - **SNMPv2c** (default): EasyEAP generates a random 24-character community. It travels in clear text, so the
     configuration binds it to a read-only view of the six tables and to an ACL that allows only EasyEAP's address.
   - **SNMPv3**: authenticated and encrypted; no community crosses the network. SHA-256 with AES-128 by default
     (`auth sha-2 256` needs IOS-XE 16.10 or later; choose SHA-1 for older software). AES-256 is offered only with
     SHA-256.
2. **Paste the block** EasyEAP shows on the switch. It contains, and changes, nothing else:

   ```
   ip access-list standard EASYEAP-SNMP
    permit host <EasyEAP's address>
    deny any
   !
   snmp-server view EASYEAP-RO 1.3.6.1.2.1.1 included
   snmp-server view EASYEAP-RO 1.3.6.1.2.1.2.2.1 included
   snmp-server view EASYEAP-RO 1.3.6.1.2.1.31.1.1.1 included
   snmp-server view EASYEAP-RO 1.3.6.1.2.1.47.1.1.1.1 included
   snmp-server view EASYEAP-RO 1.3.6.1.4.1.9.9.656 included
   snmp-server view EASYEAP-RO 1.3.6.1.4.1.9.9.548 included
   snmp-server community <community> view EASYEAP-RO RO EASYEAP-SNMP
   ```

   With SNMPv3 the last line is a group and a user instead:

   ```
   snmp-server group EASYEAP v3 priv read EASYEAP-RO access EASYEAP-SNMP
   snmp-server user easyeap EASYEAP v3 auth sha-2 256 <authentication key> priv aes 128 <privacy key>
   ```

   `<EasyEAP's address>` is the address the switch sees EasyEAP's requests come from: normally the address switches
   send RADIUS to (`EASYEAP_RADIUS_ADDRESS`). If the switch reaches EasyEAP through NAT or another interface, use that.
   The credentials are filled in while the dialog is open; EasyEAP never shows them again.
3. **Test connection.** EasyEAP asks the switch for its model, version and serial number and checks which tables it
   answers. When it gets an answer, monitoring turns on and the first poll runs within a minute.

**New credentials** (Settings → Show the configuration, or generate new credentials) replace the old ones; polling
stops until the switch has the new block and the test passes. The dialog shows the lines that retire the old community
or user first.

**Change the address** (Settings) needs **radius:secrets** too: the stored community or keys go to the new address.

**Remove** (Settings → Remove) stops polling, forgets the credentials, resolves the switch's open findings, and shows
the lines that take EasyEAP's access off the switch.

## Findings

| Finding | When | Severity |
|---|---|---|
| Port not protected | A port in the switch's port plan doesn't authenticate (forced open, or no 802.1X settings) | critical when enforcing, otherwise warning |
| Port open before authentication | Enforce mode, but a planned port still lets traffic through before authentication (`access-session closed` missing) | critical |
| Authorized without EasyEAP | The switch authorized a device EasyEAP never accepted from this switch (in 180 days) | warning |
| Authorized although EasyEAP refused it | Enforce mode, and EasyEAP's latest answer for that device from this switch is a reject | critical |
| Still connected after being denied | EasyEAP accepted the device, but now would refuse it (certificate revoked, policy now denies, MAC blocked, expired or removed): the Change of Authorization didn't arrive or isn't on | warning |
| Not in the VLAN EasyEAP sent | Enforce mode, and the session's VLAN differs from the one in EasyEAP's latest accept (not checked when EasyEAP sent none, or for voice sessions) | warning |
| Admitted by MAC authentication | A MAB session on a switch EasyEAP has MAC authentication off for | warning |
| Admitted while EasyEAP was unreachable | The switch's critical authentication admitted a device | warning |
| Port err-disabled | A planned port is err-disabled, or any port for a security violation | warning |
| Sessions not readable over SNMP | The switch doesn't answer CISCO-AUTH-FRAMEWORK-MIB, so ports and sessions can't be checked | warning |
| A different switch answers | The serial number (or SNMPv3 engine ID) differs from the one recorded at the first poll | warning |
| No SNMP answer / SNMP credentials refused | The poll got no answer, or the switch refused the community or keys | warning |

Ports are matched by one spelling for every source (`Gi1/0/5`, `gi1/0/5` and `GigabitEthernet1/0/5` are the same
port). Devices are matched by MAC, and only against EasyEAP's answers to **this** switch.

**Two polls before a finding opens, two clean polls before it resolves**, so a session caught mid-authentication doesn't
raise one. SNMP failures open and resolve at once. A finding the switch didn't give evidence for is left as it was: a
failed poll doesn't resolve port findings, and a switch without the 802.1X tables gets none.

**Acknowledge** a finding with a note when it's expected (a port that's meant to be open, a VLAN the switch maps
differently). It leaves the dashboard until its details change, and stays on the switch's audit marked as
acknowledged. "A different switch answers" stays open until it's acknowledged; acknowledging it records the new serial
number.

Open findings that nobody has acknowledged appear in the dashboard's needs-action queue, one item per switch. Resolved
findings are kept for 90 days.

## Capability check

Test connection, and every poll, check whether the switch answers `cafAuthMethodRegTable` (1.3.6.1.4.1.9.9.656.1.1.2,
which lists the authentication methods on every switch that runs Cisco's authentication framework) and
`cErrDisableRecoveryInterval`. A check that needs a table the switch doesn't answer never runs. Nothing is assumed from
the model or the release.

## Readiness

With monitoring on, **Enforce** uses the switch's own session list from the latest poll (within three intervals) instead
of asking you to paste `show access-session`. You can still paste it.

## Security

- Read-only: the view covers six subtrees, and the requests are GET, GETNEXT and GETBULK.
- The community or keys are encrypted at rest with the tenant's key in OpenBao, decrypted only by the collector (and
  the API for Test connection), and never logged or returned after setup.
- The collector's UDP socket is connected to the switch's address, so the kernel drops datagrams from anyone else. An
  SNMPv3 response is believed only when its HMAC verifies, it's encrypted, and it's inside the engine's time window
  (RFC 3414); request ids are random, so an old response can't be replayed into a new request.
- The collector container holds only the application database role's password; the credentials are decrypted through
  OpenBao.
- The audit's findings never feed a RADIUS decision.

## Troubleshooting

| Symptom | Check |
|---|---|
| No SNMP answer | The address; that UDP 161 is open from EasyEAP; that the ACL permits the address the switch sees EasyEAP's requests come from (`show ip access-lists EASYEAP-SNMP` shows hits); for v2c, the community. |
| SNMP credentials refused | Paste the block again, or generate new credentials. With SNMPv3, "ignored EasyEAP's request" usually means the privacy key or algorithm differs. |
| The last poll failed: "couldn't store this poll's result" | The database was unavailable or rejected the result; the collector's log has the error. The switch is polled again at the next interval. |
| Sessions not readable over SNMP | `show snmp view` includes 1.3.6.1.4.1.9.9.656; some releases don't implement the MIB. Reachability and err-disable checks still run. |
| The collector isn't running | System health → Switch collector. On the server: `docker compose up -d easyeap-collector`, and its log: `docker compose logs easyeap-collector`. |
| Poll one switch by hand | `docker compose exec easyeap-collector python -m app.switchaudit.collector --once <switch id>` prints the result. |

Syslog from switches (allow-listed messages, shown as "the switch says") is planned next
([plan](plans/switch-audit.md) §9).
