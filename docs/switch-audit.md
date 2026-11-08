# Switch audit (SNMP and syslog)

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
| Cisco Catalyst (IOS-XE, classic IOS 12.2(50)SE and later) with CISCO-AUTH-FRAMEWORK-MIB | Every check below. |
| Cisco Catalyst without it | Reachability, a replaced switch, err-disabled ports (classic: from 12.2(52)SE). |
| Cisco Nexus (NX-OS) | Reachability, a replaced switch, ports; err-disabled ports on the Nexus 9000. No 802.1X sessions (no CISCO-AUTH-FRAMEWORK-MIB). |
| Cisco Business (Catalyst 1200/1300, CBS, SG/SF 250–550X, CBS220) | Reachability, a replaced switch, ports. |
| Classic IOS before 12.2(50)SE, SG200, Meraki MS | No. |
| UniFi, others | No. UniFi switches publish no 802.1X MIB; a UniFi Network API audit may come later. |

The SNMP and syslog block follows the switch's family: a numbered ACL (98) and no logging discriminator on classic
IOS (Cisco links the discriminator to a memory leak there; the block says how to remove one an earlier EasyEAP block
added); an IPv4 ACL and the `network-operator` role on NX-OS, which has no SNMP views; the community limited to
EasyEAP's address on Cisco Business. SNMPv3 algorithms are chosen on IOS-XE only: classic IOS uses SHA-1 and AES-128,
Cisco Business SHA-256 and AES-128. Nexus switches (where an SNMPv3 user is also a login account) and the SG300/SF300
(DES only) use SNMPv2c. Switches that send syslog only
to UDP 514 (classic IOS before 15.2(1)E, Nexus 5000 and 3548, NX-OS before 9.3(3) on the Nexus 9000 and 3000) get the
SNMP block with a note: the audit works without syslog.

## How it works

A separate container, `easyeap-collector`, polls each monitored switch every minute by default (1 to 60; a poll is one short SNMP walk, about 0.1 s on a 24-port switch). It reads:

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
   - **SNMPv3**: authenticated and encrypted; no community crosses the network. SHA-1 with AES-128 by default
     (`auth sha … priv aes 128`), which every IOS-XE 3.x, 16.x and 17.x Catalyst accepts. SHA-256 (`auth sha-2 256`)
     is documented from IOS XE 17.10.1a and not on every Catalyst: choose it only if `snmp-server user x y v3 auth ?`
     lists `sha-2`. AES-256 is offered only with SHA-256. On IOS XE 26.1 and later, SNMPv2c communities are blocked
     unless `system mode insecure` is set: use SNMPv3 there.
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
   The credentials are filled in while the dialog is open. To see the block again later, with the credentials, open
   **Set up** on a monitored switch and choose **Fill in the credentials** (needs permission to manage RADIUS secrets;
   each showing is audited). Removing the audit also gives the removal lines with the community filled in.
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
- Syslog (below) is received by its own container, `easyeap-syslog`, which holds the same database password and nothing
  else. Messages are kept only from addresses EasyEAP has polled successfully, never open or resolve a finding, and
  can at most bring a switch's next poll forward to 30 seconds after the last.

## Troubleshooting

| Symptom | Check |
|---|---|
| No SNMP answer | The address; that UDP 161 is open from EasyEAP; that the ACL permits the address the switch sees EasyEAP's requests come from (`show ip access-lists EASYEAP-SNMP` shows hits); for v2c, the community. |
| SNMP credentials refused | Paste the block again, or generate new credentials. With SNMPv3, "ignored EasyEAP's request" usually means the privacy key or algorithm differs. |
| The last poll failed: "couldn't store this poll's result" | The database was unavailable or rejected the result; the collector's log has the error. The switch is polled again at the next interval. |
| Sessions not readable over SNMP | `show snmp view` includes 1.3.6.1.4.1.9.9.656; some releases don't implement the MIB. Reachability and err-disable checks still run. |
| The collector isn't running | System health → Switch collector. On the server: `docker compose up -d easyeap-collector`, and its log: `docker compose logs easyeap-collector`. |
| No syslog from the switch | `EASYEAP_SYSLOG_BIND` is set (the audit says when it isn't); UDP 5514 (or `EASYEAP_SYSLOG_PORT`) is open from the switch to that address; `show logging` lists the host and counts messages sent; the switch sends from the address EasyEAP polls (`logging source-interface`); the switch's latest poll succeeded. System health → Switch syslog lists the busiest addresses messages came from that aren't a monitored switch: one gateway address for everything means Docker is rewriting the source address (see `docs/DEPLOYMENT.md`). |
| The syslog receiver isn't running | System health → Switch syslog. On the server: `docker compose up -d easyeap-syslog`, and its log: `docker compose logs easyeap-syslog`. |
| Poll one switch by hand | `docker compose exec easyeap-collector python -m app.switchaudit.collector --once <switch id>` prints the result. |

## Syslog: what the switch says

With syslog, the audit also shows what the switch logs about access: 802.1X and MAB failures, security violations,
VLANs EasyEAP sent that the switch doesn't have, err-disabled and recovered ports, its RADIUS servers going dead or
alive, and configuration changes. Messages appear on the switch's audit (**What the switch says**, last 24 hours) and
under the findings for the same device or port; the API keeps 14 days (`GET …/clients/<id>/monitoring/syslog`, by port
or MAC).

Syslog isn't authenticated, so a message is **never a finding on its own**: findings come only from SNMP. An
err-disable, a failed authentication, a security violation or a configuration change brings the switch's next poll
forward, to 10 seconds after the message and 30 seconds after the last poll at the earliest, so the SNMP evidence
follows; it never polls on demand.

When the switch says one of its RADIUS servers isn't responding, the audit shows it, one notice per server. EasyEAP's
own RADIUS address (or "no RADIUS server is responding") is a warning: the switch may be admitting devices on its own
(critical authentication) or turning them away. It clears when the switch says the server is alive again, or when a
RADIUS request from that switch reaches EasyEAP, since not every switch logs the recovery.

**Turn it on** on the EasyEAP server: set `EASYEAP_SYSLOG_BIND` in `.env` to the address switches reach EasyEAP on
(normally the RADIUS address), and `EASYEAP_SYSLOG_PORT` if UDP 5514 is taken on the host; then `docker compose up -d`.
The receiver runs in its own container, `easyeap-syslog`; until the bind is set its port is published on 127.0.0.1
only. The switch configuration EasyEAP generates for IOS-XE then includes (other families: see "What's supported"):

```
logging discriminator EASYEAP facility includes SESSION_MGR|AUTHMGR|DOT1X|DOT1X_SWITCH|MAB|PM|RADIUS|SYS rate-limit 100
logging host <EasyEAP's address> transport udp port 5514 discriminator EASYEAP
```

with, as comments, `logging source-interface` and the `vrf Mgmt-vrf` form of the host line. Nothing global changes (no
`logging trap` level or timestamps). A switch set to `logging trap warnings` or lower sends only the err-disable and
RADIUS server messages; the 802.1X ones are at level 5 (notifications). To take it off the switch, the removal lines
are the same with `no` in front.

**Which messages are kept**: only those sent from the address EasyEAP polls the switch on, once a poll there has
succeeded (with the tenant's own SNMP credentials, in the last three intervals). An address two switches claim, in any
tenant, is ignored. Of those messages, only the access-related ones above are kept; the rest are counted and dropped.
User names and passwords are replaced with `<redacted>` before anything is stored. Repeats of one message (same port,
device and server) are counted in a single line per minute. Each switch may send 100 new messages a second, and each
tenant stores at most 50 MB a day (err-disable and RADIUS server messages are kept regardless); past that, messages are
dropped and counted on the switch's audit. Messages are kept for 14 days.

> **Not yet verified on switch hardware.** The message formats come from Cisco's documentation and published logs
> (IOS-XE 16 and 17, including `%RADIUS_AUDIT_MESSAGE` and `%PM-SP-…`), and the end-to-end test sends them from a
> pretend switch.
