# Troubleshooting authentication

Every RADIUS decision appears in the tenant's **Authentication log** with a reason in plain language, the rule that
matched and the VLAN. The dashboard's needs-action queue raises a reason once it reaches 5 rejects in 24 hours (or at
once for `snapshot_stale`). This page lists every reason code and what to do about it.

| Code | What it means | What to do |
|---|---|---|
| `unknown_ca` | The device presented a certificate from an authority this tenant's RADIUS server doesn't trust. | Re-enroll the device so it has a certificate from this tenant's issuing CA, or remove a stale certificate the device chose instead. |
| `cert_expired` | The device's certificate is past its expiry date. | Issue a new certificate from the user's page and install the package on the device. |
| `cert_revoked` | An administrator revoked this certificate. | If the device should still connect, issue it a new certificate. Revocation can't be undone. |
| `cert_unknown` | The certificate chains to the tenant's CA, but EasyEAP has no record of issuing it. | Look for certificates issued outside EasyEAP from the same CA, then re-enroll the device. |
| `identity_unauthorized` | The certificate is valid, but none of the user's directory groups has an Allow rule. | Add the user to a group with an Allow rule, or add a rule for one of their groups. Test with **Access policy → Test a user**. |
| `account_disabled` | Active Directory reports the account as disabled, locked out or deleted. | Re-enable or unlock the account in AD, then run a directory sync. |
| `policy_deny` | A Deny rule matched one of the user's groups. Deny always wins. | Review the rule in the decision trace, or remove the user from the denied group. |
| `vlan_assignment` | Authentication succeeded, but the controller couldn't put the device on the assigned VLAN. | Make sure the VLAN exists on the controller and its uplinks, and AAA override / RADIUS VLAN assignment is on for the SSID. |
| `snapshot_stale` | RADIUS's copy of the authorization data is older than the tenant's maximum age, so it denies everyone in the tenant (fail closed). | Check that the API and worker are running (System health) and that directory sync succeeds. RADIUS recovers by itself within about 15 seconds of a fresh snapshot. |
| `tls_handshake` | The device and the server couldn't complete TLS. Usually the device doesn't trust the server certificate. | Install the tenant's Root CA on the device and make sure its Wi-Fi profile names the RADIUS server name (the tenant's RADIUS screen shows it). |
| `client_timeout` | The device stopped answering midway. This often means it silently rejected the server certificate. | Same as `tls_handshake`. Also check the device's clock. |
| `network_not_enabled` | The request came from a network (Wi-Fi or wired) the controller or switch isn't registered for. | Edit it on the RADIUS screen and turn that network on, or fix the switch or controller sending it. |
| `network_unknown` | EasyEAP couldn't tell whether the request was wired or Wi-Fi: no port type, no SSID, and the client serves both. | Send `NAS-Port-Type` from the switch or controller, or register it for one network. |
| `mab_not_enabled` | A switch or controller asked EasyEAP to admit a device by its MAC address, but MAC authentication isn't on for it (or the request didn't come from a switch port). | To admit devices without 802.1X on this switch, open it on the RADIUS page and turn on MAC authentication. Wi-Fi MAC filtering isn't supported. |
| `mab_mismatch` | The MAC address the switch asked about differs from the device address it reported (`Calling-Station-Id`), so EasyEAP refused it rather than guess. | Make the switch send the device's MAC in both: `radius-server attribute 31 mac format ietf upper-case` and the default MAB user name. |
| `mab_password` | In a MAC authentication request the password must be the device's MAC address, and this one wasn't. | Remove any `mab request format` or custom MAB password settings from the switch. |
| `mac_unknown` | The device's MAC address isn't on the MAC allow list. | If it belongs on the network, allow it from **MAC allow list → Seen, not allowed**. Otherwise it stays out (or in the unknown-device VLAN). |
| `mac_disabled` | The device is on the MAC allow list but blocked. | Unblock it on the MAC allow list if it should have access again. |
| `mac_expired` | The device's allow-list entry had an expiry date that has passed. | Extend or remove the expiry. |
| `mac_group_disabled` | The device's group is turned off, so every device in it is refused. | Turn the group back on, or move the device to another group. |
| `mab_unsupported` | Older events, from before MAC authentication: a switch tried MAC Authentication Bypass. | Turn on MAC authentication for the switch, or remove `mab` from the port. |

On a switch in **monitor mode**, a reject is logged but the port stays open: the device keeps its access until the
switch enforces. Accepts in monitor mode show the VLAN EasyEAP would assign ("Not sent: monitor mode").

## Before an attempt reaches the log

Some failures never produce an authentication event:

- **No event at all.** The controller isn't sending to EasyEAP, or EasyEAP doesn't recognise its source address.
  Check the controller's RADIUS server entry and the client address on the tenant's RADIUS screen, then
  `docker compose logs easyeap-radius` for "unknown client" lines. Check firewalls and the VPN for UDP 1812.
- **Bad shared secret.** FreeRADIUS drops the request because the Message-Authenticator doesn't verify. Open the
  controller or switch on the RADIUS screen, choose **Fill in the shared secret** on its configuration and paste the
  secret again, or rotate it and paste the new one.
- **The Add switch wizard explains both.** While it waits for a switch's first request, it reads FreeRADIUS's log
  for requests dropped from an address near the switch's: an unregistered source address (with the address the
  switch actually uses), or a wrong shared secret.
- **Tenant not enforceable.** A tenant without a CA, a RADIUS server certificate and at least one controller isn't
  served. The dashboard lists exactly what's missing.
- **"Requests weren't matched to a controller."** The RADIUS screen shows this when RADIUS answered requests that
  EasyEAP couldn't tie to a registered controller. Requests are matched by the address they arrive from, then by the
  NAS-IP-Address the controller reports. Widen or correct the controller's source address. Until then its last
  request isn't shown and it can't receive a CoA disconnect.
- **"Controllers can't reach the configured RADIUS address."** `EASYEAP_RADIUS_ADDRESS` is a loopback or unspecified
  address. Set it in `deploy/.env` to the address controllers use for this server and restart the stack. The setup
  guides leave the address as a placeholder until then.
- **FreeRADIUS shows "Idle".** No tenant is active yet, so there is nothing to serve and the agent keeps FreeRADIUS
  stopped. It starts when a tenant is activated (setup's last step). For about 15 seconds after that the status reads
  "Starting" while the agent picks up the new configuration. "Not running" after that is a real fault: check the
  Configuration status on the RADIUS screen and `docker compose logs easyeap-radius`.

## What each enforcement status means

Every tenant has one enforcement status. The dashboard, the Tenants page, the tenant switcher and each user's
"Can connect" all show the same one.

| Status | Meaning | What to do |
|---|---|---|
| Enforcing | RADIUS is running, serves the tenant and has its latest snapshot. | Nothing. |
| Applying a change | A new snapshot was built under two minutes ago; RADIUS normally loads it within seconds. | Nothing, unless it turns into Update pending. |
| Update pending | RADIUS is still on an older snapshot after two minutes, so recent changes (including revocations) aren't enforced. | System health: is the RADIUS agent reporting? Any configuration error? |
| Refresh overdue | The worker is running, but the snapshot hasn't been rebuilt in over an hour. | System health → Background jobs for failures. |
| At risk | The snapshot isn't being refreshed: the worker is down, or directory data is out of date (sync failing, too old, or never run). RADIUS denies everyone when it expires; the dashboard shows when. | Start the worker, or fix the directory sync. |
| Denying everyone | No snapshot yet, or it's past its limit: RADIUS fails closed for this tenant. | As for At risk. Recovery is automatic within seconds of a fresh snapshot. |
| RADIUS stopped / not reporting / configuration rejected / not served by RADIUS | RADIUS itself can't serve the tenant. | System health and System log (source FreeRADIUS or RADIUS agent). |
| Starting | The tenant was just activated; RADIUS picks it up within about 15 seconds. | Nothing. |
| Not enforceable yet | Setup isn't finished. | The dashboard lists the steps. |
| Suspended | Suspended on purpose; nobody can connect. | Reactivate in tenant settings. |

The revocation list has its own item: it's rebuilt daily and valid for 72 hours, so under 48 hours left means
rebuilds are failing (warning), and under 12 hours is critical, because RADIUS rejects every certificate from the CA
once it expires. **PKI → Rebuild now** publishes a new one at once.

## Certificate renewal

Renewal tasks (the Windows setup file, the portal's Windows helper, the Linux script) renew certificates by
themselves from the tenant's percentage of each certificate's life (**Certificate authority → Renewal**); Windows
renews Group Policy certificates on the template's own renewal period. The dashboard raises what needs a person:

- **"N certificates should have renewed by themselves"** (overdue). The device hasn't renewed two weeks into its
  renewal window (Group Policy and renewal tasks made before 1.1.0, which don't check in: not before two weeks before
  expiry). It's switched off or away, the renewal task or Group Policy can't reach EasyEAP, or EasyEAP refused it:
  the Audit log's **Certificate renewal refused** entries give the reason (table below).
- **"N devices haven't checked in for renewal in a week"** (gone quiet). A renewal task that checks in daily stopped
  while its certificate is due: the device is off or away, can't reach EasyEAP (a proxy or firewall), or the task was
  removed. It renews by itself once it's back. Run the setup file or script again if the task is gone; revoke a
  device that's gone for good. Both items turn critical once a certificate has 14 days or less.
- **"A renewed certificate is still in use."** RADIUS accepted a certificate more than a day after the one that
  renewed it was first used. A Windows PC that kept the old certificate can do that; so can a copied key. Check the
  device, and revoke the old certificate if it isn't needed. With **Retire renewed certificates** on, EasyEAP revokes
  it by itself once it hasn't connected for 7 days.
- **"A certificate was renewed with two keys"** (conflict, critical). A renewal arrived signed by a certificate that
  another key already renewed, and that newer certificate is in use: two devices hold the same key, so it may have
  been copied. EasyEAP refuses it (`conflict`). Revoke the certificate (the revoke dialog includes the certificates
  renewed from it) and enroll the device again.
- **"N devices stopped connecting after the server certificate changed."** For 14 days after the RADIUS server
  certificate rotates, the dashboard counts devices that connected in the week before and have since had two or more
  `tls_handshake` or `client_timeout` rejects and no accept. Their Wi-Fi profile usually trusts the old server
  certificate itself rather than the tenant's CA: enroll them again. Meanwhile **Put the previous certificate back**
  on the RADIUS screen (for 14 days after the change, while that certificate names the same server and has more than
  a day left) presents the old one again and pauses automatic rotation. Turn rotation back on under **Certificate
  authority → Renewal** once those devices are enrolled again.

Refused renewals are audited once a day per certificate and reason. Renewal tasks made with 1.1.0 keep their request
after `clock`, `off`, `account` and `ca`, and ask again; after any other reason they stop asking for that certificate.

| Reason | What it means | What to do |
|---|---|---|
| `clock` | The request's time is more than 10 minutes off. | Fix the device's clock (time sync). |
| `off` | Automatic renewal of user (or device) certificates is turned off. | Turn it on under **Certificate authority → Renewal**, or give the user a new link. |
| `account` | The account is disabled, locked out or deleted in the directory. | Re-enable or unlock it in AD and run a directory sync. |
| `ca` | The issuing CA couldn't issue the new certificate, for example with less than a day left on the CA. | Check the PKI page and the dashboard's CA items. |
| `revoked` | The certificate was revoked. | Enroll the device again. |
| `expired` | The certificate expired before it renewed. | Enroll the device again. |
| `renewed` | The certificate was already renewed, or replaced by a new enrollment or by Group Policy. EasyEAP reissues an unused renewal to a new key only within 14 days of it, at most 3 times. | Nothing, if the device has the newer certificate. Otherwise enroll it again. |
| `conflict` | Another key already renewed it, and that certificate is in use. | See "A certificate was renewed with two keys" above. |
| `gpo` | A Group Policy certificate: Windows renews it through autoenrollment. | Check autoenrollment on the PC ([docs/autoenrollment.md](autoenrollment.md)). |
| `same_key` | The renewal request reused the old key. | Run the setup file or script again. |
| `request` | The certificate request isn't valid. | Run the setup file or script again. |
| `kind` | Not a user or device certificate, such as a Group Policy computer certificate. | As for `gpo`, for a Group Policy certificate; otherwise enroll the device again. |
| `missing` | The certificate's user or template no longer exists, or the tenant isn't active. | Enroll the device again. |

## Remote syslog and backups

- **"The server's certificate isn't trusted."** The syslog server's certificate isn't signed by a public CA: paste
  the CA certificate that signed it into the destination. The host name you enter must match the certificate.
- **"Connection refused" / "timed out".** Nothing is listening on that port, or a firewall blocks it. The worker
  sends from the EasyEAP host.
- **A destination keeps failing.** Messages wait in EasyEAP and are sent when it recovers (TCP and TLS). The System
  log is kept 30 days; the audit trail and authentication events follow their own retention.
- **A restore says the backup is from a newer version.** Upgrade this server to that version first.
- **A restore can't regain CA access.** The backup came from an installation without recovery keys and is more than
  32 days old. Use a more recent backup.

## Useful commands

```sh
docker compose ps                                    # every service healthy?
docker compose logs --since 10m easyeap-radius       # agent and FreeRADIUS output (secrets are redacted)
docker compose exec easyeap-api easyeap verify-audit # audit chain intact?
```

## Device administration (switch logins)

Admin logins over TACACS+ have their own log (**Device administration → Admin log**) and reasons. See
[docs/device-administration.md](device-administration.md#troubleshooting).
