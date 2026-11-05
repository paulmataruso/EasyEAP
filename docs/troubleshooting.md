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

## Before an attempt reaches the log

Some failures never produce an authentication event:

- **No event at all.** The controller isn't sending to EasyEAP, or EasyEAP doesn't recognise its source address.
  Check the controller's RADIUS server entry and the client address on the tenant's RADIUS screen, then
  `docker compose logs easyeap-radius` for "unknown client" lines. Check firewalls and the VPN for UDP 1812.
- **Bad shared secret.** FreeRADIUS drops the request because the Message-Authenticator doesn't verify. Rotate the
  secret in EasyEAP and paste the new one into the controller.
- **Tenant not enforceable.** A tenant without a CA, a RADIUS server certificate and at least one controller isn't
  served. The dashboard lists exactly what's missing.

## Useful commands

```sh
docker compose ps                                    # every service healthy?
docker compose logs --since 10m easyeap-radius       # agent and FreeRADIUS output (secrets are redacted)
docker compose exec easyeap-api easyeap verify-audit # audit chain intact?
```
