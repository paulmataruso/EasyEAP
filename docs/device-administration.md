# Device administration (TACACS+)

Network administrators log in to Cisco switches and Catalyst 9800 controllers with their **Active Directory account**
or an **EasyEAP account**. The device asks EasyEAP over TACACS+ (TCP 49), which checks the password, gives the
administrator a privilege level from their role, and records the login and the commands they run. Devices keep their
own local accounts for when EasyEAP can't be reached.

The console has the same steps with your values filled in: **Device administration** in the Configure section. This
page is the long form; where they differ, the console is current.

> **Not yet verified on Cisco hardware.** EasyEAP's TACACS+ service is tested against a protocol client that follows
> IOS's login sequence (SSH, telnet, PAP, enable, exec authorization, accounting), not against a real switch. Always
> paste with `reload in 15` and keep a session open, as the steps below say.

## What's supported

| Device | Admin logins |
|---|---|
| Cisco Catalyst switches (IOS 15.2, IOS XE) | Yes. EasyEAP generates the configuration. Older IOS images without `tacacs server` get the `tacacs-server host` form. |
| Cisco Catalyst 9800 | Yes, CLI and (not yet verified) the web UI. |
| Cisco AireOS | Not yet: it uses a different TACACS+ configuration. |
| UniFi | No. UniFi switches and gateways have no TACACS+, RADIUS or LDAP login for administrators; they're managed from UniFi Network. |
| Others (FortiGate, PAN-OS, Junos, NX-OS, Aruba) | Not yet. They need their own TACACS+ attributes. |

v1 has no command authorization: a role is a privilege level, and the device decides what each level may run.
Logins use ASCII (SSH, telnet, console) or PAP; CHAP and MS-CHAP are refused because EasyEAP needs the password.

## Before you start

1. **Publish TCP 49.** EasyEAP doesn't listen for TACACS+ on the network until you say where. In `deploy/.env` set
   `EASYEAP_TACACS_BIND` to the address your switches reach EasyEAP on (normally the same as `EASYEAP_RADIUS_ADDRESS`),
   then `docker compose up -d easyeap-radius`. `EASYEAP_TACACS_PORT` changes the published port (default 49).
2. **Keep it on the management network.** TACACS+ (RFC 8907) only obfuscates packets with the shared key: there's no
   integrity protection. Firewall TCP 49 to your devices' management addresses, and don't route it over the internet
   without a VPN.
3. **Add the devices on the RADIUS page** (Add switch, or Add controller for a 9800). Each device's address must be its
   management address (the source of its TACACS+ connections). If it uses a source interface or a VRF, set them in the
   switch's port plan; the admin configuration uses the same values.
4. **For AD logins**, the directory must use LDAPS or StartTLS **with certificate verification on**: administrators'
   passwords are sent to the domain controller, so EasyEAP refuses to send them to one it can't verify. The RADIUS
   container connects to the domain controllers itself (TCP 636, or 389 for StartTLS), so allow that too.
5. Make sure every device has a **local privilege-15 account** and an **enable secret**. They're how you log in from the
   console port, and from SSH while EasyEAP can't be reached.

## Turn on admin logins for a device

1. **Device administration → Devices**, turn on **Admin logins** for the device. EasyEAP creates a 40-character
   TACACS+ key for it and shows it **once**, already filled into the configuration. Copy the key somewhere safe.
2. Run the checks the console lists on the device first: the local account, the enable secret, no existing TACACS+ or
   AAA lists from ISE or ACS (merge those by hand), and that the device can reach EasyEAP.
3. Enter `reload in 15` in enable mode. If anything locks you out, the device reloads in 15 minutes with its saved
   configuration.
4. `configure terminal`, paste the configuration, `end`.
5. From a **new** SSH session, log in with your AD or EasyEAP account. `show privilege` shows your level. The login
   appears in EasyEAP's Admin log within a minute.
6. It works: `reload cancel`, then `write memory`. It doesn't: in the first session paste the rollback (under the
   configuration in the console), or let the reload undo it.

What the configuration does:

- `aaa authentication login default group EASYEAP-ADMIN local`: SSH and telnet ask EasyEAP; when EasyEAP doesn't answer
  (or answers ERROR, see below), the device's local accounts.
- `aaa authentication login EASYEAP-CONSOLE local` on `line con 0`: the console port always uses local accounts.
- `aaa authentication enable default group EASYEAP-ADMIN enable`: `enable` checks your password again, up to your
  role's level; the enable secret when EasyEAP doesn't answer.
- `aaa authorization exec default group EASYEAP-ADMIN local if-authenticated`: the privilege level comes from your role.
  EasyEAP only answers it for sessions it authenticated itself on that device (the device reports how it
  authenticated the session); for a login with the device's own account it answers ERROR, so the device's `local`
  method gives that account its level. The role is worked out again at this step, so an account disabled or a group
  mapping removed since the login applies straight away.
- `aaa accounting exec` and `aaa accounting commands 1` / `15`: sessions and commands go to the Admin log.

On switches that also use EasyEAP for wired 802.1X, the wired configuration stops setting `aaa authentication login
default local` once admin logins are on, so re-pasting it doesn't undo this.

Turning admin logins off makes EasyEAP stop answering the device, so it uses its local accounts. Paste the rollback to
remove the TACACS+ lines.

## Who can log in

**EasyEAP accounts** (Device administration → EasyEAP accounts) are for people who aren't in the directory, such as
contractors, or for sites without AD. Each has a username, a role, optionally sites and an expiry date.

**Directory access** lets members of AD groups log in with their AD username (`nina`, `nina@corp.example` or
`CORP\nina`) and password. EasyEAP checks the user's groups in AD itself at every login, nested groups included, so
removing someone from a group takes effect at their next login. The list is ordered: the first group that matches
decides the role. Only Active Directory groups can be used (not groups created in EasyEAP). "Who can log in" shows
whom the groups admit, from the last sync. EasyEAP only asks AD about users the last sync found in a mapped group, so
someone just added to a group can log in after the next sync (Directory → Sync now); other names are refused without
their password being sent to a domain controller.

When an EasyEAP account and a directory user have the same name, the EasyEAP account wins; the console marks the clash.

**Roles** are Cisco privilege levels. The built-ins are **Network administrator** (15: full access) and **Read-only**
(1). Levels in between need the device to assign commands to them, for example
`privilege exec level 7 show running-config`.

**Sites** limit an account or a group to devices at those sites (each device's Site on the RADIUS page). Empty means
every device.

## Passwords and authenticator codes

EasyEAP accounts follow NIST SP 800-63B: at least 15 characters (or 8 with an authenticator code), up to 128, no
composition rules, and common or predictable passwords are refused. A phrase of several words works well.

An account can also use an authenticator app (TOTP). Devices show one password field, so the code is typed straight
after the password: password `harbor-violet` and code `123456` are typed as `harbor-violet123456`. Each code works
once for a login and once for `enable` (which often follows within the same 30 seconds). AD accounts don't support
codes yet. Codes are tracked per RADIUS node, so with several nodes a code could be replayed once on another node
within its 90-second window.

## When EasyEAP can't be reached

TACACS+ has two kinds of "no": FAIL, which IOS treats as final, and ERROR, which makes it try the next method (the
local accounts). EasyEAP answers FAIL only when it really means no (wrong password, unknown name, disabled, expired,
wrong site, locked, not in a mapped group). It answers ERROR when it can't decide properly:

- the domain controllers are unreachable or too slow (3 seconds for the whole login), or too many logins for the
  same tenant are already waiting for them;
- the directory can't be used for admin logins (plain LDAP, certificate verification off, or the directory turned off);
- exec authorization for a session EasyEAP didn't authenticate (a login with the device's own account);
- the RADIUS node's copy of EasyEAP's data is older than the snapshot age limit in Access policy;
- the device's key doesn't match;
- an internal error;
- the username is a **local-only username** (below).

If the RADIUS container or TCP 49 is down, the device gets no answer at all and uses its local accounts after the
5-second timeout.

**Break-glass**: list your devices' emergency account names under **Settings → Local-only usernames**. EasyEAP always
answers ERROR for them, so the device's own account is used even while EasyEAP is up. Keep the console port local, as
the configuration does.

## Failed logins and lockouts

- Every failure is answered after the same 1-second delay, so timing doesn't reveal which names exist.
- After 3 failures for the same account from the same address, further attempts are slowed down (1, 2, 4 … up to 60
  seconds).
- EasyEAP accounts: 10 failures in 15 minutes lock the account for 15 minutes. The console shows **Locked** with an
  **Unlock** button.
- AD accounts: EasyEAP limits failed binds per account to under half the domain's lockout threshold, within the
  domain's lockout observation window (at least 30 minutes), so EasyEAP alone can't lock someone out of AD. Both are
  read from the domain's default password policy at each directory sync; until a sync has read them, one failed bind
  per account per 30 minutes. Logins in flight count towards the limit, so a burst of logins with the same account
  (a script connecting to many switches) waits its turn rather than binding all at once. The same wrong password
  typed again isn't sent to AD again for 10 minutes.
- The AD limit is per RADIUS node. The generated configuration names one EasyEAP server, so a device asks one node.
  If you add more by hand, keep it to two: two nodes' limits together stay under the threshold, three or more can
  reach it. Fine-grained password policies (PSOs) can't be read with a read-only bind account and aren't considered:
  if administrators are under a stricter PSO, its threshold is the one that matters.
- The EasyEAP-account lockout is keyed by the account, not by where attempts come from: anyone who can reach a
  device's SSH can lock a named EasyEAP account for 15 minutes with 10 wrong passwords. That is the price of stopping
  password guessing; it doesn't affect AD accounts or the devices' own accounts, and Unlock ends it early.

## Rotating a key

**Rotate key** creates a new key and shows it once. The old key keeps working for 24 hours, so you can change the
device in that time: paste `tacacs server EASYEAP-ADMIN-<TENANT>` / ` key 0 <new key>` (or the full configuration
again). Rotating again within the 24 hours ends the older key's grace.

## Admin log

Device administration → Admin log shows logins, enables, exec sessions and every command administrators run (command
accounting), with the device, the account, where they connected from, and why something was refused. Secrets in
commands (`secret`, `password` with the rest of its line, `key`, `key-string`, `community` and `snmp-server host`
communities, SNMPv3 `auth`/`priv`, `pre-shared-key`, HSRP/VRRP `authentication text`, IS-IS `area-password` and
`domain-password`, and others) are replaced with `*****` before they're stored. Masking works from a list of
commands: a secret in a command it doesn't know (another vendor's syntax) can still reach the log. Names that match no account are logged as `unknown:<hash>`, so a password
typed at the username prompt isn't kept. The log is kept for 180 days by default (30 to 730, under Settings).

## Troubleshooting

| Admin log says | What to do |
|---|---|
| No entries at all | Check `EASYEAP_TACACS_BIND`, the firewall for TCP 49, and that the device's address on the RADIUS page is the source of its TACACS+ connections (`ip tacacs source-interface`). The RADIUS container's log names addresses that aren't devices with admin logins on. |
| The device's TACACS+ key doesn't match | Paste the key again, or rotate it. `show tacacs` shows the server and its counters. |
| Not in a directory group that may log in | Add one of the user's AD groups under Directory access, or sync the directory if the group is new. |
| CHAP or MS-CHAP | The device sends CHAP: use the generated configuration (ASCII logins). |
| Domain controllers unreachable / too slow | The RADIUS container can't reach the DCs on TCP 636 (or 389 for StartTLS), or they answer slowly. The device used its local accounts. |
| The session didn't log in through EasyEAP | Normal for logins with the device's own accounts (break-glass, or while EasyEAP was unreachable): the device's `local` method gave the level. |
| The directory can't be used for admin logins | Directory settings: use LDAPS or StartTLS with certificate verification on. |
| EasyEAP's data on the RADIUS node is out of date | The RADIUS node hasn't reached the API for longer than the snapshot age limit. Check System health. |
| Not allowed at this device's site | The account's or group's sites don't include the device's site. |
| Enable level above the role's | `enable 15` with a read-only role: give the account a higher role. |
| Locked after too many failures | Check where the attempts came from, then Unlock the account. |

## Who can change it

Device administration (accounts, group mappings, roles, keys, turning admin logins on) needs the **Tenant
Administrator** role. So does changing the address, type or site of a device with admin logins on, or deleting it, on
the RADIUS page: the address decides which connections get answers and the site which administrators may log in.

The RADIUS container keeps its copy of the admin data (TACACS+ keys, password hashes, authenticator secrets) in a file
only its own user can read. FreeRADIUS runs as that same user, so anyone who can run code in the RADIUS container can
read it; treat the container (and its volume) as sensitive as the API's database.

See also [docs/plans/device-admin.md](plans/device-admin.md) for the design and the protocol details.
