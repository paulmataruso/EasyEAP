# Plan: console backup and restore, restore-on-first-run, remote syslog, status audit

Requested 2026-11-06. The console must do a **full** backup and restore with no command line. A fresh instance offers
"Set up new" or "Restore from backup", and restoring needs only the backup file and its passphrase. Audit and system
logs go to remote syslog. Every status chip must tell the truth. Also in scope: centre the sign-in logo, and make
sign-out return to the sign-in screen.

## What exists today (and why the console can't do it)

- `deploy/backup.sh` stops OpenBao and tars its volume. It also copies the API secrets volume, `deploy/secrets` (which
  holds the OpenBao seal key) and `.env`, runs `pg_dump` inside the DB container, then encrypts the lot with
  `openssl enc -aes-256-cbc` (no authentication). `restore.sh` reverses this with `docker compose down`/`up`.
- Both scripts need the Docker CLI on the host. The API container has neither Docker access (and must not get it:
  the Docker socket is root on the host) nor a usable `pg_dump` (Debian ships client 17, but the server is 18 and
  `pg_dump` refuses newer servers).
- OpenBao uses the **static seal**. The key comes from a Docker secret file, so it is fixed at install time. A backup
  from another install can only be opened if OpenBao runs with *that* install's key, so a console restore must be
  able to swap the key.
- **Bug found:** `pki/openbao.py` reads `recovery_keys_b64`, but OpenBao returns `recovery_keys_base64`. Every
  install so far threw its recovery keys away. Without them, nobody can mint a new OpenBao admin token. The API's
  token is periodic (32 days) and renewed every 12 hours, so **a backup older than about 32 days would restore with
  an expired token and a locked PKI**. That is true of today's scripts too.

## Design

### 1. PKI supervisor (no Docker socket)
The PKI container's entrypoint becomes `deploy/openbao/supervisor.sh`, a short POSIX `sh` script:

- It runs `bao server` as the `openbao` user (`su-exec`), just like the stock entrypoint does.
- It watches a request directory on a new **tmpfs** volume, `easyeap-control`, shared only by the API and the PKI.
- **snapshot:** stop OpenBao cleanly, tar the storage and the seal key into the control volume, start OpenBao and
  wait until it is unsealed.
- **restore:** check the tar holds only `file/` and `seal/unseal.key`, with no absolute or `..` paths. Move the
  current storage and key to a rollback area, unpack, start, and wait up to 60 s for an unsealed OpenBao. If it
  doesn't come up, roll back automatically.
- **rollback** and **commit:** used by the API when a later restore step fails, or once it succeeds.
- The seal key moves to the new `easyeap-pki-seal` volume. On first start it is seeded from the existing Docker
  secret, so existing installs carry on with the same key and no manual step.

### 2. Backup bundle (`.easyeap`)
- The bundle is an uncompressed tar holding:
  - `easyeap-backup.json`: plain metadata (format, product version, created time, source host). It holds no
    secrets.
  - `key.age`: a fresh X25519 age identity, encrypted with the passphrase (age scrypt).
  - `manifest.json.age`, `secrets.tar.age`, `pki.tar.age` and `database.dump.age`: each component, stream-encrypted
    to that identity with `pyrage`, a maintained binding to `rage`.
- Only standard age is used: no home-grown cryptography, authenticated encryption, memory-hard passphrase
  derivation, and streaming, so a multi-GB database never sits in memory.
- `pg_dump` output is encrypted as it streams, so it never touches disk in plaintext. The OpenBao tar exists in
  plaintext only on the tmpfs control volume, for seconds.
- The manifest holds per-component SHA-256 digests (of the plaintext), the schema revision, the OpenBao version,
  tenant names and counts, and the PKI recovery method: recovery keys, or "token only, restore before <date>".
- Order: renew the OpenBao token, dump the DB, then snapshot the PKI. A certificate issued in between can only end up
  in the PKI without a database row. That is harmless: RADIUS accepts only serials the database knows. The reverse
  ordering would leave database rows that OpenBao can't revoke.

### 3. Restore engine (API process, maintenance mode)
- **Upload:** the file streams to the API's backup volume. nginx gets a dedicated location with a large body
  limit, no request buffering and long timeouts. Authorization is checked **before** the body is read: an owner
  session, or the setup token on first run.
- **Inspect** (needs the passphrase): decrypt the key and the manifest, then return a summary. Refuse backups from a
  newer EasyEAP schema or OpenBao version. A wrong passphrase gives a plain error.
- **Start:** an owner restoring a running system re-enters their password, plus a two-factor code if they use one,
  and types `RESTORE`. A first-run restore needs the setup token. The passphrase is sent again; the server never
  keeps it.
- **Steps**, each recorded in `/var/lib/easyeap/secrets/restore-state.json`:
  1. Enter maintenance mode. `/api/*` answers 503 with progress, the worker pauses, and RADIUS keeps
     authenticating from local data.
  2. Verify the whole database dump: decrypt it, hash it and compare with the manifest before anything is changed.
  3. Restore the PKI (supervisor `restore`, which rolls itself back on failure).
  4. Database: terminate sessions, rename `easyeap` to `easyeap_pre_restore`, create a new database and
     `pg_restore` from the decrypting stream, then `alembic upgrade head` for older backups.
  5. Secrets: install the backup's OpenBao token, keeping the old ones for rollback.
  6. Check the PKI token. If it has expired and recovery keys exist, mint a new API token through `generate-root`
     with the recovery keys, then revoke that root token.
  7. Verify the audit chain, and move RADIUS snapshot and config versions past any value an agent could hold (so
     no agent keeps newer local data). Recompute decisions and record a `system.backup_restored` audit event.
  8. Commit: drop the old database, `commit` the PKI, delete the rollback secrets and leave maintenance mode.
  - If any step fails, everything rolls back in reverse order, and the error is shown.
  - If the API restarts mid-restore, the entrypoint runs `easyeap restore-recover` before migrations and finishes
    the rollback from the state file.
- Sessions come from the backup, so everyone signs in again with an account from the backup.

### 4. Console UX
- **System → Backup and restore:**
  - **Create backup:** a passphrase (generated or typed, at least 12 characters) and password re-entry. A
    progress view, then **Download**. The server copy is deleted after 24 h. A backup counts as "done" for the
    health check and dashboard only once it has been downloaded.
  - **Restore from backup:** upload with a progress bar, enter the passphrase, review the summary, confirm, then a
    full-page progress view and a sign-in prompt.
- **First run:** a choice of "Set up new" or "Restore from backup". Both need the one-time setup token, which the
  installer prints; this guards against someone claiming a fresh instance on the network.
- **Maintenance:** any console page gets a full-page "Restoring backup: step n of 8" view that polls the API until
  it is done.
- **CLI:** `backup.sh` and `restore.sh` become thin wrappers around the same engine (`easyeap backup create` /
  `easyeap backup restore`), for cron and automation only.

### 5. Remote syslog
- **Destinations** (platform setting, up to 4):
  - host, port, UDP / TCP / TLS (TLS verifies the server against system CAs or a pasted CA bundle);
  - RFC 5424 or RFC 3164 headers, and a text or JSON body;
  - a facility, and the categories to send.
- **Categories:**
  - **Audit:** every row of `audit_events`. It is already scrubbed of secrets.
  - **Authentication:** every RADIUS accept and reject from `auth_events`, with its reason, user, MAC, NAS and VLAN.
  - **System:** a new `system_logs` table. A non-blocking log handler in the API and worker feeds it
    (`easyeap.*` at INFO and above, libraries at WARNING and above, after the existing redaction filter). The RADIUS
    agent ships its own and FreeRADIUS warnings and errors through `/api/agent/logs`, in bounded local buffers, so
    RADIUS never waits on the API. Retention is 30 days.
- **Delivery:** a forwarder thread in the worker reads each category past a per-destination cursor and sends in
  batches.
  - TCP and TLS use RFC 6587 octet counting (newline framing optional) and advance the cursor only after the send
    succeeds (at least once).
  - UDP is best effort.
  - A new destination starts at "now" rather than replaying history.
  - Each destination shows its delivery status and backlog on the System page, and appears in System health.
  - **Send test message** goes out from the API straight away.
- The console gets a **System log** viewer (level and source filters) on the System page.

### 6. Status audit
An independent review checks every chip, badge, tone and state label against its backend source. Each finding is
either fixed or confirmed correct. The known case: the root CA "Offline" chip describes key custody (by design), but
reads like an outage. It becomes "Key held offline" with neutral styling, and the issuing CA chip reflects real CA
validity and PKI health instead of being hard-coded.

### 7. Small fixes
- Centre the logo and wordmark on sign-in and setup.
- **Sign-out:** `signOut()` calls `queryClient.clear()` while observers are mounted. Mounted `useQuery` observers keep
  the removed `['me']` query, so the page stays up and every later request just says "sign in". The fix: set
  `me = null` first, navigate to sign-in, and remove other queries without detaching the session observer. A test
  covers it.
- Save `recovery_keys_base64` on new installs.

## Critique (round 1) and changes

| Concern | Resolution |
|---|---|
| The console can now produce an (encrypted) copy of every CA key. Today only someone with shell access can. | This is inherent to "full backup in the GUI". Limit it to the Super Administrator, require password and two-factor re-entry, set a passphrase floor, audit it (who, when, size, SHA-256 of the file), purge server copies after 24 h, and never log the passphrase. Documented in SECURITY.md as a deliberate, guarded exception. |
| The supervisor runs as root in the PKI container. | The stock OpenBao entrypoint already starts as root and drops to `openbao`; we do the same. Requests are file names matched against a strict pattern, and tar members are validated before extraction. |
| A tmpfs volume shared by two containers is unusual. | Test it on the lab. If the semantics surprise us, fall back to a normal volume and delete files immediately. |
| The seal key moving out of `deploy/secrets` changes the operator story ("back up secrets/openbao_unseal_key"). | The console backup now carries the key (encrypted). DEPLOYMENT.md explains that the passphrase is the thing to protect, and the Docker secret only seeds a new install. |
| Existing installs have no recovery keys, so a backup older than about 32 days can't regain PKI access. | No API can fix this without root. The manifest records the restore-by date, the restore screen warns, the token is renewed just before each backup, and new installs save recovery keys. Tell the user plainly. |
| A long restore running inside a request handler is fragile. | Run it in a background thread with a state file and crash recovery at startup. uvicorn runs one process, so in-memory state is safe, and the state file is the source of truth anyway. |
| Restoring an older point in time can leave an agent at the same snapshot version number with newer content. | Move versions past `unix_time()` after restore. Agents compare with `!=`, so they reload. |
| The first-run restore still needs the setup token from the installer: a CLI touchpoint. | Kept on purpose: without it, anyone who reaches a fresh instance first could take it over ("no unsecured default administrator"). The installer prints it, and the screen says where it comes from. |
| Syslog over UDP is unencrypted and can drop messages. | The default is TLS when a destination is added. UDP shows a warning. The database is the durable record, and TCP/TLS delivery is at least once. |
| Writing every log line to Postgres could get heavy. | Only INFO+ from EasyEAP code and WARNING+ from libraries, batched by a background thread, with 30-day retention. A dead database never blocks a request, because the queue is bounded and drops the oldest entries. |
| Old `.tar.gz.enc` backups. | No one has made one through the product yet (System showed "No backup recorded"). The new format replaces it, as the changelog notes. |

## Critique (round 2): failure walk-through

- **Wrong passphrase:** inspect fails before anything changes.
- **Damaged file:** age authenticates every 64 KiB chunk. Step 2 decrypts the whole database dump before step 3
  changes anything.
- **OpenBao won't unseal with the backup's key:** the supervisor rolls back on its own, and the restore stops with
  nothing changed.
- **`pg_restore` fails half-way:** drop the new database, rename `easyeap_pre_restore` back, roll the PKI back and
  restore the secrets.
- **API container killed mid-restore:** `restore-recover` at the next start rolls back from the state file.
- **Disk full while uploading:** the upload fails cleanly and the partial file is removed.
- **Restore on a fresh instance with a different hostname:** CRL/OCSP URLs in old certificates point at the old
  name. RADIUS checks revocation locally, so Wi-Fi works. The summary shows both hostnames and says to point DNS at
  the new host.
- **Console TLS certificate:** this is host configuration, not data, so it is not in the backup. Documented.

## Test plan
- **Unit:**
  - bundle round trip, wrong passphrase, tampered chunk, truncated file;
  - manifest version gates and tar member validation;
  - maintenance middleware;
  - syslog RFC 5424 and 3164 formatting and framing;
  - forwarder cursor semantics;
  - sign-out flow;
  - status helpers.
- **Lab end-to-end:**
  - back up;
  - change data (new tenant, revoke a certificate, add an admin);
  - restore and check everything is reverted;
  - issue a certificate from the restored CA;
  - verify the audit chain;
  - `eapol_test` gets Access-Accept;
  - RADIUS kept authenticating during the restore.
- **Fresh instance:** a throwaway compose project on loopback runs the first-run restore of the lab backup. Then sign
  in with the lab admin, check the PKI and run `eapol_test` against it.
- **Syslog:** a throwaway rsyslog-style receiver on UDP, TCP and TLS. Check that audit, authentication and system
  messages arrive, and that delivery catches up after an outage.
- **Regression:** backend tests, frontend tests, `tests/e2e/run.sh`, console smoke.
- **Then deploy to the demo instance.** Only proxy, API, worker and PKI are recreated, after the seal migration has
  been proven on the lab.

## Status audit findings (independent review, 2026-11-06)
Each will be verified against the code before it is fixed. Ordered by severity.
1. FreeRADIUS stopped while its agent heartbeats: "Enforcing" stays green and the queue says nothing. Add a critical
   `radius_stopped` item, and require `radius_running` and `config_ok` before showing "Enforcing".
2. An expiring CRL never reaches the queue, although `allow_expired_crl = no` means every certificate is rejected.
   Add a CRL posture item: warning under 48 h, critical under 12 h or unreadable.
3. "Directory sync is failing" is shown whenever refreshes stop, even when the worker is down. Branch on
   `refresh_blocked_by`.
4. The "Enforcing" chip contradicts its panel (denying everyone, out of sync). Derive both from one function.
   `snapshot_overdue` becomes critical past the deadline.
5. The issuing CA chip is hard-coded "Online · signs certificates". Base it on CA expiry and PKI reachability.
6. "Applied" compares versions only. Require agent online, FreeRADIUS running and the snapshot unexpired. Name
   tenants missing from the RADIUS config (the agent reports served tenant IDs).
7. An expired issuing CA is shown as a warning titled "expires within six months". Make it critical, "has expired".
8. The Tenants page shows idle RADIUS as a fault. Use `radiusState()`.
9. The tenant switcher uses a narrower health definition (`health.issues`). Use the posture queue.
10. System health:
    - every passing check is labelled "Running";
    - the "Online" chip ignores failures;
    - "configuration applied" is never compared;
    - the PKI check only tests the seal, so an expired token passes.
11. Setup and suspended tenants show a warn "Not loaded" in the snapshot list. Make it neutral, "Not served".
12. Suspension is presented as "setup". Add a separate `tenant_suspended` item with a Reactivate action.
13. "Can connect" ignores RADIUS enforcement health.
14. A stale-but-not-failed directory, or one that has never synced, is unreported. Add `directory_stale`, and stop
    sync intervals at or above the snapshot age limit.
15. The frontend shows "Update pending" with no grace; the backend allows 2 minutes. Align them.
16. Certificates: superseded ones show "Active", and the counts disagree. Add a "Renewed" marker and one definition.
17. The audit verification claims removal is detected, but tail deletions can't be. Reword it.
18. Minor:
    - an expired RADIUS server certificate shows warn text;
    - MFA "Off" is warn for owners although the queue calls it critical;
    - CoA "awaiting reply" never times out;
    - the portal's "finished on this computer" claim;
    - no warning on the root CRL;
    - `identity.enrolled` is never cleared;
    - the root "Offline" chip.
