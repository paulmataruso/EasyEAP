# Plan: time (NTP) from the console, and log timestamps with their date

Requested 2026-11-09. Admins set up the NTP client from the console (a module for chrony). Every log view shows a
date as well as a time. All logging must agree with NTP time.

## Why the host's clock is the one that matters

Every EasyEAP container shares the host kernel's clock, and nothing in a container may set it. PostgreSQL stamps rows
with it. So do the API (audit, sessions, certificates, Kerberos), the syslog receiver (each device message gets the
time EasyEAP *received* it) and RADIUS. If that one clock is right, every log lines up, so EasyEAP manages the host's
time daemon instead of keeping a clock of its own.

The receive-time stamp also means Device syslog lines from different devices line up even when a device's clock is
wrong. A device's own clock matters only for its own logs (`show logging`). The console suggests pointing devices at
the same servers.

## Facts the design rests on (checked; see the research notes in the commit)

- **Changing chronyd:**
  - It accepts changes (`reload sources`, `selectopts`, `add`, `allow`) only on its Unix socket, `/run/chrony/chronyd.sock`.
  - Over UDP it answers reads only; writes get "501 Not authorised".
  - On Ubuntu the directory is `_chrony` 0700 (systemd RuntimeDirectory).
  - chronyc makes its own reply socket in the same directory, so the mount is read-write.
  - Ubuntu's AppArmor profile for chronyd lets it reply only under `/run/chrony`, so the container path is the same.
- **Sources files:**
  - `sourcedir /etc/chrony/sources.d` is in Ubuntu's and Debian's chrony.conf, and files there hold `server`, `pool`
    and `peer` lines only.
  - `chronyc reload sources` adds and removes their sources and keeps unchanged ones. A changed source is re-added.
  - The files are read again when chronyd starts, so EasyEAP's servers last through a host reboot or an EasyEAP outage.
- **`selectopts <IP> +noselect`** (chrony 4.4 and later):
  - It keeps a source configured but unused, and it changes the source's configured options too, so EasyEAP records
    which sources it switched off itself.
  - It takes an IP, not a name, and it is lost when chronyd restarts or a pool replaces an address.
  - So the service re-applies it every 10 seconds.
  - A change applies "in the next source selection, e.g. when a new measurement is made, or the reselect command is
    executed" (chronyc docs). On a settled host the next measurement can be 17 minutes away, so the service runs
    `reselect` after every selectopts change and every reload. Seen on the demo before that: the removed pool server
    stayed the reference, and the host's servers stayed "N", for more than 5 minutes.
  - After `reselect` the chosen source still "waits for a new measurement" (state `U`). So the sources switched back
    on also get `burst 1/4 <IP>` (one good measurement, at most four requests), then return to normal polling. On the
    demo the reference moved within seconds (chronyc 4.6.1 → chronyd 4.8).
- **NTS on the host:** Ubuntu 26.04's own servers use NTS. With `authselectmode mix` (the default), authenticated
  sources get `trust` and `require`, so a source without NTS is used only where it agrees with them (selectdata `T`:
  "does not fully agree with sources that have the trust option"). Switched-off sources don't count either way ("Sources
  specified with the noselect option are ignored"), so with "Use only these servers" plain NTP servers work.
- **`prefer`:** Ubuntu's pools carry it. If any selectable source has `prefer`, chronyd uses no other source while
  one of those is usable. The admin's servers would never be used unless the host's own servers are switched off,
  hence "Use only these servers", which the console turns on by default.
- **Versions:**
  - Debian 13's chronyc 4.6.1 (the API image) works against Ubuntu 26.04's chronyd 4.8, read and write.
    Tested: tracking, sources, sources -N, selectdata, authdata, reload sources, selectopts.
  - `add` changed in 4.8, so EasyEAP doesn't use it.
- **Access:**
  - Root with only CAP_DAC_OVERRIDE reaches the socket. Root with no capabilities, or uid 10001, doesn't.
  - Docker's default AppArmor profile allows it. SELinux hosts need `label=disable`.
- **A missing `/run/chrony`:**
  - Docker's short volume syntax creates a missing host path as root 0755.
  - systemd re-owns and re-modes an existing RuntimeDirectory when chrony starts (systemd.exec(5)), so a
    Docker-created directory can't break a later chrony install.
  - On `systemctl stop`/`start` (not `restart`) the directory is removed and made again, so the container's mount goes
    stale. The service exits when it loses the socket, and Docker restarts it with a fresh mount.
- **Kernel state:** `adjtimex(modes=0)` needs no privilege. systemd calls the clock synchronised when
  `maxerror < 16 s`, whatever daemon keeps it. That covers hosts with systemd-timesyncd, where EasyEAP can only measure.
- **SNTP check** (RFC 5905 §8):
  - offset ((T2−T1)+(T3−T4))/2 and delay (T4−T1)−(T3−T2);
  - a random transmit timestamp, which the reply must echo;
  - the reply is refused for mode ≠ 4, stratum 0 (kiss code), LI = 3 or stratum > 15.

## Design

### Service `easyeap-time` (the API image, `entrypoint.sh time` → `python -m app.timesync.service`)

- **Container:**
  - root with `cap_drop: ALL` and `cap_add: DAC_OVERRIDE`; `no-new-privileges`, `label=disable`;
  - networks `data` (database) and `egress` (NTP checks);
  - mounts:
    - `/run/chrony:/run/chrony`;
    - `/etc/chrony/sources.d:/etc/chrony/sources.d`;
    - the secrets volume, read-only (to notice a restore).
- **Every 10 seconds, with chrony:**
  1. **Settings to file:** write `easyeap.sources` from the settings (temporary file, then rename) when its text
     differs, then `reload sources`. With no servers the file is removed.
  2. **Mapping:** map addresses to configured names (`sources -a` and `sources -a -N`, same order). EasyEAP's sources
     are those whose name is one of its servers or pools. When none appears after a reload, chronyd doesn't read the
     directory; the status says so.
  3. **Only these:** with "use only these servers", each host source with an IP address that isn't noselected gets
     `selectopts +noselect`, but only while one of EasyEAP's sources is reachable (reach ≠ 0). Otherwise the host's
     servers keep the clock until one answers, so nobody locks themselves out of time. Turning it off, or losing all
     of EasyEAP's servers, reverses exactly the sources EasyEAP switched off (recorded in the status).
  4. **Report:** tracking, sources, selectdata and authdata (NTS).
- **Without chrony (no socket):**
  - an SNTP check of each configured server every 5 minutes, plus the kernel's synchronised state;
  - EasyEAP measures but can't steer, and the status explains why.
  - The service exits hourly so Docker re-mounts `/run/chrony`, which picks up chrony installed later.
- **Reporting:**
  - It writes `platform_settings['time_status']` every 30 seconds and right after a change.
  - Transitions go to the system log, which reaches remote syslog: unsynchronised, offset past 100 ms or 1 s,
    settings not applied, and recoveries.

### API (`/api/system/time`)
- `GET`: settings, status, the API's `now` (the console compares it with the browser clock) and thresholds.
  Needs platform:read.
- `PUT`: servers (at most 8: an address or name; server or pool; iburst, NTS, prefer) and `only_these`. Needs
  platform:write and is audited as `system.time_updated` with the directives.
- `POST /test`: one SNTP query from the API container, rate limited.

### Health
`/system/health` gains `time`:
- warn when the service is silent for 3 minutes;
- crit when the clock isn't synchronised or is off by 1 s or more;
- warn at 100 ms, or when the settings couldn't be applied.

### Console
- **System → Time panel:**
  - status (synchronised to what, stratum, offset, last update), EasyEAP's servers with their state (in use,
    combined, not reachable, not preferred, NTS), and the host's other servers (switched off or in use);
  - "Edit servers" dialog with a per-row Test;
  - a browser clock check;
  - a "Your devices" disclosure with Cisco IOS/IOS-XE lines: `ntp server <x> [prefer] [iburst]` and
    `service timestamps log datetime msec localtime show-timezone`, from the Basic System Management Command Reference.
- **Log views:**
  - a date and time to the second (`fmtStamp`), with the zone named in the column, in Device syslog, the system log,
    the Admin log, the policy publish status and EventTable when not grouped by day;
  - grouped lists keep a day header.

## Not in scope
- Serving NTP to devices (`allow`): a runtime `allow` is lost on restart, and it opens UDP 123 on the host.
- UniFi and Meraki steps: no official documentation was found for UniFi's NTP setting, and Meraki MS switches can't be set.
- Parsing a device's own timestamp to show its clock skew.
