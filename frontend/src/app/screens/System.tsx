// System health for the MSP: each EasyEAP component with the age of its data, the RADIUS agent and which tenant
// snapshots it has applied, background jobs, and backup/restore (server-side commands, not console actions).
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { Archive, Cog, Database, KeyRound, Router, Terminal } from 'lucide-react'
import { ApiError } from '../api/client'
import { useOverview } from '../api/dashboard'
import { useSession } from '../api/session'
import { useSystemHealth, type HealthCheck } from '../api/system'
import { radiusState } from '../api/types'
import { ago, fmtDateTime, plural, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Callout, Chip, CopyButton, Dl, ErrorState, HealthDot, LoadingBlock, PageHeader, Panel, SectionHeader } from '../ui'
import { fmtBytes } from './events/bytes'

const SERVICE: Record<string, { name: string; icon: ReactNode; what: string }> = {
  database: { name: 'Database', icon: <Database />, what: 'PostgreSQL: tenants, users, certificates, policy and the audit log.' },
  pki: { name: 'Certificate authority service', icon: <KeyRound />, what: 'OpenBao: holds each tenant’s issuing CA key and signs certificates.' },
  radius: { name: 'RADIUS', icon: <Router />, what: 'FreeRADIUS and its agent: authenticates devices from a local snapshot.' },
  worker: { name: 'Background worker', icon: <Cog />, what: 'Directory sync, hourly snapshot rebuilds, CRLs, renewals and retention.' },
}

function ageText(c: HealthCheck, checkedAt: number, now: Date) {
  if (c.service === 'database' || c.service === 'pki') return `Checked ${relative(new Date(checkedAt).toISOString(), new Date(Math.max(now.getTime(), checkedAt) + 1))}`
  return c.last_seen_at ? `Last heartbeat ${ago(c.last_seen_at, now)}` : 'No heartbeat recorded'
}

function Command({ label, cmd }: { label: string; cmd: string }) {
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <p className="text-[13px] font-medium">{label}</p>
        <CopyButton text={cmd} what={`${label.toLowerCase()} command`} />
      </div>
      <pre className="ee-code whitespace-pre-wrap break-all">{cmd}</pre>
    </div>
  )
}

/** Same threshold as the platform needs-action queue (dashboard.py BACKUP_MAX_AGE). */
const backupOverdue = (at: string, now: Date) => now.getTime() - new Date(at).getTime() > 7 * 864e5

export default function System() {
  const { isPlatform, me } = useSession()
  const now = useNow()
  // GET /api/system/health needs platform:read (Super Administrator, MSP Auditor); don't send a request that must fail.
  const canHealth = me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_auditor'
  const health = useSystemHealth(canHealth)
  const overview = useOverview()
  const forbidden = !canHealth || (health.error instanceof ApiError && health.error.status === 403)
  const agent = overview.data?.radius_agent
  const h = health.data
  const failing = h?.checks.filter((c) => !c.ok) ?? []

  if (!isPlatform) {
    return (
      <div>
        <PageHeader title="System health" />
        <Callout tone="neutral" title="Your MSP runs the EasyEAP servers" className="max-w-[70ch]">
          System health is available to MSP administrators. For this tenant’s RADIUS status and fail-closed deadline, see the tenant dashboard.
        </Callout>
      </div>
    )
  }

  return (
    <div>
      <PageHeader title="System health" lede={h ? `EasyEAP ${h.version} on this host. Each status shows when its data was last reported.` : 'Each status shows when its data was last reported.'} />

      <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-12 [&>*]:min-w-0">
        <div className="grid grid-cols-1 gap-5 lg:col-span-7 [&>*]:min-w-0">
        {/* Components */}
        <Panel risk={h ? (failing.length ? 'crit' : 'valid') : undefined} aria-labelledby="sys-components">
          <div className="p-5">
            <SectionHeader id="sys-components" title="Components" meta={h ? (failing.length ? `${plural(failing.length, 'component')} ${failing.length === 1 ? 'needs' : 'need'} attention` : 'All running') : undefined} />
            {forbidden ? (
              <Callout tone="neutral" title="Component health needs the Super Administrator or MSP Auditor role">
                Your role can see the RADIUS agent below but not the database, CA service or worker. Ask the MSP owner if you need this view.
              </Callout>
            ) : health.isLoading ? <LoadingBlock rows={5} label="Loading component health" />
              : health.error || !h ? <ErrorState error={health.error} onRetry={() => health.refetch()} title="System health couldn’t be loaded" />
              : (
                <ul className="ee-divide">
                  {h.checks.map((c) => {
                    const meta = SERVICE[c.service] ?? { name: c.service, icon: <Cog />, what: '' }
                    return (
                      <li key={c.service} className="flex gap-3 py-3.5 first:pt-0 last:pb-0">
                        <span className="mt-0.5 ee-ink-3 [&_svg]:size-4" aria-hidden>{meta.icon}</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                            <p className="font-medium">{meta.name}</p>
                            <HealthDot tone={c.ok ? 'valid' : 'crit'} label={c.ok ? 'Running' : 'Problem'} />
                          </div>
                          <p className="ee-small mt-0.5">{c.detail}</p>
                          <p className="ee-small ee-ink-3 mt-0.5">
                            <span title={c.last_seen_at ? fmtDateTime(c.last_seen_at) : undefined}>{ageText(c, health.dataUpdatedAt, now)}</span>
                            {meta.what && <> · {meta.what}</>}
                          </p>
                          {!c.ok && c.service === 'worker' && (
                            <p className="ee-small ee-ink-2 mt-1.5">While the worker is stopped, snapshots aren’t rebuilt, so each tenant fails closed when its snapshot reaches its maximum age. Check it on the host with <code className="ee-mono">docker compose logs easyeap-worker</code>.</p>
                          )}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              )}
          </div>
        </Panel>

        {/* Jobs */}
        {isPlatform && h && (
          <Panel risk={h.jobs.failed_24h ? 'warn' : undefined} aria-labelledby="sys-jobs">
            <div className="p-5">
              <SectionHeader id="sys-jobs" title="Background jobs" />
              <p className="text-[13px]"><span className="ee-num font-semibold">{h.jobs.queued}</span><span className="ee-ink-2"> queued · </span><span className="ee-num font-semibold">{h.jobs.failed_24h}</span><span className="ee-ink-2"> failed in the last 24 hours</span></p>
              {h.jobs.recent_failed.length > 0 ? (
                <ul className="ee-divide mt-3">
                  {h.jobs.recent_failed.map((j, i) => (
                    <li key={i} className="py-2.5 first:pt-0">
                      <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                        <span className="ee-mono text-[12.5px]">{j.kind}</span>
                        <span className="text-[12px] ee-ink-3" title={j.at ? fmtDateTime(j.at) : undefined}>{j.at ? `Failed ${ago(j.at, now)}` : 'Failure time not recorded'}</span>
                      </div>
                      <p className="ee-small ee-ink-2 mt-0.5 break-words">{j.error || 'No error message recorded.'}</p>
                    </li>
                  ))}
                </ul>
              ) : <p className="ee-small ee-ink-3 mt-2">No failed jobs on record.</p>}
              {h.jobs.queued > 0 && !h.checks.find((c) => c.service === 'worker')?.ok && (
                <p className="ee-small ee-ink-2 mt-3">Queued jobs wait until the background worker is running again.</p>
              )}
            </div>
          </Panel>
        )}

        </div>

        <div className="grid grid-cols-1 gap-5 lg:col-span-5 [&>*]:min-w-0">
        {/* RADIUS agent */}
        <Panel risk={overview.data ? (!agent || !agent.online || !agent.config_ok || radiusState(agent) === 'stopped' ? 'crit' : radiusState(agent) === 'running' ? 'valid' : undefined) : undefined} aria-labelledby="sys-agent">
          <div className="p-5">
            <SectionHeader id="sys-agent" title="RADIUS agent" actions={agent ? (agent.online ? <Chip tone="valid">Online</Chip> : <Chip tone="crit">Not reporting</Chip>) : undefined} />
            {overview.isLoading ? <LoadingBlock rows={4} label="Loading RADIUS agent" />
              : overview.error ? <ErrorState error={overview.error} onRetry={() => overview.refetch()} title="RADIUS agent status couldn’t be loaded" />
              : !agent ? (
                <Callout tone="crit" title="The RADIUS agent has never reported">Nothing can authenticate until it starts. Check it on the host with <code className="ee-mono">docker compose logs easyeap-radius</code>.</Callout>
              ) : (
                <>
                  <Dl
                    items={[
                      ['Last heartbeat', <span title={fmtDateTime(agent.last_seen_at)}>{ago(agent.last_seen_at, now)}</span>],
                      ['RADIUS process', {
                        running: <HealthDot tone="valid" label="Running" />,
                        idle: <HealthDot tone="neutral" label="Idle: starts when the first tenant is activated" />,
                        starting: <HealthDot tone="neutral" label="Starting for a newly activated tenant" />,
                        stopped: <HealthDot tone="crit" label="Stopped" />,
                      }[radiusState(agent)]],
                      ['Configuration', agent.config_ok ? <HealthDot tone="valid" label="Loaded" /> : <HealthDot tone="crit" label="Rejected" />, false],
                      ['Agent ID', <span className="ee-mono text-[12.5px]">{agent.agent_id}</span>],
                      ...(agent.config_error ? [['Configuration error', <span className="text-[var(--ee-crit-ink)]">{agent.config_error}</span>, 'wide'] as [ReactNode, ReactNode, 'wide']] : []),
                    ]}
                  />
                  <h3 className="ee-h3 mb-2 mt-5">Tenant snapshots</h3>
                  {overview.data && overview.data.tenants.length > 0 ? (
                    <ul className="ee-divide">
                      {overview.data.tenants.map((t) => {
                        const e = t.enforcement
                        const state = !e.snapshot_version ? { tone: 'neutral' as const, label: 'No snapshot yet' }
                          : e.agent_in_sync ? { tone: 'valid' as const, label: 'Applied' }
                          : { tone: 'warn' as const, label: e.agent_applied_version ? 'Older version' : 'Not loaded' }
                        return (
                          <li key={t.id} className="flex items-baseline justify-between gap-3 py-2 first:pt-0 last:pb-0 text-[13px]">
                            <span className="min-w-0">
                              <Link to={paths.dashboard(t.id)} className="block truncate underline-offset-2 hover:underline">{t.name}</Link>
                              {e.snapshot_built_at && <span className="block text-[12px] ee-ink-3" title={fmtDateTime(e.snapshot_built_at)}>Built {ago(e.snapshot_built_at, now)}</span>}
                            </span>
                            <HealthDot tone={state.tone} label={state.label} />
                          </li>
                        )
                      })}
                    </ul>
                  ) : <p className="ee-small ee-ink-2">No tenants yet.</p>}
                </>
              )}
          </div>
        </Panel>

        {/* Backup & restore */}
        <Panel risk={isPlatform && h && (!h.backup || backupOverdue(h.backup.at, now)) ? 'warn' : undefined} aria-labelledby="sys-backup">
          <div className="p-5">
            <SectionHeader id="sys-backup" title="Backup and restore" />
            {isPlatform && h?.backup && backupOverdue(h.backup.at, now) && (
              <Callout tone="warn" title={`Last backup ${ago(h.backup.at, now)}`} className="mb-4">Anything changed since then can’t be restored. Schedule the backup to run daily.</Callout>
            )}
            {isPlatform && h && (h.backup ? (
              <Dl
                className="mb-4"
                items={[
                  ['Last backup', <span title={fmtDateTime(h.backup.at)}>{ago(h.backup.at, now)}</span>],
                  ['Size', <span className="ee-num">{fmtBytes(h.backup.size)}{h.backup.encrypted ? ' · encrypted' : ''}</span>],
                  ['File', <span className="ee-mono text-[12.5px] break-all">{h.backup.file}</span>, 'wide'],
                ]}
              />
            ) : (
              <Callout tone="warn" title="No backup recorded" className="mb-4">This host has no record of a backup. Without one, losing the server means losing every tenant’s CA and issued certificates.</Callout>
            ))}
            <Callout tone="neutral" icon={<Terminal aria-hidden />} title="Server-side operations">
              Run these as root on the EasyEAP host, from the deploy directory of the installation (for example <code className="ee-mono">/opt/easyeap/deploy</code>). The console can’t run them.
            </Callout>
            <div className="mt-4 space-y-4">
              <Command label="Back up with a passphrase file" cmd="sudo ./backup.sh --passphrase-file /root/easyeap-backup.pass --out /srv/backups" />
              <Command label="Back up to a GPG recipient" cmd="sudo ./backup.sh --gpg-recipient backup@msp.example --out /srv/backups" />
              <Command label="Restore" cmd="sudo ./restore.sh --file /srv/backups/easyeap-20261105T104200Z.tar.gz.enc --passphrase-file /root/easyeap-backup.pass --yes" />
            </div>
            <ul className="ee-small ee-ink-2 mt-4 list-disc space-y-1.5 pl-5">
              <li>Backups are always encrypted and contain the OpenBao unseal key. Protect them like the CAs themselves, and copy them off the host.</li>
              <li>The CA service pauses for a few seconds during a backup. RADIUS keeps authenticating throughout.</li>
              <li>Restore replaces every tenant, certificate, CA key and setting on the host, then verifies the audit chain. Replace the file name with your backup; <code className="ee-mono">.gpg</code> backups need no passphrase file.</li>
              <li>Certificates issued after the backup aren’t in the restored database. RADIUS rejects them as unknown, so re-issue them to their users.</li>
            </ul>
            <p className="ee-small ee-ink-3 mt-3 flex items-center gap-1.5"><Archive className="size-3.5" aria-hidden />Schedule backups with cron or a systemd timer. Each run is recorded here.</p>
          </div>
        </Panel>
        </div>
      </div>
    </div>
  )
}
