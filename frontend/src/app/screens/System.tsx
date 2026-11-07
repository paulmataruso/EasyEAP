// System health for the MSP: each EasyEAP component with the age of its data, the RADIUS agent and which tenant
// snapshots it has applied, background jobs, and full backup and restore.
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { Cog, Database, KeyRound, Network, Router, Send } from 'lucide-react'
import { ApiError } from '../api/client'
import { useOverview } from '../api/dashboard'
import { useSession } from '../api/session'
import { useSystemHealth, type HealthCheck } from '../api/system'
import { radiusState, radiusSummary, snapshotState } from '../api/types'
import { ago, fmtDateTime, plural, relative } from '../lib/format'
import { useNow } from '../lib/useNow'
import { paths } from '../routes'
import { Callout, Chip, Dl, ErrorState, HealthDot, LoadingBlock, PageHeader, Panel, SectionHeader } from '../ui'
import { BackupPanel } from './system/BackupPanel'
import { SyslogPanel } from './system/SyslogPanel'

const SERVICE: Record<string, { name: string; icon: ReactNode; what: string }> = {
  database: { name: 'Database', icon: <Database />, what: 'PostgreSQL: tenants, users, certificates, policy and the audit log.' },
  pki: { name: 'Certificate authority service', icon: <KeyRound />, what: 'OpenBao: holds each tenant’s issuing CA key and signs certificates.' },
  radius: { name: 'RADIUS', icon: <Router />, what: 'FreeRADIUS and its agent: authenticates devices from a local snapshot.' },
  worker: { name: 'Background worker', icon: <Cog />, what: 'Directory sync, hourly snapshot rebuilds, CRLs, renewals and retention.' },
  collector: { name: 'Switch collector', icon: <Network />, what: 'Polls monitored switches over SNMP for the switch audit.' },
  syslog: { name: 'Remote syslog', icon: <Send />, what: 'Forwards the audit trail, authentication events and system log.' },
}

function ageText(c: HealthCheck, checkedAt: number, now: Date) {
  if (c.service === 'database' || c.service === 'pki') return `Checked ${relative(new Date(checkedAt).toISOString(), new Date(Math.max(now.getTime(), checkedAt) + 1))}`
  if (c.service === 'syslog') return c.last_seen_at ? `Last message sent ${ago(c.last_seen_at, now)}` : 'Nothing sent yet'
  return c.last_seen_at ? `Last heartbeat ${ago(c.last_seen_at, now)}` : 'No heartbeat recorded'
}

export default function System() {
  const { isPlatform, me } = useSession()
  const now = useNow()
  // GET /api/system/health needs platform:read (Super Administrator, MSP Auditor); don't send a request that must fail.
  const canHealth = me?.platform_role === 'platform_owner' || me?.platform_role === 'platform_auditor'
  const health = useSystemHealth(canHealth)
  const overview = useOverview()
  const forbidden = !canHealth || (health.error instanceof ApiError && health.error.status === 403)
  const agent = overview.data?.radius_agent
  const rsum = radiusSummary(agent)
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
                            <HealthDot tone={c.tone ?? (c.ok ? 'valid' : 'crit')} label={c.label ?? (c.ok ? 'Running' : 'Problem')} />
                          </div>
                          <p className="ee-small mt-0.5">{c.detail}</p>
                          <p className="ee-small ee-ink-3 mt-0.5">
                            <span title={c.last_seen_at ? fmtDateTime(c.last_seen_at) : undefined}>{ageText(c, health.dataUpdatedAt, now)}</span>
                            {meta.what && <> · {meta.what}</>}
                          </p>
                          {!c.ok && c.service === 'worker' && (
                            <p className="ee-small ee-ink-2 mt-1.5">While the worker is stopped, snapshots aren’t rebuilt, so each tenant fails closed when its snapshot reaches its maximum age. Its last messages are in the <Link to={paths.systemLog()} className="underline">System log</Link>. The worker container restarts on its own; if it stays down, the host’s <code className="ee-mono">docker compose logs easyeap-worker</code> shows why.</p>
                          )}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              )}
          </div>
        </Panel>

        <BackupPanel health={canHealth ? h : undefined} />
        {canHealth && <SyslogPanel />}

        </div>

        <div className="grid grid-cols-1 gap-5 lg:col-span-5 [&>*]:min-w-0">
        {/* RADIUS agent */}
        <Panel risk={overview.data ? (rsum.tone === 'neutral' ? undefined : rsum.tone) : undefined} aria-labelledby="sys-agent">
          <div className="p-5">
            <SectionHeader id="sys-agent" title="RADIUS agent" actions={agent ? <Chip tone={rsum.tone}>{rsum.short}</Chip> : undefined} />
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
                        const state = snapshotState(t)
                        return (
                          <li key={t.id} className="flex items-baseline justify-between gap-3 py-2 first:pt-0 last:pb-0 text-[13px]">
                            <span className="min-w-0">
                              <Link to={paths.dashboard(t.id)} className="block truncate underline-offset-2 hover:underline">{t.name}</Link>
                              {t.enforcement.snapshot_built_at && <span className="block text-[12px] ee-ink-3" title={fmtDateTime(t.enforcement.snapshot_built_at)}>Built {ago(t.enforcement.snapshot_built_at, now)}</span>}
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
      </div>
    </div>
  )
}
