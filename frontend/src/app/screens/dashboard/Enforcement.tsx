// Enforcement statement: can RADIUS enforce this tenant now, is it on the latest snapshot, and when would it fail
// closed. Separates "set up" from "enforcing" and states the deadline as a time, never as "immediately".
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ArrowRight, CircleAlert, CircleCheck, CircleX, TriangleAlert } from 'lucide-react'
import type { AgentStatus, Enforcement } from '../../api/types'
import { ago, duration, fmtDateTime, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths, targetPath } from '../../routes'
import { Chip, Panel, SectionHeader, type Tone } from '../../ui'

/** The tenant's enforcement tone, as the backend computes it for every chip and panel (posture.status_of). */
export function enforcementRisk(e: Enforcement): Tone {
  return e.status.tone
}

const statusIcon = { valid: <CircleCheck aria-hidden />, warn: <TriangleAlert aria-hidden />, crit: <CircleX aria-hidden />, neutral: <CircleAlert aria-hidden /> }

/** The tenant's enforcement status chip: the same label and tone on the dashboard, the Tenants page and anywhere else. */
export function EnforcementChip({ e }: { e: Enforcement }) {
  return <Chip tone={e.status.tone} icon={statusIcon[e.status.tone]} title={e.status.detail}>{e.status.label}</Chip>
}

function Line({ tone, children }: { tone: Tone; children: ReactNode }) {
  const icon = { valid: <CircleCheck aria-hidden />, warn: <TriangleAlert aria-hidden />, crit: <CircleX aria-hidden />, neutral: <CircleAlert aria-hidden />, gold: <CircleAlert aria-hidden /> }[tone]
  const color = { valid: 'var(--ee-valid)', warn: 'var(--ee-warn)', crit: 'var(--ee-crit-ink)', neutral: 'var(--ee-neutral)', gold: 'var(--ee-gold)' }[tone]
  const label = { valid: 'OK', warn: 'Warning', crit: 'Problem', neutral: 'Note', gold: 'Note' }[tone]
  return (
    <li className="flex gap-2.5">
      <span className="mt-[1px] shrink-0 [&_svg]:size-4" style={{ color }}>{icon}<span className="sr-only">{label}: </span></span>
      <div className="min-w-0 text-[13px] leading-[1.5]">{children}</div>
    </li>
  )
}

export function EnforcementPanel({ tid, enforcement: e, agent, className }: { tid: string; enforcement: Enforcement; agent: AgentStatus | null; className?: string }) {
  const now = useNow()
  if (e.status.state === 'suspended') {
    return (
      <Panel risk="neutral" className={className} aria-labelledby="enf-h">
        <div className="p-5">
          <SectionHeader id="enf-h" title="Enforcement" actions={<EnforcementChip e={e} />} />
          <p className="text-[13px] ee-ink-2">This tenant is suspended, so nobody here can connect. Its certificates, policy and directory settings are kept; reactivating it restores access.</p>
          <Link to={targetPath(tid, 'tenant')} className="ee-btn ee-btn-sm mt-3">Tenant settings<ArrowRight aria-hidden /></Link>
        </div>
      </Panel>
    )
  }
  if (!e.enforceable) {
    return (
      <Panel risk="neutral" className={className} aria-labelledby="enf-h">
        <div className="p-5">
          <SectionHeader id="enf-h" title="Enforcement" actions={<EnforcementChip e={e} />} />
          <p className="text-[13px] ee-ink-2">Nobody in this tenant can connect until these steps are done:</p>
          <ol className="mt-3 space-y-1">
            {e.missing.map((m, i) => (
              <li key={m.code}>
                <Link to={targetPath(tid, m.target)} className="group flex items-center gap-3 rounded-[7px] px-2 py-2 -mx-2 hover:bg-[var(--ee-hover)]">
                  <span className="ee-num grid size-5 shrink-0 place-items-center rounded-full border border-[var(--ee-line-2)] text-[12px] ee-ink-2" aria-hidden>{i + 1}</span>
                  <span className="min-w-0 flex-1 text-[13px]">{m.message}</span>
                  <ArrowRight className="size-4 shrink-0 ee-ink-3 group-hover:text-[var(--ee-ink)]" aria-hidden />
                </Link>
              </li>
            ))}
          </ol>
        </div>
      </Panel>
    )
  }

  const deadline = e.deadline_at
  const past = e.snapshot_expired || (deadline ? new Date(deadline).getTime() <= now.getTime() : false)
  const radiusLine = !e.agent_online ? (
    <Line tone="crit">
      <p className="font-medium">RADIUS agent isn’t reporting</p>
      <p className="ee-ink-2">{agent ? `Last heartbeat ${ago(agent.last_seen_at, now)}.` : 'No heartbeat has been received.'} If RADIUS is still running it keeps authenticating from its last snapshot.</p>
    </Line>
  ) : e.config_ok === false ? (
    <Line tone="crit">
      <p className="font-medium">RADIUS rejected its latest configuration</p>
      <p className="ee-ink-2">It keeps running the previous one. {agent?.config_error ? <span className="ee-mono text-[12px]">{agent.config_error.split('\n')[0]}</span> : null}</p>
    </Line>
  ) : e.radius_state === 'stopped' ? (
    <Line tone="crit">
      <p className="font-medium">FreeRADIUS isn’t running</p>
      <p className="ee-ink-2">The agent is reporting, but nobody can connect. The <Link to={paths.systemLog()} className="text-[var(--ee-ink)] underline">System log</Link> (source FreeRADIUS) shows why.</p>
    </Line>
  ) : e.radius_state === 'starting' ? (
    <Line tone="neutral">
      <p className="font-medium">RADIUS is starting for this tenant</p>
      <p className="ee-ink-2">It picks up a newly activated tenant within about 15 seconds.</p>
    </Line>
  ) : e.served === false && !e.applying ? (
    <Line tone="crit">
      <p className="font-medium">RADIUS isn’t serving this tenant</p>
      <p className="ee-ink-2">The configuration it’s running doesn’t include this tenant, so its controllers get no answer. Check <Link to={paths.system()} className="text-[var(--ee-ink)] underline">System health</Link>.</p>
    </Line>
  ) : !e.snapshot_built_at ? (
    <Line tone="valid">
      <p className="font-medium">RADIUS is running</p>
      <p className="ee-ink-2">{agent ? `Heartbeat ${ago(agent.last_seen_at, now)}.` : 'Reporting.'}</p>
    </Line>
  ) : e.agent_in_sync && e.served !== false ? (
    <Line tone="valid">
      <p className="font-medium">RADIUS is on the latest snapshot</p>
      <p className="ee-ink-2">Heartbeat {agent ? ago(agent.last_seen_at, now) : 'received'}. Policy, revocations and directory changes up to the snapshot are enforced.</p>
    </Line>
  ) : e.applying ? (
    <Line tone="neutral">
      <p className="font-medium">RADIUS is applying the latest snapshot</p>
      <p className="ee-ink-2">It was built {ago(e.snapshot_built_at, now)}; RADIUS normally loads a new one within seconds.</p>
    </Line>
  ) : (
    <Line tone="warn">
      <p className="font-medium">RADIUS hasn’t applied the latest snapshot</p>
      <p className="ee-ink-2">It’s still using an older version, so the most recent changes (including revocations) aren’t enforced yet.</p>
    </Line>
  )
  const blocked = e.refresh_blocked_by === 'worker'
    ? <>the background worker isn’t running. Check <Link to={paths.system()} className="text-[var(--ee-ink)] underline">System health</Link></>
    : <>directory data is out of date (the last successful sync is older than the limit, or sync is failing). <Link to={targetPath(tid, 'directory')} className="text-[var(--ee-ink)] underline">Check the directory sync</Link></>
  return (
    <Panel risk={e.status.tone} className={className} aria-labelledby="enf-h">
      <div className="p-5">
        <SectionHeader id="enf-h" title="Enforcement" actions={<EnforcementChip e={e} />} />
        <ul className="space-y-3">
          {radiusLine}

          {e.snapshot_built_at ? (
            <Line tone="neutral">
              <p className="font-medium">Snapshot built {ago(e.snapshot_built_at, now)}</p>
              <p className="ee-ink-2">{fmtDateTime(e.snapshot_built_at)} · valid for {duration(e.max_snapshot_age_seconds)}</p>
            </Line>
          ) : (
            <Line tone="warn">
              <p className="font-medium">No authorization snapshot has been built yet</p>
              <p className="ee-ink-2">Nobody in this tenant can connect until it’s built and RADIUS applies it. The background worker builds it after activation and after every policy or directory change.</p>
            </Line>
          )}

          {deadline && (past ? (
            <Line tone="crit">
              <p className="font-medium">RADIUS has been denying everyone since {fmtDateTime(deadline)}</p>
              <p className="ee-ink-2">The snapshot is older than its {duration(e.max_snapshot_age_seconds)} limit, so RADIUS fails closed. {e.auto_refresh ? 'The worker is running, but the rebuild hasn’t happened: check the background jobs in System health.' : <>It isn’t rebuilt because {blocked}.</>}</p>
            </Line>
          ) : !e.auto_refresh ? (
            <Line tone="crit">
              <p className="font-medium">Refreshes have stopped: RADIUS denies everyone from {fmtDateTime(deadline)}</p>
              <p className="ee-ink-2">That’s {relative(deadline, now)}. The snapshot isn’t rebuilt because {blocked}.</p>
            </Line>
          ) : e.refresh_overdue ? (
            <Line tone="warn">
              <p className="font-medium">RADIUS denies everyone from {fmtDateTime(deadline)} if refreshes stop</p>
              <p className="ee-ink-2">That’s {relative(deadline, now)}. The snapshot is normally rebuilt every hour, but this one is {duration((now.getTime() - new Date(e.snapshot_built_at!).getTime()) / 1000)} old, so the rebuild is overdue. Check the background jobs in System health.</p>
            </Line>
          ) : (
            <Line tone="neutral">
              <p className="font-medium">RADIUS denies everyone from {fmtDateTime(deadline)} if refreshes stop</p>
              <p className="ee-ink-2">That’s {relative(deadline, now)}. While the directory and worker are healthy the snapshot is rebuilt hourly, so this deadline keeps moving forward.</p>
            </Line>
          ))}
        </ul>
      </div>
    </Panel>
  )
}
