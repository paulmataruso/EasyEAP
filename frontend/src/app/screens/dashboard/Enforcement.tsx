// Enforcement statement: can RADIUS enforce this tenant now, is it on the latest snapshot, and when would it fail
// closed. Separates "set up" from "enforcing" and states the deadline as a time, never as "immediately".
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ArrowRight, CircleAlert, CircleCheck, CircleX, TriangleAlert } from 'lucide-react'
import type { AgentStatus, Enforcement } from '../../api/types'
import { ago, duration, fmtDateTime, relative } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { targetPath } from '../../routes'
import { Chip, Panel, SectionHeader, type Tone } from '../../ui'

export function enforcementRisk(e: Enforcement): Tone {
  if (!e.enforceable) return 'neutral'
  if (!e.agent_online || !e.auto_refresh) return 'crit'
  if (!e.agent_in_sync || !e.snapshot_built_at) return 'warn'
  return 'valid'
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
  if (!e.enforceable) {
    return (
      <Panel risk="neutral" className={className} aria-labelledby="enf-h">
        <div className="p-5">
          <SectionHeader id="enf-h" title="Enforcement" actions={<Chip tone="neutral" icon={<CircleAlert aria-hidden />}>Not enforceable yet</Chip>} />
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
  const past = deadline ? new Date(deadline).getTime() <= now.getTime() : false
  // The worker rebuilds the snapshot hourly while the directory is healthy; a snapshot well past an hour old means
  // the rebuild is overdue (worker stopped or failing), so the deadline has stopped moving.
  const overdue = !!(e.auto_refresh && e.snapshot_built_at && now.getTime() - new Date(e.snapshot_built_at).getTime() > 75 * 60_000)
  return (
    <Panel risk={overdue && enforcementRisk(e) === 'valid' ? 'warn' : enforcementRisk(e)} className={className} aria-labelledby="enf-h">
      <div className="p-5">
        <SectionHeader
          id="enf-h"
          title="Enforcement"
          actions={!e.agent_online || !e.auto_refresh
            ? <Chip tone="crit" icon={<CircleX aria-hidden />}>At risk</Chip>
            : !e.snapshot_built_at
              ? <Chip tone="warn" icon={<TriangleAlert aria-hidden />}>Waiting for snapshot</Chip>
              : <Chip tone="valid" icon={<CircleCheck aria-hidden />}>Enforcing</Chip>}
        />
        <ul className="space-y-3">
          {!e.agent_online ? (
            <Line tone="crit">
              <p className="font-medium">RADIUS agent isn’t reporting</p>
              <p className="ee-ink-2">{agent ? `Last heartbeat ${ago(agent.last_seen_at, now)}.` : 'No heartbeat has been received.'} If RADIUS is still running it keeps authenticating from its last snapshot.</p>
            </Line>
          ) : !e.snapshot_built_at ? (
            <Line tone="valid">
              <p className="font-medium">RADIUS agent is online</p>
              <p className="ee-ink-2">{agent ? `Heartbeat ${ago(agent.last_seen_at, now)}.` : 'Reporting.'}</p>
            </Line>
          ) : e.agent_in_sync ? (
            <Line tone="valid">
              <p className="font-medium">RADIUS is on the latest snapshot</p>
              <p className="ee-ink-2">Agent online{agent && <>, heartbeat {ago(agent.last_seen_at, now)}</>}. Policy, revocations and directory changes up to the snapshot are enforced.</p>
            </Line>
          ) : (
            <Line tone="warn">
              <p className="font-medium">RADIUS hasn’t applied the latest snapshot</p>
              <p className="ee-ink-2">The agent is online but still using an older version, so the most recent changes (including revocations) aren’t enforced yet.</p>
            </Line>
          )}

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
              <p className="ee-ink-2">The snapshot is older than its {duration(e.max_snapshot_age_seconds)} limit, so RADIUS fails closed. {e.auto_refresh ? 'Check that the EasyEAP worker is running.' : 'Directory sync is failing, so it isn’t being rebuilt.'}</p>
            </Line>
          ) : e.auto_refresh && overdue ? (
            <Line tone="warn">
              <p className="font-medium">RADIUS denies everyone from {fmtDateTime(deadline)} if refreshes stop</p>
              <p className="ee-ink-2">That’s {relative(deadline, now)}. The snapshot is normally rebuilt every hour, but this one is {duration((now.getTime() - new Date(e.snapshot_built_at!).getTime()) / 1000)} old, so the rebuild is overdue. Check that the EasyEAP worker is running.</p>
            </Line>
          ) : e.auto_refresh ? (
            <Line tone="neutral">
              <p className="font-medium">RADIUS denies everyone from {fmtDateTime(deadline)} if refreshes stop</p>
              <p className="ee-ink-2">That’s {relative(deadline, now)}. While the directory is healthy the snapshot is rebuilt hourly, so this deadline keeps moving forward.</p>
            </Line>
          ) : (
            <Line tone="crit">
              <p className="font-medium">Refreshes have stopped because directory sync is failing</p>
              <p className="ee-ink-2">RADIUS denies everyone from {fmtDateTime(deadline)}, {relative(deadline, now)}. <Link to={targetPath(tid, 'directory')} className="text-[var(--ee-ink)] underline">Fix the directory connection</Link>.</p>
            </Line>
          ))}
        </ul>
      </div>
    </Panel>
  )
}
