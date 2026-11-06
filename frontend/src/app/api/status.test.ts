import { describe, expect, it } from 'vitest'
import { radiusSummary, snapshotState, type AgentStatus, type Enforcement } from './types'

const agent = (over: Partial<AgentStatus> = {}): AgentStatus => ({
  agent_id: 'radius-1', last_seen_at: '2026-11-06T09:00:00Z', config_ok: true, config_error: null, radius_running: true, state: 'running',
  snapshot_versions: {}, config_version: 'v', online: true, detail: null, ...over,
})

const enf = (over: Partial<Enforcement> = {}): Enforcement => ({
  enforceable: true, missing: [], snapshot_built_at: '2026-11-06T08:00:00Z', snapshot_version: 7, deadline_at: '2026-11-07T08:00:00Z',
  max_snapshot_age_seconds: 86_400, auto_refresh: true, refresh_blocked_by: null, refresh_overdue: false, directory_fresh: true, worker_alive: true,
  worker_seen_at: null, agent_online: true, radius_state: 'running', config_ok: true, served: true, snapshot_expired: false,
  agent_applied_version: 7, agent_in_sync: true, applying: false,
  status: { state: 'enforcing', tone: 'valid', label: 'Enforcing', detail: '' }, ...over,
})

describe('radiusSummary', () => {
  it('treats idle and starting as by design, and every real fault as critical', () => {
    expect(radiusSummary(agent())).toMatchObject({ tone: 'valid', short: 'Running' })
    expect(radiusSummary(agent({ state: 'idle', radius_running: false }))).toMatchObject({ tone: 'neutral', short: 'Idle' })
    expect(radiusSummary(agent({ state: 'starting', radius_running: false }))).toMatchObject({ tone: 'neutral', short: 'Starting' })
    expect(radiusSummary(agent({ state: 'stopped', radius_running: false }))).toMatchObject({ tone: 'crit', short: 'Stopped' })
    expect(radiusSummary(agent({ config_ok: false }))).toMatchObject({ tone: 'crit', short: 'Configuration rejected' })
    expect(radiusSummary(agent({ online: false }))).toMatchObject({ tone: 'crit', short: 'Not reporting' })
    expect(radiusSummary(null)).toMatchObject({ tone: 'crit', short: 'Never reported' })
  })
})

describe('snapshotState', () => {
  it('says Applied only when RADIUS can actually use the snapshot', () => {
    expect(snapshotState({ status: 'active', enforcement: enf() })).toEqual({ tone: 'valid', label: 'Applied' })
    expect(snapshotState({ status: 'active', enforcement: enf({ radius_state: 'stopped' }) }).tone).toBe('neutral')
    expect(snapshotState({ status: 'active', enforcement: enf({ snapshot_expired: true }) }).tone).toBe('crit')
    expect(snapshotState({ status: 'active', enforcement: enf({ served: false }) }).label).toBe('Not in RADIUS configuration')
  })

  it('gives a fresh change time to apply, then warns', () => {
    expect(snapshotState({ status: 'active', enforcement: enf({ agent_in_sync: false, applying: true }) })).toEqual({ tone: 'neutral', label: 'Applying' })
    expect(snapshotState({ status: 'active', enforcement: enf({ agent_in_sync: false }) })).toEqual({ tone: 'warn', label: 'Older version' })
  })

  it('does not call setup or suspended tenants a fault', () => {
    expect(snapshotState({ status: 'setup', enforcement: enf({ snapshot_version: null }) }).tone).toBe('neutral')
    expect(snapshotState({ status: 'suspended', enforcement: enf() }).label).toMatch(/suspended/)
  })
})
