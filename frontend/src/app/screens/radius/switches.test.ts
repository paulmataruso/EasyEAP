// Wired 802.1X in the RADIUS screen: when the Enforce dialog shows the closed-mode change, and route intents.
import { describe, expect, it } from 'vitest'
import { configAppliedState, type RadiusAgent } from '../../api/radius'
import { paths, targetPath } from '../../routes'

const agent = (over: Partial<RadiusAgent>): RadiusAgent =>
  ({ agent_id: 'radius-1', last_seen_at: '2026-11-07T00:00:00Z', config_ok: true, config_error: null, radius_running: true, ...over }) as RadiusAgent

describe('configAppliedState (Enforce shows the change only once RADIUS sends VLANs)', () => {
  it('waits until the agent runs the change', () => {
    expect(configAppliedState(agent({ tenant_config_in_sync: false }), 5_000).state).toBe('waiting')
    expect(configAppliedState(agent({ tenant_config_in_sync: true }), 5_000).state).toBe('live')
  })
  it('says when it is slow, and never calls it live on its own when the agent reports', () => {
    expect(configAppliedState(agent({ tenant_config_in_sync: false }), 95_000).state).toBe('slow')
  })
  it('falls back to 20 seconds for an agent that does not report it', () => {
    expect(configAppliedState(agent({ tenant_config_in_sync: null }), 10_000).state).toBe('waiting')
    expect(configAppliedState(agent({ tenant_config_in_sync: null }), 21_000).state).toBe('live')
  })
  it('reports a rejected configuration', () => {
    expect(configAppliedState(agent({ config_ok: false, config_error: 'freeradius -C failed' }), 5_000)).toEqual({ state: 'rejected', error: 'freeradius -C failed' })
  })
  it('waits when no agent has reported yet', () => {
    expect(configAppliedState(null, 30_000).state).toBe('waiting')
  })
})

describe('switch routes', () => {
  it('opens Add switch and selects a client', () => {
    expect(paths.radius('t-1', { add: 'switch' })).toBe('/t/t-1/radius?add=switch')
    expect(paths.radius('t-1', { client: 'c-1' })).toBe('/t/t-1/radius?client=c-1')
    expect(targetPath('t-1', 'radius:client:c-1')).toBe('/t/t-1/radius?client=c-1')
  })
})
