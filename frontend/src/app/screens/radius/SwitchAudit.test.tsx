import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TenantProvider } from '../../api/tenant'
import type { RadiusClient } from '../../api/radius'
import type { MonitoringResponse, RadiusDown, SyslogLine } from '../../api/switchAudit'
import type { TenantDetail } from '../../api/types'
import { SwitchAuditPanel } from './SwitchAudit'

const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions: ['radius:read'] } as unknown as TenantDetail
const sw = { id: 'c1', name: 'sw1', vendor: 'cisco-switch', address: '192.0.2.10', networks: ['wired'], wired_profile: null } as unknown as RadiusClient
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const at = new Date(Date.now() - 2 * 60_000).toISOString()

const line = (over: Partial<SyslogLine>): SyslogLine => ({
  id: 'l1', first_at: at, last_at: at, count: 1, tag: 'DOT1X-5-FAIL', severity: 5, port: null, mac: null, session_id: null, subject: null,
  text: 'Authentication failed', ...over,
})
const down = (over: Partial<RadiusDown>): RadiusDown => ({
  ...line({ tag: 'RADIUS-4-RADIUS_DEAD', severity: 4, text: 'RADIUS server 192.0.2.1:1812,1813 is not responding.' }),
  server: '192.0.2.1', ours: true, ...over,
})

function response(syslog: Partial<NonNullable<MonitoringResponse['syslog']>>): MonitoringResponse {
  return {
    monitoring: { enabled: true, host: '192.0.2.10', port: 161, version: 'v2c', user: 'easyeap', auth: 'sha256', priv: 'aes128', interval_minutes: 15,
      credentials_set: true, credentials_set_at: at, pinned: null, set_up: true },
    default_host: '192.0.2.10', state: null, findings: [], pending: 0, resolved: [], config: null, removal: null, source_address: '192.0.2.1',
    collector: { alive: true, last_seen_at: at }, poll_requested_at: null,
    syslog: { receiving: true, listening: true, address: '192.0.2.1', port: 5514, stats: {}, recent: [], radius_down: [], ...syslog },
  }
}

function show(r: MonitoringResponse) {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => url === '/api/tenants/t1/radius/clients/c1/monitoring' ? json(200, r) : json(404, { detail: 'not found' })))
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><TenantProvider tenant={tenant}><SwitchAuditPanel client={sw} /></TenantProvider></QueryClientProvider>)
}

afterEach(() => vi.unstubAllGlobals())

describe('SwitchAuditPanel syslog', () => {
  it('warns once per RADIUS server the switch says is down, more strongly for EasyEAP’s', async () => {
    show(response({ radius_down: [down({ id: 'a' }), down({ id: 'b', server: '10.0.0.9', ours: false, text: 'RADIUS server 10.0.0.9:1812,1813 is not responding.' })] }))
    expect(await screen.findByText('The switch says EasyEAP’s RADIUS server isn’t responding')).toBeInTheDocument()
    expect(screen.getByText('The switch says RADIUS server 10.0.0.9 isn’t responding')).toBeInTheDocument()
    expect(screen.getByText(/It isn’t EasyEAP’s address/)).toBeInTheDocument()
  })

  it('says when the receiver is down, and where the switch should send', async () => {
    show(response({ listening: false }))
    fireEvent.click(await screen.findByRole('button', { name: /What the switch says/ }))
    expect(screen.getByText('The syslog receiver isn’t running')).toBeInTheDocument()
    expect(screen.queryByText(/Nothing from this switch yet/)).not.toBeInTheDocument()
  })

  it('shows the destination and what it keeps before the first message, then the messages', async () => {
    show(response({}))
    fireEvent.click(await screen.findByRole('button', { name: 'What the switch says (0)' }))
    expect(screen.getByText(/Nothing from this switch yet/)).toBeInTheDocument()
    expect(screen.getByText(/on UDP port 5514/)).toBeInTheDocument()
  })

  it('lists the coalesced messages', async () => {
    show(response({ stats: { last_at: at, last_tag: 'DOT1X-5-FAIL', kept: 3 }, recent: [line({ count: 3, port: 'GigabitEthernet1/0/5', mac: '020000001103' })] }))
    fireEvent.click(await screen.findByRole('button', { name: 'What the switch says (1)' }))
    expect(screen.getByText(/Today: 3 kept/)).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'What the switch says' })
    expect(list).toHaveTextContent('DOT1X-5-FAIL ×3')
    expect(list).toHaveTextContent('02:00:00:00:11:03')
  })
})
