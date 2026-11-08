import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { TenantProvider } from '../api/tenant'
import type { DeviceSyslogResponse, LiveMessage, LiveResponse } from '../api/deviceSyslog'
import type { RadiusClient } from '../api/radius'
import type { TenantDetail } from '../api/types'
import DeviceSyslog from './DeviceSyslog'
import { DeviceSyslogPanel } from './radius/DeviceSyslog'

const tenant = (perms: string[]) => ({ id: 't1', name: 'Acme', slug: 'acme', permissions: perms }) as unknown as TenantDetail
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const at = new Date(Date.now() - 60_000).toISOString()
const msg = (id: string, seq: number, over: Partial<LiveMessage> = {}): LiveMessage => ({
  id, seq, first_at: at, last_at: at, count: 1, tag: 'DOT1X-5-FAIL', facility: 'DOT1X', mnemonic: 'FAIL', severity: 5, port: 'GigabitEthernet1/0/24',
  mac: '00051B31576E', session_id: null, subject: null, text: `Authentication failed ${id}`, notable: true, source: null, client_id: 'c1', device: 'office-sx', ...over,
})
const meta = {
  receiver: { receiving: true, listening: true, address: '172.16.0.45', port: 5514, port_514: true },
  devices: [{ id: 'c1', name: 'office-sx', vendor: 'cisco-switch', address: '172.16.0.3', sends: true, via_audit: true, addresses: [], stats: { received: 9, kept: 9 } },
    { id: 'c2', name: 'wlc', vendor: 'cisco-9800', address: '172.16.0.9', sends: false, via_audit: false, addresses: [], stats: {} }],
}

function wrap(ui: React.ReactNode, perms = ['radius:read', 'radius:write'], path = '/t/t1/syslog') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<MemoryRouter initialEntries={[path]}><QueryClientProvider client={qc}><TenantProvider tenant={tenant(perms)}>{ui}</TenantProvider></QueryClientProvider></MemoryRouter>)
}

afterEach(() => vi.unstubAllGlobals())

describe('Device syslog live view', () => {
  it('loads the newest, then adds what arrives and moves a repeat to the top', async () => {
    const calls: string[] = []
    let n = 0
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      calls.push(url)
      expect((init.headers as Record<string, string>)['X-EasyEAP-Passive']).toBe('1')
      n += 1
      const body: LiveResponse = n === 1
        ? { messages: [msg('a', 1), msg('b', 2, { tag: 'LINK-3-UPDOWN', severity: 3, notable: false, text: 'Interface Gi1/0/5 down', port: null, mac: null })], cursor: 2, reset: false, more: false, earliest: 1, ...meta }
        : n === 2 ? { messages: [msg('a', 3, { count: 2 })], cursor: 3, reset: false, more: false, earliest: 3 }
        : { messages: [], cursor: 3, reset: false, more: false, earliest: null }
      return json(200, body)
    }))
    wrap(<DeviceSyslog />)
    expect(await screen.findByText('Authentication failed a')).toBeInTheDocument()
    expect(screen.getByText(/Receiving on/)).toHaveTextContent('Receiving on 172.16.0.45 UDP 5514 and 514')
    expect(screen.getByText('1 of 2 devices sending')).toBeInTheDocument()
    expect(calls[0]).toBe('/api/tenants/t1/syslog/live?limit=200&meta=true')
    let rows = within(screen.getByRole('table', { name: 'Device syslog, newest first' })).getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('Interface Gi1/0/5 down')
    await waitFor(() => expect(calls).toContain('/api/tenants/t1/syslog/live?after=2&limit=500'), { timeout: 3000 })
    await waitFor(() => {
      rows = within(screen.getByRole('table', { name: 'Device syslog, newest first' })).getAllByRole('row').slice(1)
      expect(rows[0]).toHaveTextContent('Authentication failed a')
    })
    expect(rows[0]).toHaveTextContent('×2')
    expect(rows[0]).toHaveTextContent('00:05:1B:31:57:6E')
    expect(rows).toHaveLength(2)

    fireEvent.click(screen.getByRole('radio', { name: 'Access' }))
    expect(screen.queryByText('Interface Gi1/0/5 down')).not.toBeInTheDocument()
    expect(screen.getByText('1 of 2 messages')).toBeInTheDocument()
  })

  it('says how to start when no device sends', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { messages: [], cursor: 0, reset: false, more: false, earliest: null, ...meta,
      devices: meta.devices.map((d) => ({ ...d, sends: false })) })))
    wrap(<DeviceSyslog />)
    expect(await screen.findByText('Nothing received yet')).toBeInTheDocument()
    expect(screen.getByText(/No device sends syslog to EasyEAP yet/)).toBeInTheDocument()
  })
})

const wlc = { id: 'c9', name: 'wlc-1', vendor: 'cisco-aireos', address: '10.0.0.6', networks: ['wireless'], wired_profile: null } as unknown as RadiusClient
const panel = (over: Partial<DeviceSyslogResponse> = {}): DeviceSyslogResponse => ({
  settings: { enabled: false, addresses: [] }, via_audit: false,
  receiver: { receiving: true, listening: true, address: '172.16.0.45', port: 5514, port_514: false },
  guide: { steps: ['Management → Logs → Config.'], config: 'config logging syslog host 172.16.0.45', removal: 'config logging syslog host 172.16.0.45 delete',
    notes: ['AireOS (and the vWLC) sends syslog to UDP 514 only, and this EasyEAP server listens on 5514.', 'EasyEAP keeps messages sent from 10.0.0.6.'], can_send: false, port: 514 },
  stats: {}, recent: [], sessions: [], ...over,
})

describe('DeviceSyslogPanel', () => {
  it('warns when the controller can’t reach the port, and turns syslog on', async () => {
    const puts: unknown[] = []
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      if (init.method === 'PUT') { puts.push(JSON.parse(String(init.body))); return json(200, { settings: { enabled: true, addresses: [] } }) }
      return json(200, panel())
    }))
    wrap(<DeviceSyslogPanel client={wlc} />, undefined, '/t/t1/radius')
    expect(await screen.findByText('This device can’t reach EasyEAP’s syslog port')).toBeInTheDocument()
    expect(screen.getByText(/UDP 514 only/)).toBeInTheDocument()
    expect(screen.getByText('EasyEAP keeps messages sent from 10.0.0.6.')).toBeInTheDocument()
    expect(screen.getByLabelText('Syslog configuration')).toHaveTextContent('config logging syslog host 172.16.0.45')
    fireEvent.click(screen.getByRole('switch', { name: 'Keep syslog from this device' }))
    await waitFor(() => expect(puts).toEqual([{ enabled: true, addresses: [] }]))
  })

  it('shows a field error for a bad address', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => init.method === 'PUT'
      ? json(422, { detail: { field: 'addresses', message: '“10.0.0.0/8”: use an IPv4 or IPv6 address, or a range of at most 65,536 addresses.' } })
      : json(200, panel({ settings: { enabled: true, addresses: [] }, guide: { ...panel().guide, can_send: true } }))))
    wrap(<DeviceSyslogPanel client={wlc} />, undefined, '/t/t1/radius')
    fireEvent.change(await screen.findByLabelText(/Also sends from/), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/range of at most 65,536 addresses/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Live view' })).toHaveAttribute('href', '/t/t1/syslog?device=c9')
  })

  it('points a switch with the audit set up to the audit panel', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, panel({ via_audit: true }))))
    wrap(<DeviceSyslogPanel client={{ ...wlc, vendor: 'cisco-switch' } as RadiusClient} />, undefined, '/t/t1/radius')
    expect(await screen.findByText(/sends syslog through its switch audit/)).toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })
})
