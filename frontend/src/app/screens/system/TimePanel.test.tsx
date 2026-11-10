import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { TimeConfig, TimeSettings, TimeSource } from '../../api/time'
import { fmtOffset } from '../../api/time'
import { browserSkew, deviceConfig, sourceState, TimePanel } from './TimePanel'
import { TimeDialog } from './TimeDialog'

vi.mock('../../api/session', () => ({ useSession: () => ({ me: { platform_role: 'platform_owner' } }) }))
// The switch (Radix) measures itself; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
afterEach(() => vi.unstubAllGlobals())

const src = (over: Partial<TimeSource>): TimeSource => ({
  address: '192.0.2.10', name: null, ours: true, mode: 'server', select: 'combined', reachable: true, stratum: 2, offset: 0.0004,
  error: 0.02, last_rx: 30, authenticated: false, nts: false, noselect: false, prefer: false, resolved: true, switched_off_by_easyeap: false, ...over,
})

const settings = (over: Partial<TimeSettings> = {}): TimeSettings => ({
  servers: [{ address: 'ntp.example.net', kind: 'pool', iburst: true, nts: false, prefer: false }], only_these: false, revision: 3,
  updated_at: null, updated_by: null, ...over,
})

function config(over: Partial<TimeConfig> = {}): TimeConfig {
  return {
    settings: settings(),
    status: {
      at: new Date().toISOString(), mode: 'chrony', synchronised: true, offset: 0.00025, stratum: 3, reference: '192.0.2.1',
      reference_time: new Date().toISOString(), leap: 'normal', rms_offset: 0.0001, frequency_ppm: -27.7, root_delay: 0.06,
      root_dispersion: 0.001, update_interval: 520,
      sources: [
        src({ address: '198.51.100.10', name: 'ntp.example.net', select: 'not_preferred' }),
        src({ address: '203.0.113.1', name: '1.ntp.ubuntu.com', ours: false, select: 'best', prefer: true }),
        src({ address: '203.0.113.2', name: '2.ntp.ubuntu.com', ours: false, noselect: true, switched_off_by_easyeap: true }),
      ],
      checks: [], applied_revision: 3, apply_error: null, select_error: null, problem: null, kernel_synchronised: true,
    },
    stale: false,
    assessment: { tone: 'valid', line: 'synchronised' },
    max_servers: 8,
    now: new Date().toISOString(),
    warn_offset: 0.1,
    crit_offset: 1,
    ...over,
  }
}

function renderWith(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>)
}

describe('time helpers', () => {
  it('says what chronyd does with each source', () => {
    expect(sourceState(src({ resolved: false, address: null }))[0]).toBe('Name not resolved yet')
    expect(sourceState(src({ noselect: true, switched_off_by_easyeap: true }))[0]).toBe('Switched off by EasyEAP')
    expect(sourceState(src({ reachable: false }))).toEqual(['Not answering', 'warn'])
    expect(sourceState(src({ select: 'best' }))).toEqual(['In use: the reference', 'valid'])
    expect(sourceState(src({ select: 'falseticker' }))[1]).toBe('crit')
  })

  it('compares the browser clock with the server, ignoring the request’s own time', () => {
    const t = Date.parse('2026-11-09T12:00:00Z')
    expect(browserSkew('2026-11-09T12:00:00Z', t + 900)).toBe(0)
    expect(browserSkew('2026-11-09T12:00:00Z', t + 5000)).toBe(5)
    expect(browserSkew('2026-11-09T12:00:00Z', t - 90_000)).toBe(-90)
  })

  it('writes offsets the way people say them', () => {
    expect(fmtOffset(0.00025)).toBe('250 µs fast')
    expect(fmtOffset(-0.042)).toBe('42 ms slow')
    expect(fmtOffset(1.5)).toBe('1.50 s fast')
  })

  it('gives devices the same servers', () => {
    const cfg = deviceConfig([{ address: '192.0.2.10', kind: 'server', iburst: true, nts: false, prefer: true }])
    expect(cfg).toContain('ntp server 192.0.2.10 prefer')
    expect(cfg).toContain('service timestamps log datetime msec show-timezone')
    expect(deviceConfig([])).toContain('ntp server <your NTP server>')
  })
})

describe('TimePanel', () => {
  it('shows the reference, each source’s state, and why the servers set here go unused', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, config())))
    renderWith(<TimePanel />)
    expect(await screen.findByText('Synchronised to 192.0.2.1')).toBeInTheDocument()
    expect(screen.getByText('250 µs fast')).toBeInTheDocument()
    expect(screen.getByText('chronyd prefers the host’s own servers')).toBeInTheDocument()
    expect(screen.getByText('Switched off by EasyEAP')).toBeInTheDocument()
    expect(screen.getByText('In use: the reference')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Edit servers/ })).toBeInTheDocument()
  })

  it('says when the time service has stopped reporting', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, config({ stale: true, assessment: null }))))
    renderWith(<TimePanel />)
    expect(await screen.findByText('The time service isn’t reporting')).toBeInTheDocument()
  })

  it('without chrony, shows the measurements and why nothing is applied', async () => {
    const c = config()
    c.status = { ...c.status!, mode: 'sntp', sources: [], reference: null, problem: 'The host doesn’t run chrony.',
      checks: [{ server: 'ntp.example.net', address: '198.51.100.10', offset: -0.003, delay: 0.02, stratum: 2, error: null }] }
    c.assessment = { tone: 'warn', line: 'the host doesn’t run chrony, so EasyEAP’s NTP servers can’t be applied' }
    vi.stubGlobal('fetch', vi.fn(async () => json(200, c)))
    renderWith(<TimePanel />)
    expect(await screen.findByText('EasyEAP measures this clock but doesn’t set it')).toBeInTheDocument()
    expect(screen.getByText(/this clock 3.0 ms slow/)).toBeInTheDocument()
  })
})

describe('TimeDialog', () => {
  it('starts a first setup with “use only these servers” on and saves what was entered', async () => {
    const calls: { url: string; body: unknown }[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init.body)) })
      return json(200, { settings: settings() })
    }))
    renderWith(<TimeDialog open onOpenChange={() => {}} settings={settings({ servers: [] })} max={8} />)
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'time.cloudflare.com (NTS)' }))
    expect(screen.getByLabelText('Server 1 address')).toHaveValue('time.cloudflare.com')
    expect(screen.getByRole('switch', { name: 'Use only these servers' })).toBeChecked()
    fireEvent.click(save)
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0].url).toBe('/api/system/time')
    expect(calls[0].body).toEqual({ servers: [{ address: 'time.cloudflare.com', kind: 'server', iburst: true, nts: true, prefer: false }], only_these: true })
  })

  it('tests a server from EasyEAP and shows how far the clock is from it', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { address: '198.51.100.10', offset: 0.012, delay: 0.03, stratum: 2, leap: 0 })))
    renderWith(<TimeDialog open onOpenChange={() => {}} settings={settings()} max={8} />)
    const row = screen.getByLabelText('Server 1 address').closest('li')!
    fireEvent.click(within(row).getByRole('button', { name: /Test/ }))
    expect(await within(row).findByText(/this server’s clock is 12 ms fast, round trip 30 ms, stratum 2/)).toBeInTheDocument()
  })
})
