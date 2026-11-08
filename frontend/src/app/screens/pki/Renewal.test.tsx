import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { TenantProvider } from '../../api/tenant'
import type { RenewalOverview } from '../../api/renewal'
import { derivedDays, renewAfterDays } from '../../api/renewal'
import type { RadiusSettings } from '../../api/radius'
import type { TenantDetail } from '../../api/types'
import { ServerCertificateCard } from '../radius/Settings'
import { RenewalPanel } from './Renewal'

const tenant = (perms: string[]) => ({ id: 't1', name: 'Acme', slug: 'acme', permissions: perms }) as unknown as TenantDetail
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const day = 864e5
const iso = (ms: number) => new Date(Date.now() + ms).toISOString()

const overview = (over: Partial<RenewalOverview['settings']> = {}): RenewalOverview => ({
  settings: { user_certs: true, machine_certs: true, server_cert: true, renew_at_percent: 80, updated_at: null, updated_by: null, ...over },
  limits: { min_percent: 50, max_percent: 90, rollback_days: 14 },
  templates: [
    { id: 'a', name: 'User Wi-Fi', purpose: 'user', validity_days: 365, renew_before_days: 73, group_policy: false },
    { id: 'b', name: 'EasyEAP computer', purpose: 'device', validity_days: 365, renew_before_days: 42, group_policy: true },
    { id: 'c', name: 'RADIUS Server', purpose: 'radius-server', validity_days: 397, renew_before_days: 80, group_policy: false },
  ],
  server_certificate: { serial: '0A', not_before: iso(-100 * day), not_after: iso(297 * day), rotates_at: iso(217.6 * day), ca_too_short: false, rotated_at: null, previous: null },
  ca_schedule: {
    issuing: { common_name: 'Acme Issuing CA', expires: iso(4 * 365 * day), prepare_by: iso(1000 * day), switch_by: iso(1200 * day), shortens_from: iso(3 * 365 * day), shortening: false },
    root: { common_name: 'Acme Root CA', expires: iso(19 * 365 * day), crl_next_update: iso(300 * day) },
    longest_validity_days: 730,
  },
})

function wrap(ui: React.ReactNode, perms: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<MemoryRouter><QueryClientProvider client={qc}><TenantProvider tenant={tenant(perms)}>{ui}</TenantProvider></QueryClientProvider></MemoryRouter>)
}

afterEach(() => vi.unstubAllGlobals())

describe('renewal arithmetic', () => {
  it('matches the backend', () => {
    expect(derivedDays(365, 80)).toBe(73)
    expect(derivedDays(730, 80)).toBe(146)
    expect(derivedDays(365, 90)).toBe(37)
    expect(derivedDays(1, 90)).toBe(1)
    expect(renewAfterDays(365, 80)).toBe(292)
  })
})

describe('Renewal panel', () => {
  it('saves the switches and the percentage, previewing template days first', async () => {
    const puts: unknown[] = []
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      if (init?.method === 'PUT') {
        puts.push(JSON.parse(init.body as string))
        return json(200, overview({ renew_at_percent: 70, user_certs: false }))
      }
      return json(200, overview())
    }))
    wrap(<RenewalPanel />, ['certificates:read', 'ca:manage'])
    expect(await screen.findByText(/A 365-day certificate renews from day 292, 73 days before it expires/)).toBeInTheDocument()
    expect(screen.getByText(/User Wi-Fi renews 73 days before expiry/)).toBeInTheDocument()
    expect(screen.getByText(/Group Policy certificates keep Windows’ own schedule/)).toBeInTheDocument()
    const save = screen.getByRole('button', { name: /Save renewal settings/ })
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByRole('radio', { name: '70 %' }))
    expect(screen.getByText(/renews from day 255, 110 days before it expires/)).toBeInTheDocument()
    expect(screen.getByText(/User Wi-Fi renews 110 days before expiry/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: 'User certificates' }))
    fireEvent.click(save)
    await waitFor(() => expect(puts).toEqual([{ user_certs: false, machine_certs: true, server_cert: true, renew_at_percent: 70 }]))
  })

  it('says when turning server rotation back on rotates at once', async () => {
    const o = overview({ server_cert: false })
    o.server_certificate = { ...o.server_certificate!, not_before: iso(-330 * day), not_after: iso(67 * day), rotates_at: null }
    vi.stubGlobal('fetch', vi.fn(async () => json(200, o)))
    wrap(<RenewalPanel />, ['certificates:read', 'ca:manage'])
    fireEvent.click(await screen.findByRole('switch', { name: 'RADIUS server certificate' }))
    expect(screen.getByText(/past 80 % of its life: it rotates within 6 hours of saving/)).toBeInTheDocument()
  })

  it('says a due rotation waits when the issuing CA is too short', async () => {
    const o = overview()
    o.server_certificate = { ...o.server_certificate!, not_before: iso(-330 * day), not_after: iso(20 * day), ca_too_short: true }
    vi.stubGlobal('fetch', vi.fn(async () => json(200, o)))
    wrap(<RenewalPanel />, ['certificates:read', 'ca:manage'])
    expect(await screen.findByText(/it waits for a new issuing CA/)).toBeInTheDocument()
    expect(screen.queryByText(/rotates within 6 hours/)).toBeNull()
  })

  it('is read-only without ca:manage', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, overview())))
    wrap(<RenewalPanel />, ['certificates:read'])
    expect(await screen.findByText(/Changing renewal needs/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'User certificates' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Save renewal settings/ })).toBeNull()
  })
})

describe('Server certificate card', () => {
  const settings = (previous: boolean): RadiusSettings => ({
    server_hostname: 'radius.acme.example', ssid: 'Acme', wpa3: false, auth_port: 1812, acct_port: 1813, dedicated_ports: false, tls_min_version: '1.2',
    tls_session_cache: false, session_timeout_seconds: 28800, wired_enabled: false, snapshot_version: 1, snapshot_built_at: null, radius_address: '', radius_address_problem: null,
    server_certificate: { id: 's1', serial: '0B', common_name: 'radius.acme.example', not_after: iso(396 * day), fingerprint_sha256: 'AA' },
    server_certificate_renewal: {
      serial: '0B', not_before: iso(-1 * day), not_after: iso(396 * day), rotates_at: iso(316 * day), ca_too_short: false, rotated_at: iso(-1 * day),
      previous: previous ? { serial: '0A', not_after: iso(60 * day), until: iso(13 * day) } : null,
    },
  })

  it('shows when it rotates and puts the previous one back', async () => {
    const posts: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string) => { posts.push(url); return json(200, { settings: settings(false) }) }))
    wrap(<ServerCertificateCard s={settings(true)} />, ['radius:read', 'radius:write', 'certificates:read'])
    expect(screen.getByText(/Rotates by itself on/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Put the previous certificate back/ }))
    expect(await screen.findByText(/Automatic rotation is paused/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^Put it back$/ }))
    await waitFor(() => expect(posts).toContain('/api/tenants/t1/radius/server-certificate/rollback'))
  })

  it('offers no rollback without a previous certificate or radius:write', () => {
    vi.stubGlobal('fetch', vi.fn())
    wrap(<ServerCertificateCard s={settings(false)} />, ['radius:read'])
    expect(screen.queryByRole('button', { name: /Put the previous certificate back/ })).toBeNull()
  })
})
