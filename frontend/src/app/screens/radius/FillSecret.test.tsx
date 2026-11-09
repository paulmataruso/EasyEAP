import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TenantProvider } from '../../api/tenant'
import { SECRET_PLACEHOLDER, type RadiusSettings, type WiredGuide } from '../../api/radius'
import type { TenantDetail } from '../../api/types'
import { WiredGuideBody } from './Switches'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const settings = { radius_address: '10.9.9.9', radius_address_problem: null } as unknown as RadiusSettings
const guide = {
  kind: 'wired', mode: 'monitor', title: 'Cisco Catalyst switch', vendor: 'cisco-switch', preflight: [], safe_paste: [], steps: [], checks: [],
  cli: `radius server EASYEAP\n address ipv4 10.9.9.9 auth-port 1812 acct-port 1813\n key 0 ${SECRET_PLACEHOLDER}\n`, session_command: null, radius_address: '10.9.9.9',
} as unknown as WiredGuide

function show(permissions: string[]) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    return url.endsWith('/radius/clients/c1/secret') ? json(200, { shared_secret: 'S3cret-from-EasyEAP' }) : json(404, { detail: 'not found' })
  }))
  const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions } as unknown as TenantDetail
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><TenantProvider tenant={tenant}><WiredGuideBody guide={guide} settings={settings} secretOf="sw-office" clientId="c1" /></TenantProvider></QueryClientProvider>)
  return calls
}

afterEach(() => vi.unstubAllGlobals())

describe('WiredGuideBody: the shared secret on demand', () => {
  it('fills the kept secret into the configuration when an admin who may see secrets asks', async () => {
    const calls = show(['radius:read', 'radius:secrets'])
    expect(calls).toEqual([])  // nothing is fetched until asked
    fireEvent.click(screen.getByRole('button', { name: /Fill in the shared secret/ }))
    expect(await screen.findByText(/key 0 S3cret-from-EasyEAP/)).toBeInTheDocument()
    expect(calls).toEqual(['POST /api/tenants/t1/radius/clients/c1/secret'])
    expect(screen.queryByRole('button', { name: /Fill in the shared secret/ })).not.toBeInTheDocument()
  })

  it('without radius:secrets, says who can fill it in', () => {
    show(['radius:read'])
    expect(screen.queryByRole('button', { name: /Fill in the shared secret/ })).not.toBeInTheDocument()
    expect(screen.getByText(/an administrator who manages RADIUS secrets can fill it in/)).toBeInTheDocument()
  })
})
