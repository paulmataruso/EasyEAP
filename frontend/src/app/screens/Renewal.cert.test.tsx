// How a certificate renews on its page, and revoking a renewed certificate with or without what it was renewed into
// (docs/plans/cert-renewal.md §15b items 4 and 8).
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { CertificateDetail } from '../api/people'
import { TenantProvider } from '../api/tenant'
import type { TenantDetail } from '../api/types'
import { RenewalCard } from './CertificateDetail'
import { RevokeDialog } from './people/RevokeDialog'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const day = 864e5
const iso = (ms: number) => new Date(Date.now() + ms).toISOString()

const cert = (over: Partial<CertificateDetail> = {}): CertificateDetail => ({
  id: 'c1', serial: '0A1B2C3D4E5F60718293A4B5C6D7E8F9', common_name: 'pc-nina01', subject: 'CN=pc-nina01', sans: [], purpose: 'device',
  not_before: iso(-300 * day), not_after: iso(65 * day), key_algorithm: 'EC-256', key_origin: 'device', fingerprint_sha256: 'AA',
  status: 'active', stored_status: 'active', revoked_at: null, revocation_reason: null, revoked_by: null, template_id: 't', identity: null,
  device: { id: 'd1', name: 'PC-NINA01', platform: 'windows' }, created_at: iso(-300 * day), decision: null, issuer: null,
  renewer: 'windows-setup', renewer_version: '2.0', renewal_checked_at: iso(-0.5 * day), retired_at: null,
  renewal: { renew_from: iso(-8 * day), enabled: true, state: 'auto' }, successors: [], ...over,
})

function wrap(ui: React.ReactNode, permissions: string[] = ['certificates:read', 'certificates:revoke']) {
  const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions } as unknown as TenantDetail
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}><MemoryRouter><TenantProvider tenant={tenant}>{ui}</TenantProvider></MemoryRouter></QueryClientProvider>)
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('RenewalCard', () => {
  it('says what renews it and when it last checked in', () => {
    wrap(<RenewalCard c={cert()} />)
    expect(screen.getByText('Windows setup file')).toBeInTheDocument()
    expect(screen.getByText(/Renewal task version 2.0/)).toBeInTheDocument()
    expect(screen.getByText('Renewal starts')).toBeInTheDocument()
  })

  it('says an older task reports nothing until due', () => {
    wrap(<RenewalCard c={cert({ renewer_version: '1', renewal_checked_at: null })} />)
    expect(screen.getByText(/An older renewal task: it asks only once the certificate is due/)).toBeInTheDocument()
  })

  it('says a profile needs the user', () => {
    wrap(<RenewalCard c={cert({ renewer: null, renewer_version: null, renewal_checked_at: null, renewal: { renew_from: iso(-8 * day), enabled: true, state: 'manual' } })} />)
    expect(screen.getByText('It doesn’t renew by itself')).toBeInTheDocument()
    expect(screen.queryByText('Last check-in')).toBeNull()
  })

  it('warns when the task went silent or renewal is off', () => {
    wrap(<RenewalCard c={cert({ renewal_checked_at: iso(-9 * day), renewal: { renew_from: iso(-20 * day), enabled: false, state: 'silent' } })} />)
    expect(screen.getByText('Its renewal task stopped checking in')).toBeInTheDocument()
    expect(screen.getByText(/Turned off for device certificates/)).toBeInTheDocument()
  })

  it('lists what it was renewed into, and a replaced one', () => {
    wrap(<RenewalCard c={cert({
      status: 'superseded', renewal: { renew_from: iso(-8 * day), enabled: true, state: null },
      successors: [
        { id: 'c3', serial: '0C', status: 'active', not_after: iso(365 * day), revoked_by: null },
        { id: 'c2', serial: '0B', status: 'revoked', not_after: iso(365 * day), revoked_by: 'EasyEAP (replaced: the device never received it)', replaced: true },
      ],
    })} />)
    expect(screen.getAllByRole('link').map((a) => a.getAttribute('href'))).toEqual(['/t/t1/certificates/c3', '/t/t1/certificates/c2'])
    expect(screen.getByText(/Replaced: the device never received it/)).toBeInTheDocument()
    expect(screen.queryByText('Renewal starts')).toBeNull()
  })
})

describe('Revoking a renewed certificate', () => {
  function open(revokeAlso: CertificateDetail['revoke_also'], status: CertificateDetail['status'] = 'superseded') {
    const posts: unknown[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') { posts.push(JSON.parse(init.body as string)); return json(200, { ok: true, disconnect: { sessions: 0, queued: 0, without_coa: 0 }, session_timeout_seconds: null, note: '', successors: [] }) }
      if (url.endsWith('/certificates/c1')) return json(200, cert({ status, revoke_also: revokeAlso }))
      if (url.includes('/radius')) return json(200, { clients: [], settings: null })
      return json(200, {})
    }))
    wrap(<RevokeDialog cert={{ ...cert({ status }) }} open onOpenChange={() => {}} />)
    return posts
  }
  const revoke = async () => {
    fireEvent.click(await screen.findByRole('radio', { name: /Superseded/ }))
    await waitFor(() => expect(screen.getByRole('button', { name: /Revoke certificate/ })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: /Revoke certificate/ }))
  }

  it('revokes what it was renewed into unless told not to', async () => {
    const posts = open([{ id: 'c3', serial: '0C' }])
    const box = await screen.findByRole('checkbox', { name: /Also revoke the newer certificate renewed from it/ })
    expect(box).toBeChecked()
    fireEvent.click(box)
    await revoke()
    await waitFor(() => expect(posts).toEqual([{ reason: 'superseded', disconnect: false, successors: false }]))
  })

  it('asks about an expired certificate’s renewals too', async () => {
    const posts = open([{ id: 'c3', serial: '0C' }, { id: 'c4', serial: '0D' }], 'expired')
    expect(await screen.findByRole('checkbox', { name: /Also revoke the 2 newer certificates/ })).toBeChecked()
    await revoke()
    await waitFor(() => expect(posts).toEqual([{ reason: 'superseded', disconnect: false, successors: true }]))
  })

  it('cascades nothing it didn’t show', async () => {
    const posts = open([])
    await revoke()
    await waitFor(() => expect(posts).toEqual([{ reason: 'superseded', disconnect: false, successors: false }]))
    expect(screen.queryByRole('checkbox', { name: /Also revoke/ })).toBeNull()
  })
})
