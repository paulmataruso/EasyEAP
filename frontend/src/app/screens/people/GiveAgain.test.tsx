import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { IdentityListItem, WaitingEnrollment } from '../../api/people'
import { TenantProvider } from '../../api/tenant'
import type { TenantDetail } from '../../api/types'
import { WaitingList } from './GiveAgain'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const w = (over: Partial<WaitingEnrollment>): WaitingEnrollment => ({
  id: 'e1', method: 'link', device_name: 'Nina’s laptop', platform: 'windows', expires_at: '2099-11-11T10:00:00Z', available: true, device_id: null, ...over,
})
const nina = (waiting: WaitingEnrollment[], account_state = 'enabled') => ({ id: 'i1', display_name: 'Nina Patel', username: 'nina', account_state, waiting }) as unknown as IdentityListItem

function show(waiting: WaitingEnrollment[], permissions = ['enrollment:manage'], state = 'enabled') {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.endsWith('/windows-setup')) return json(200, { filename: 'EasyEAP-Setup-nina.cmd', content: '<# : batch\r\n', expires_at: '2099-11-11T10:00:00Z', sign_in_mode: 'machineOrUser', enrollments: [] })
    return json(404, { detail: 'not found' })
  }))
  const onShow = vi.fn()
  const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions } as unknown as TenantDetail
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><MemoryRouter><TenantProvider tenant={tenant}><WaitingList u={nina(waiting, state)} onShow={onShow} /></TenantProvider></MemoryRouter></QueryClientProvider>)
  return { calls, onShow }
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('WaitingList', () => {
  it('shows nothing when nothing waits', () => {
    const { container } = render(<MemoryRouter><TenantProvider tenant={{ id: 't1', permissions: [] } as unknown as TenantDetail}><WaitingList u={nina([])} onShow={() => {}} /></TenantProvider></MemoryRouter>)
    expect(container).toBeEmptyDOMElement()
  })

  it('opens a waiting link without making a new one', () => {
    const { calls, onShow } = show([w({})])
    fireEvent.click(screen.getByRole('button', { name: /^Windows link waiting for Nina’s laptop until .*: show it$/ }))
    expect(onShow).toHaveBeenCalledWith(expect.objectContaining({ id: 'e1' }))
    expect(calls).toEqual([])
  })

  it('downloads a waiting setup file again', async () => {
    const saved: string[] = []
    vi.spyOn(URL, 'createObjectURL').mockImplementation(() => { saved.push('blob'); return 'blob:x' })
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const { calls } = show([w({ id: 'e2', method: 'windows-setup', device_name: 'Windows PC', device_id: 'd1' })])
    fireEvent.click(screen.getByRole('button', { name: /^Windows setup file waiting for Nina Patel until .*: download it again$/ }))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(calls).toEqual(['POST /api/tenants/t1/enrollments/e2/windows-setup'])
  })

  it('points to the user’s page when it can’t be given again here', () => {
    show([w({ available: false }), w({ id: 'e3', method: 'server', available: false })])
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /^Windows link waiting for Nina’s laptop until .*: open Nina Patel’s page$/ })).toHaveAttribute('href', '/t/t1/users/i1')
    expect(screen.getByRole('link', { name: /^Package waiting/ })).toBeInTheDocument()
  })

  it('names each platform’s link', () => {
    show([w({ id: 'a', platform: 'ios' }), w({ id: 'b', platform: 'linux' }), w({ id: 'c', platform: 'macos' })])
    expect(screen.getByRole('button', { name: /^iPhone\/iPad link waiting/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Linux link waiting/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Mac link waiting/ })).toBeInTheDocument()
  })

  it('only points to the user’s page for a disabled account', () => {
    show([w({})], ['enrollment:manage'], 'disabled')
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /^Windows link waiting/ })).toBeInTheDocument()
  })

  it('only points to the user’s page without enrollment:manage', () => {
    show([w({}), w({ id: 'e2', method: 'windows-setup', device_id: 'd1' })], ['identities:read'])
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getAllByRole('link')).toHaveLength(2)
  })
})
