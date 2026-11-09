import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { TenantProvider } from '../api/tenant'
import type { AutoenrollStatus, KeytabInfo } from '../api/autoenroll'
import type { TenantDetail } from '../api/types'
import Autoenroll from './Autoenroll'

const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions: ['directory:read', 'directory:write'] } as unknown as TenantDetail
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const at = new Date(Date.now() - 60_000).toISOString()

function status(over: Partial<AutoenrollStatus['config']> = {}, readiness: AutoenrollStatus['readiness'] = []): AutoenrollStatus {
  return {
    config: {
      enabled: false, computers: true, users: false, computer_group: null, require_channel_binding: true, response_format: 'pkcs7',
      service_account: 'easyeap-cep', policy_id: 'p1', keytab: null, keytab_test: null, machine_account_quota: 10,
      last_success_at: null, last_error_at: null, last_error: null, ...over,
    },
    host: 'easyeap.corp.example', realm: 'CORP.EXAMPLE', urls: { policy: 'https://easyeap.corp.example/cep', enrollment: 'https://easyeap.corp.example/ces' },
    templates: [], readiness, ready: false, counts: { computers: 0, certificates: 0 }, events: [],
  }
}

const keytab: KeytabInfo = {
  principal: 'HTTP/easyeap.corp.example@CORP.EXAMPLE', realm: 'CORP.EXAMPLE', kvno: 2, enctypes: ['aes256-cts-hmac-sha1-96'], problems: [], entries: 1,
  sha256: 'x', uploaded_at: at, source: 'console', account_dn: 'CN=easyeap-cep,CN=Users,DC=corp,DC=example', created_by: 'Administrator@corp.example',
}

function show(initial: AutoenrollStatus, create?: (body: unknown) => Response) {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === '/api/tenants/t1/autoenroll') return json(200, initial)
    if (url === '/api/tenants/t1/autoenroll/service-account' && init?.method === 'POST' && create) return create(JSON.parse(String(init.body)))
    if (url.startsWith('/api/tenants/t1/autoenroll/events')) return json(200, { items: [], total: 0 })
    return json(404, { detail: 'not found' })
  })
  vi.stubGlobal('fetch', fetch)
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<MemoryRouter><QueryClientProvider client={qc}><TenantProvider tenant={tenant}><Autoenroll /></TenantProvider></QueryClientProvider></MemoryRouter>)
  return fetch
}

afterEach(() => vi.unstubAllGlobals())

describe('Autoenroll service account', () => {
  it('creates the service account from the console and clears the password', async () => {
    const created = status({ keytab, keytab_test: { ok: true, step: 'done', message: 'The key works.', at, uploaded_at: at } })
    const fetch = show({ ...status(), directory_verified: true }, () => json(200, { ...created, service_account: { dn: keytab.account_dn, created: true, forest_checked: true } }))
    fireEvent.click(await screen.findByRole('button', { name: 'Create the service account…' }))
    const create = screen.getByRole('button', { name: 'Create and test' })
    expect(create).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Administrator'), { target: { value: ' Administrator@corp.example ' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 's3cret' } })
    fireEvent.click(create)
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Create and test' })).not.toBeInTheDocument())
    const call = fetch.mock.calls.find(([u]) => u === '/api/tenants/t1/autoenroll/service-account')
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ username: 'Administrator@corp.example', password: 's3cret', container: '' })
    expect(await screen.findByText('HTTP/easyeap.corp.example@CORP.EXAMPLE')).toBeInTheDocument()
    expect(screen.getByText(/by Administrator@corp.example/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create it again…' })).toBeInTheDocument()
  })

  it('shows why it failed, keeps the dialog open and clears the password', async () => {
    show({ ...status(), directory_verified: true }, () => json(403, { detail: { step: 'permission', message: 'Administrator@corp.example may not create users in CN=Users,DC=corp,DC=example.', detail: 'insufficientAccessRights' } }))
    fireEvent.click(await screen.findByRole('button', { name: 'Create the service account…' }))
    fireEvent.change(screen.getByLabelText('Administrator'), { target: { value: 'Administrator@corp.example' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 's3cret' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create and test' }))
    expect(await screen.findByText(/may not create users/)).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.getByLabelText('Administrator')).toHaveValue('Administrator@corp.example')
  })

  it('asks before sending the password over a connection whose certificate isn’t checked', async () => {
    const fetch = show({ ...status(), directory_verified: false }, () => json(200, { ...status({ keytab }), service_account: { dn: 'x', created: true, forest_checked: true } }))
    fireEvent.click(await screen.findByRole('button', { name: 'Create the service account…' }))
    fireEvent.change(screen.getByLabelText('Administrator'), { target: { value: 'Administrator@corp.example' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 's3cret' } })
    expect(screen.getByText('EasyEAP doesn’t check your domain controller’s certificate')).toBeInTheDocument()
    const create = screen.getByRole('button', { name: 'Create and test' })
    expect(create).toBeDisabled()
    fireEvent.click(screen.getByLabelText(/Send it anyway/))
    fireEvent.click(create)
    await waitFor(() => expect(fetch.mock.calls.some(([u]) => u === '/api/tenants/t1/autoenroll/service-account')).toBe(true))
    const call = fetch.mock.calls.find(([u]) => u === '/api/tenants/t1/autoenroll/service-account')
    expect(JSON.parse(String(call?.[1]?.body)).accept_unverified).toBe(true)
  })

  it('won’t start until EasyEAP has a DNS name', async () => {
    show(status({}, [{ key: 'host', level: 'error', message: 'PCs need a DNS name for EasyEAP, not an IP address.' }]))
    expect(await screen.findByText('EasyEAP needs a DNS name first')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create the service account…' })).toBeDisabled()
  })
})
