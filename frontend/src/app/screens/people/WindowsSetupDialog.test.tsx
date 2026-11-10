import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TenantProvider } from '../../api/tenant'
import type { TenantDetail } from '../../api/types'
import { WindowsSetupDialog } from './WindowsSetupDialog'

const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions: ['enrollment:manage', 'certificates:issue'] } as unknown as TenantDetail
const nina = { id: 'i1', display_name: 'Nina Patel', username: 'nina', upn: 'nina@acme.example' }
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

function setup(settings: Record<string, unknown> | null, exe: { exe_filename: string; exe_b64: string } | null = null) {
  const posts: Record<string, unknown>[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (url === '/api/tenants/t1/radius') return json(200, { settings, clients: [] })
    if (url === '/api/tenants/t1/enrollments/windows-setup' && init?.method === 'POST') {
      posts.push(JSON.parse(String(init.body)) as Record<string, unknown>)
      return json(201, { filename: 'EasyEAP-Setup-nina.cmd', content: '<# : batch\r\n', exe_filename: null, exe_b64: null, ...exe,
        expires_at: '2026-11-10T12:00:00Z', sign_in_mode: 'machineOrUser', enrollments: [] })
    }
    return json(404, { detail: 'not found' })
  }))
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><TenantProvider tenant={tenant}><WindowsSetupDialog identity={nina} open onOpenChange={() => {}} /></TenantProvider></QueryClientProvider>)
  return posts
}

afterEach(() => vi.unstubAllGlobals())

describe('WindowsSetupDialog', () => {
  it('sends the chosen parts, saves the file and shows the next steps', async () => {
    const created: string[] = []
    vi.spyOn(URL, 'createObjectURL').mockImplementation(() => { created.push('blob'); return 'blob:x' })
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const posts = setup({ ssid: 'Acme-Secure', server_hostname: 'radius.acme.example', session_timeout_seconds: null, wired_enabled: true })
    const download = await screen.findByRole('button', { name: /Download setup/ })
    await waitFor(() => expect(download).not.toBeDisabled())
    expect(screen.getByRole('switch', { name: 'Wi-Fi (Acme-Secure)' })).toBeChecked()
    expect(screen.getByRole('switch', { name: 'Wired 802.1X (switch ports)' })).toBeChecked()
    expect(screen.getByText(/computer’s certificate at the sign-in screen, then the user’s/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('switch', { name: /Shared PC/ }))
    expect(screen.getByText(/Anyone who signs in on the PC keeps the network/)).toBeInTheDocument()
    fireEvent.click(download)
    expect(await screen.findByText(/Saved as EasyEAP-Setup-nina.cmd/)).toBeInTheDocument()
    expect(posts).toEqual([{ identity_id: 'i1', user_certificate: true, computer_certificate: true, wifi: true, wired: true, shared_pc: true, ttl_hours: 72 }])
    expect(created).toHaveLength(1)
  })

  it('saves the program users double-click when the server made one, and the .cmd on request', async () => {
    const blobs: Blob[] = []
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { blobs.push(b as Blob); return 'blob:x' })
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    setup({ ssid: 'Acme-Secure', server_hostname: 'radius.acme.example', session_timeout_seconds: null, wired_enabled: false },
      { exe_filename: 'EasyEAP-Setup-nina.exe', exe_b64: btoa('MZ\x90\x00\xff payload') })
    const download = await screen.findByRole('button', { name: /Download setup/ })
    await waitFor(() => expect(download).not.toBeDisabled())
    fireEvent.click(download)
    expect(await screen.findByText(/Saved as EasyEAP-Setup-nina.exe/)).toBeInTheDocument()
    expect(screen.getByText(/More info/)).toBeInTheDocument()
    expect(blobs[0].type).toBe('application/vnd.microsoft.portable-executable')
    expect(Array.from(new Uint8Array(await blobs[0].arrayBuffer()))).toEqual(Array.from('MZ\x90\x00\xff payload', (ch) => ch.charCodeAt(0)))
    fireEvent.click(screen.getByRole('button', { name: 'Download the .cmd instead' }))
    expect(blobs).toHaveLength(2)
    expect(await blobs[1].text()).toBe('<# : batch\r\n')
  })

  it('needs a certificate and a network', async () => {
    setup({ ssid: '', server_hostname: 'radius.acme.example', session_timeout_seconds: null, wired_enabled: false })
    const download = await screen.findByRole('button', { name: /Download setup/ })
    await waitFor(() => expect(screen.getByRole('switch', { name: /no network name/ })).toBeDisabled())
    expect(screen.getByText('Choose Wi-Fi, wired, or both.')).toBeInTheDocument()
    expect(download).toBeDisabled()
    fireEvent.click(screen.getByRole('switch', { name: 'Wired 802.1X (switch ports)' }))
    expect(download).not.toBeDisabled()
    fireEvent.click(screen.getByRole('switch', { name: 'Nina’s certificate' }))
    fireEvent.click(screen.getByRole('switch', { name: /The computer’s certificate/ }))
    expect(screen.getByText('Choose at least one certificate.')).toBeInTheDocument()
    expect(download).toBeDisabled()
  })

  it('asks for the RADIUS settings first', async () => {
    setup(null)
    expect(await screen.findByText('Save the RADIUS settings first')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Download setup/ })).toBeDisabled()
  })
})
