import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ShowLinkDialog, type Waiting } from './people/GiveAgain'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const LINK = 'https://easyeap.example/enroll.html#/t/abc123'
const pending = (platform: string): Waiting => ({ id: 'e1', device_name: 'Nina’s device', platform, expires_at: '2099-11-11T10:00:00Z' })

function show(platform: string, link: () => Response) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url === '/api/tenants/t1/radius') return json(200, { settings: { ssid: 'Acme-Secure', server_hostname: 'radius.acme.example', wired_enabled: false }, clients: [] })
    if (url.endsWith('/link')) return link()
    if (url.endsWith('/linux-script')) return json(200, { filename: 'EasyEAP-WiFi-Setup.sh', content: '#!/bin/bash\n', expires_at: '2099-11-11T10:00:00Z' })
    return json(404, { detail: 'not found' })
  }))
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><ShowLinkDialog tid="t1" identityName="Nina Patel" e={pending(platform)} onClose={() => {}} /></QueryClientProvider>)
  return calls
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('ShowLinkDialog', () => {
  it('fetches the pending link and offers to copy it, with the platform’s next steps', async () => {
    const calls = show('windows', () => json(200, { link: LINK, expires_at: '2099-11-11T10:00:00Z' }))
    expect(await screen.findByLabelText('Enrollment link')).toHaveTextContent(LINK)
    expect(screen.getByRole('button', { name: 'Copy enrollment link' })).toBeInTheDocument()
    expect(screen.getByText(/For the computer’s certificate as well .* use Windows setup/)).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /QR code/ })).not.toBeInTheDocument()
    expect(calls).toContain('POST /api/tenants/t1/enrollments/e1/link')
  })

  it('shows a QR code for an iPhone or iPad', async () => {
    show('ios', () => json(200, { link: LINK, expires_at: '2099-11-11T10:00:00Z' }))
    expect(await screen.findByRole('img', { name: 'QR code of the enrollment link for Nina’s device' })).toBeInTheDocument()
    expect(screen.getByText(/open the link on the device itself/)).toBeInTheDocument()
  })

  it('leaves the QR code out when the link is too long for one', async () => {
    show('android', () => json(200, { link: `https://${'a'.repeat(240)}.example/enroll.html#/t/abc123`, expires_at: '2099-11-11T10:00:00Z' }))
    expect(await screen.findByLabelText('Enrollment link')).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /QR code/ })).not.toBeInTheDocument()
    expect(screen.queryByText(/camera/)).not.toBeInTheDocument()
  })

  it('gives a Linux link’s setup script', async () => {
    vi.spyOn(URL, 'createObjectURL').mockImplementation(() => 'blob:x')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    const calls = show('linux', () => json(200, { link: LINK, expires_at: '2099-11-11T10:00:00Z' }))
    fireEvent.click(await screen.findByRole('button', { name: /Download setup script/ }))
    await waitFor(() => expect(calls).toContain('POST /api/tenants/t1/enrollments/e1/linux-script'))
    expect(screen.getByText(/before anyone signs in/)).toBeInTheDocument()
  })

  it('says why when the link can no longer be shown', async () => {
    show('windows', () => json(409, { detail: 'Only a pending link can be shown again: this one was used, cancelled or has expired.' }))
    expect(await screen.findByText(/this one was used, cancelled or has expired/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Enrollment link')).not.toBeInTheDocument()
  })
})
