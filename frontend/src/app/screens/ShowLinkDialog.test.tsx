import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { IdentityEnrollment } from '../api/people'
import { ShowLinkDialog } from './people/GiveAgain'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const pending: IdentityEnrollment = {
  id: 'e1', device_name: 'Nina’s laptop', platform: 'windows', method: 'link', status: 'pending', created_by: 'admin@acme.example',
  created_at: '2026-11-08T10:00:00Z', expires_at: '2099-11-11T10:00:00Z', completed_at: null, link_available: true,
}

function show(reply: Response) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    return reply
  }))
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><ShowLinkDialog tid="t1" identityName="Nina Patel" e={pending} onClose={() => {}} /></QueryClientProvider>)
  return calls
}

afterEach(() => vi.unstubAllGlobals())

describe('ShowLinkDialog', () => {
  it('fetches the pending link and offers to copy it', async () => {
    const calls = show(json(200, { link: 'https://easyeap.example/enroll.html#/t/abc123', expires_at: pending.expires_at }))
    expect(await screen.findByLabelText('Enrollment link')).toHaveTextContent('https://easyeap.example/enroll.html#/t/abc123')
    expect(screen.getByRole('button', { name: 'Copy enrollment link' })).toBeInTheDocument()
    expect(calls).toEqual(['POST /api/tenants/t1/enrollments/e1/link'])
  })

  it('says why when the link can no longer be shown', async () => {
    show(json(409, { detail: 'Only a pending link can be shown again: this one was used, cancelled or has expired.' }))
    expect(await screen.findByText(/this one was used, cancelled or has expired/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Enrollment link')).not.toBeInTheDocument()
  })
})
