import { describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { SessionProvider, useSession } from './session'

vi.mock('./client', async (orig) => {
  const real = await orig<typeof import('./client')>()
  return {
    ...real,
    api: {
      get: vi.fn(async (path: string) => {
        if (path === '/api/setup/status') return { needs_setup: false }
        if (path === '/api/auth/me') return { id: 'a1', email: 'owner@example.test', csrf_token: 'c' }
        return { tenants: [{ id: 't1' }] }
      }),
      post: vi.fn(async () => ({ ok: true })),
    },
  }
})

function TenantScreen() {
  const tenants = useQuery({ queryKey: ['tenants'], queryFn: async () => ({ tenants: [{ id: 't1' }] }) })
  return <p>{tenants.data ? 'tenant data loaded' : 'loading tenants'}</p>
}

// Like RequireSession: screens are mounted only while signed in.
function Probe() {
  const { me, loading, signOut } = useSession()
  if (loading) return <p>loading</p>
  return (
    <div>
      <p>{me ? `signed in as ${me.email}` : 'signed out'}</p>
      {me && <TenantScreen />}
      <button onClick={() => void signOut()}>Sign out</button>
    </div>
  )
}

describe('signOut', () => {
  it('tells mounted screens the session is gone at once and forgets cached data', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><SessionProvider><Probe /></SessionProvider></QueryClientProvider>)
    expect(await screen.findByText('signed in as owner@example.test')).toBeInTheDocument()
    expect(await screen.findByText('tenant data loaded')).toBeInTheDocument()
    await act(async () => { screen.getByRole('button', { name: 'Sign out' }).click() })
    expect(await screen.findByText('signed out')).toBeInTheDocument()
    expect(qc.getQueryData(['tenants'])).toBeUndefined()
    expect(qc.getQueryData(['me'])).toBeNull()
  })
})
