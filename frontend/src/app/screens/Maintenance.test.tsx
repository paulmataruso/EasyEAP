import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { RestoreState } from '../api/backup'
import { api, notifyMaintenance } from '../api/client'
import { MaintenanceGate } from './Maintenance'

vi.mock('../api/client', async (orig) => {
  const real = await orig<typeof import('../api/client')>()
  return { ...real, api: { ...real.api, get: vi.fn() } }
})

const steps = (doneUpTo: number, current: number | null) =>
  ['verify', 'pki', 'database', 'migrate', 'secrets', 'access', 'finish'].map((key, i) => ({ key, label: `Step ${key}`, done: i < doneUpTo, current: i === current }))

const running: RestoreState = {
  id: 'r1', status: 'running', step: 'database', steps: steps(2, 2), error: null, started_at: new Date().toISOString(), finished_at: null,
  source: 'console', backup_created_at: '2026-11-05T10:00:00+00:00', warnings: [],
}

function renderGate() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}><MaintenanceGate><p>the console</p></MaintenanceGate></QueryClientProvider>)
}

afterEach(() => vi.mocked(api.get).mockReset())

describe('MaintenanceGate', () => {
  it('replaces the console with restore progress as soon as the API reports a restore', async () => {
    vi.mocked(api.get).mockResolvedValue({ maintenance: running, last_restore: null })
    renderGate()
    expect(screen.getByText('the console')).toBeInTheDocument()
    act(() => notifyMaintenance(running))
    expect(await screen.findByRole('heading', { name: 'Restoring a backup' })).toBeInTheDocument()
    expect(screen.queryByText('the console')).not.toBeInTheDocument()
    const current = screen.getByText('Step database').closest('li')
    expect(current).toHaveAttribute('aria-current', 'step')
    expect(screen.getByText('Step verify').closest('li')).toHaveAttribute('data-state', 'done')
    expect(api.get).toHaveBeenCalledWith('/api/system/maintenance', expect.anything())
  })

  it('ignores 503s that are not a restore', () => {
    renderGate()
    act(() => notifyMaintenance({ something: 'else' }))
    expect(screen.getByText('the console')).toBeInTheDocument()
  })

  it('says the restore is complete only for the restore it watched, then sends everyone to sign in', async () => {
    const done: RestoreState = { ...running, status: 'done', step: null, steps: steps(7, null), finished_at: new Date().toISOString(), warnings: ['Audit note'] }
    vi.mocked(api.get).mockResolvedValue({ maintenance: null, last_restore: done })
    renderGate()
    act(() => notifyMaintenance(running))
    expect(await screen.findByRole('heading', { name: 'Restore complete' })).toBeInTheDocument()
    expect(screen.getByText('Audit note')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('reports a failed restore with its error and that everything was put back', async () => {
    const failed: RestoreState = { ...running, status: 'failed', error: 'The database restore failed: disk full', finished_at: new Date().toISOString() }
    vi.mocked(api.get).mockResolvedValue({ maintenance: null, last_restore: failed })
    renderGate()
    act(() => notifyMaintenance(running))
    expect(await screen.findByRole('heading', { name: 'The restore didn’t complete' })).toBeInTheDocument()
    expect(screen.getByText('The database restore failed: disk full')).toBeInTheDocument()
    expect(screen.getByText(/put everything back/)).toBeInTheDocument()
  })

  it('does not claim success when the outcome belongs to another restore', async () => {
    const other: RestoreState = { ...running, id: 'older', status: 'done', finished_at: new Date().toISOString() }
    vi.mocked(api.get).mockResolvedValue({ maintenance: null, last_restore: other })
    renderGate()
    act(() => notifyMaintenance(running))
    expect(await screen.findByRole('heading', { name: 'EasyEAP is available again' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Restore complete' })).not.toBeInTheDocument()
  })
})
