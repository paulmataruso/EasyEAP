import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { SessionProvider } from '../api/session'
import { FirstRun } from './FirstRun'

function renderFirstRun() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, enabled: false } } })
  return render(<QueryClientProvider client={qc}><SessionProvider><MemoryRouter><FirstRun /></MemoryRouter></SessionProvider></QueryClientProvider>)
}

describe('FirstRun', () => {
  it('offers a new setup or a restore, both behind the setup token', () => {
    renderFirstRun()
    const newSetup = screen.getByRole('radio', { name: /Set up new/ })
    const restore = screen.getByRole('radio', { name: /Restore a backup/ })
    expect(newSetup).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('button', { name: /Create administrator/ })).toBeDisabled()

    fireEvent.click(restore)
    expect(restore).toHaveAttribute('aria-checked', 'true')
    const picker = screen.getByLabelText('Backup file')
    expect(picker).toBeDisabled()
    expect(screen.getByText('Enter the setup token first.')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Setup token'), { target: { value: 'a-setup-token-value' } })
    expect(screen.getByLabelText('Backup file')).not.toBeDisabled()
    expect(screen.queryByText('Enter the setup token first.')).not.toBeInTheDocument()
  })

  it('refuses a file that is not an EasyEAP backup without uploading it', async () => {
    renderFirstRun()
    fireEvent.click(screen.getByRole('radio', { name: /Restore a backup/ }))
    fireEvent.change(screen.getByLabelText('Setup token'), { target: { value: 'a-setup-token-value' } })
    fireEvent.change(screen.getByLabelText('Backup file'), { target: { files: [new File(['x'], 'notes.txt')] } })
    expect(await screen.findByText(/ends in \.easyeap/)).toBeInTheDocument()
  })
})
