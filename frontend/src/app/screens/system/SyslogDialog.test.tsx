import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SyslogDialog } from './SyslogDialog'

const facilities = ['user', 'daemon', 'auth', 'authpriv', 'local0', 'local1']

function renderDialog() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}><SyslogDialog open onOpenChange={() => {}} editing={null} facilities={facilities} /></QueryClientProvider>)
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('SyslogDialog', () => {
  it('defaults to TLS, warns about plain transports and moves a default port with the transport', () => {
    renderDialog()
    expect(screen.getByRole('radio', { name: 'TLS (recommended)' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByLabelText(/CA certificate/)).toBeInTheDocument()
    expect(screen.getByLabelText('Port')).toHaveValue('6514')

    fireEvent.click(screen.getByRole('radio', { name: 'UDP' }))
    expect(screen.getByLabelText('Port')).toHaveValue('514')
    expect(screen.getByText(/UDP is unencrypted/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/CA certificate/)).not.toBeInTheDocument()

    // A port the operator chose stays when the transport changes.
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '5514' } })
    fireEvent.click(screen.getByRole('radio', { name: 'TCP' }))
    expect(screen.getByLabelText('Port')).toHaveValue('5514')
    expect(screen.getByText(/TCP is unencrypted/)).toBeInTheDocument()
  })

  it('needs a name, a host and at least one category', () => {
    renderDialog()
    const add = screen.getByRole('button', { name: 'Add destination' })
    expect(add).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'SIEM' } })
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'siem.msp.example' } })
    expect(add).not.toBeDisabled()
    for (const c of [/^Audit trail/, /^Authentication events/, /^System log/]) fireEvent.click(screen.getByRole('checkbox', { name: c }))
    expect(add).toBeDisabled()
  })

  it('sends the test from the server, shows the outcome and forgets it when the settings change', async () => {
    const calls: { url: string; body: Record<string, unknown> }[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      calls.push({ url, body })
      return body.port === 1 ? json(400, { detail: 'The test message couldn’t be sent: Connection refused: nothing is listening on that port.' })
        : json(200, { ok: true, detail: 'Sent to siem.msp.example:6514 over TLS.' })
    }))
    renderDialog()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: ' SIEM ' } })
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'siem.msp.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Send test message' }))
    expect(await screen.findByText('Test message sent')).toBeInTheDocument()
    expect(calls[0].url).toBe('/api/system/syslog/test')
    expect(calls[0].body).toMatchObject({ name: 'SIEM', host: 'siem.msp.example', port: 6514, transport: 'tls', ca_pem: null })

    fireEvent.click(screen.getByRole('radio', { name: 'TCP' }))
    expect(screen.queryByText('Test message sent')).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Send test message' }))
    await waitFor(() => expect(screen.getByText(/nothing is listening on that port/)).toBeInTheDocument())
    expect(screen.queryByText('Test message sent')).not.toBeInTheDocument()
  })
})
