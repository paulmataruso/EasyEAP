import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import type { PendingInfo } from './api'
import { Flow } from './Flow'
import { ConnectSteps, type GuideCtx } from './guides'

const info: PendingInfo = {
  status: 'pending',
  tenant: 'Acme',
  user: { display_name: 'Pat Doe', upn: 'pat@acme.example' },
  device_name: 'Pat’s laptop',
  platform: 'linux',
  method: 'link',
  expires_at: new Date(Date.now() + 86_400_000).toISOString(),
  network: { ssid: 'Acme Staff', server_name: 'radius.acme.example', wpa3: false, wired: false },
  instructions: [],
}
const env = { detected: 'linux' as const, inAppBrowser: false, iosNotSafari: false, appName: null }
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

function stubApi(linkStatus: () => string) {
  const fetch = vi.fn(async (url: string) => {
    if (url === '/api/enroll/tok/linux.sh') return new Response('#!/bin/sh\n', { status: 200 })
    if (url === '/api/enroll/tok/ca.pem') return new Response('', { status: 404 })
    if (url === '/api/enroll/tok') return json(200, linkStatus() === 'pending' ? info : { status: linkStatus(), tenant: 'Acme' })
    return json(404, { detail: 'not found' })
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

beforeEach(() => {
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: () => 'blob:x', revokeObjectURL: () => {} }))
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
})
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers() })

describe('Linux enrollment', () => {
  it('offers the setup script first and shows how to run it', async () => {
    let status = 'pending'
    const fetch = stubApi(() => status)
    vi.useFakeTimers({ shouldAdvanceTime: true })
    render(<Flow token="tok" info={info} env={env} onGone={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /Continue/ }))
    fireEvent.click(await screen.findByRole('button', { name: /Download the setup script/ }))
    expect(await screen.findByRole('heading', { name: 'Run the setup script' })).toBeInTheDocument()
    expect(fetch.mock.calls.some(([u]) => u === '/api/enroll/tok/linux.sh')).toBe(true)
    expect(screen.getAllByText('bash ~/Downloads/EasyEAP-WiFi-Setup.sh').length).toBeGreaterThan(0)
    expect(screen.getByText('bash ~/Downloads/EasyEAP-WiFi-Setup.sh --check')).toBeInTheDocument()
    expect(screen.queryByText(/powershell/i)).not.toBeInTheDocument()
    expect(screen.getByText('Waiting for the script to finish')).toBeInTheDocument()

    // The script posts the certificate request itself; the page notices when the link is used.
    status = 'completed'
    await act(async () => { await vi.advanceTimersByTimeAsync(6500) })
    expect(await screen.findByText('Your certificate was issued')).toBeInTheDocument()
  })

  it('falls back to creating the certificate in the browser', async () => {
    stubApi(() => 'pending')
    render(<Flow token="tok" info={info} env={env} onGone={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /Continue/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Create the certificate in this browser instead' }))
    expect(screen.queryByRole('button', { name: /Download the setup script/ })).not.toBeInTheDocument()
  })
})

describe('Linux manual Wi-Fi steps', () => {
  const c: GuideCtx = {
    tenant: 'Acme', ssid: 'Acme Staff', serverName: 'radius.acme.example', wpa3: false, wired: false, identity: 'pat@acme.example',
    deviceName: 'laptop', profileName: null, rootCn: 'Acme Root CA', files: { p12: 'Acme-Staff.p12', ca: 'Acme-Staff-ca.pem' }, androidCertName: 'Acme Staff',
  }

  it('tells people to forget the old network and pick TLS', () => {
    render(<ConnectSteps platform="linux" route="p12" c={c} password="pw" />)
    expect(screen.getByText(/choose/, { selector: 'li' }).textContent).toMatch(/Forget/)
    expect(screen.getByText(/not the preselected Tunneled TLS/)).toBeInTheDocument()
    expect(screen.getByText(/Store the password for all users/)).toBeInTheDocument()
  })

  it('says the script is already connected on the helper route', () => {
    render(<ConnectSteps platform="linux" route="helper" c={c} password={null} />)
    expect(screen.queryByText(/Tunneled TLS/)).not.toBeInTheDocument()
  })
})
