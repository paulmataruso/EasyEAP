import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import type { PendingInfo } from './api'
import { Flow } from './Flow'

const info: PendingInfo = {
  status: 'pending',
  tenant: 'Acme',
  user: { display_name: 'Pat Doe', upn: 'pat@acme.example' },
  device_name: 'Pat’s laptop',
  platform: 'windows',
  method: 'link',
  expires_at: new Date(Date.now() + 86_400_000).toISOString(),
  network: { ssid: 'Acme Staff', server_name: 'radius.acme.example', wpa3: false, wired: false },
  instructions: [],
}
const env = { detected: 'windows' as const, inAppBrowser: false, iosNotSafari: false, appName: null }
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

// exe: what the server answers for the program (a launcher-less development image answers 501).
function stubApi(exe: () => Response | Promise<Response>) {
  const fetch = vi.fn(async (url: string) => {
    if (url === '/api/enroll/tok/windows.exe') return exe()
    if (url === '/api/enroll/tok/windows.ps1') return new Response('﻿$ErrorActionPreference', { status: 200 })
    if (url === '/api/enroll/tok/ca.pem') return new Response('', { status: 404 })
    if (url === '/api/enroll/tok') return json(200, info)
    return json(404, { detail: 'not found' })
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

let saved: { name: string; blob: Blob }[] = []
beforeEach(() => {
  saved = []
  let last: Blob | null = null
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: (b: Blob) => { last = b; return 'blob:x' }, revokeObjectURL: () => {} }))
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { saved.push({ name: this.download, blob: last! }) })
})
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

async function download() {
  render(<Flow token="tok" info={info} env={env} onGone={() => {}} />)
  fireEvent.click(screen.getByRole('button', { name: /Continue/ }))
  fireEvent.click(await screen.findByRole('button', { name: /Download the setup helper/ }))
  expect(await screen.findByRole('heading', { name: 'Install with the setup helper' })).toBeInTheDocument()
}

describe('Windows setup helper', () => {
  it('saves the program people double-click', async () => {
    const fetch = stubApi(() => new Response(new Uint8Array([0x4d, 0x5a, 0x90, 0x00]), { status: 200 }))
    await download()
    expect(saved[0].name).toBe('EasyEAP-WiFi-Setup.exe')
    expect(saved[0].blob.type).toBe('application/vnd.microsoft.portable-executable')
    expect(Array.from(new Uint8Array(await saved[0].blob.arrayBuffer()))).toEqual([0x4d, 0x5a, 0x90, 0x00])
    expect(fetch.mock.calls.some(([u]) => u === '/api/enroll/tok/windows.ps1')).toBe(false)
    expect(screen.getByText(/Double-click/)).toBeInTheDocument()
    expect(screen.queryByText(/Run with PowerShell/)).not.toBeInTheDocument()
  })

  it('offers the same helper as a PowerShell script where programs are blocked', async () => {
    stubApi(() => new Response(new Uint8Array([0x4d, 0x5a]), { status: 200 }))
    await download()
    expect(screen.getByText(/If your browser warned about the file/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Can’t run the program?'))
    // Never -File on the program: PowerShell runs only .ps1 files that way.
    expect(screen.queryByText(/-File ".*EasyEAP-WiFi-Setup\.exe"/)).not.toBeInTheDocument()
    expect(screen.getByText('powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\EasyEAP-WiFi-Setup.ps1"')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Download the PowerShell script/ }))
    expect(await screen.findByText(/Saved as/)).toBeInTheDocument()
    expect(saved[1].name).toBe('EasyEAP-WiFi-Setup.ps1')
    expect(await saved[1].blob.text()).toContain('$ErrorActionPreference')
  })

  it.each([
    ['the server has no launcher', () => json(501, { detail: 'no launcher' })],
    ['the program download fails', () => Promise.reject(new TypeError('network'))],
  ])('falls back to the PowerShell script when %s', async (_, exe) => {
    stubApi(exe)
    await download()
    expect(saved[0].name).toBe('EasyEAP-WiFi-Setup.ps1')
    expect(await saved[0].blob.text()).toContain('$ErrorActionPreference')
    expect(screen.getByText(/Run with PowerShell/)).toBeInTheDocument()
    expect(screen.queryByText(/Double-click/)).not.toBeInTheDocument()
    expect(screen.queryByText('Can’t run the program?')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('Prefer to type a command?'))
    expect(screen.getByText('powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\\Downloads\\EasyEAP-WiFi-Setup.ps1"')).toBeInTheDocument()
  })
})
