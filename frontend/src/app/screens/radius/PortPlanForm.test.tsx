// The port-plan form across Cisco families and Meraki: "paste show version" sets the family, model and release; the
// choices follow what the switch can do (the backend's capabilities); Meraki has no port list.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TenantProvider } from '../../api/tenant'
import { defaultWiredProfile, type SwitchCaps, type WiredProfile } from '../../api/radius'
import type { TenantDetail } from '../../api/types'
import { PortPlanForm } from './Switches'

const tenant = { id: 't1', name: 'Acme', slug: 'acme', permissions: ['radius:read', 'radius:write'] } as unknown as TenantDetail
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const caps = (over: Partial<SwitchCaps> = {}): SwitchCaps => ({
  dialect: 'ibns2', monitor: 'switch', mab: 'pap', host_modes: ['multi-auth', 'single-host', 'multi-host'], radius_vlan: true, no_supplicant_vlan: true,
  server_down: ['wait', 'open', 'vlan'], coa: 'full', accounting: true, tacacs: 'named', audit: 'caf', session_command: 'show access-session', errdisable: true,
  notes: [], warnings: [], ...over,
})
const NEXUS = caps({ dialect: 'nxos', monitor: 'server', mab: 'pap-wired', host_modes: ['multi-host', 'single-host'], radius_vlan: false, no_supplicant_vlan: false,
  server_down: ['wait'], coa: null, audit: 'ports', session_command: 'show dot1x all summary', notes: ['NX-OS has no open (monitor) mode.'] })
const SERIES = { ibns2: [''], classic: [''], nxos: ['n9k-fx', 'n3k'], cbs: ['c1300', 'sx350'], meraki: ['ms', 'ms-open'] }
const LABELS = { 'n9k-fx': 'Nexus 9300-EX, -FX or -FX2', 'n3k': 'Nexus 3000', c1300: 'Catalyst 1300', sx350: 'CBS350', ms: 'Meraki MS (any model)', 'ms-open': 'Meraki MS130 or MS150 on MS 18 or later' }

/** The backend: capabilities by family, and a detection for a pasted Nexus `show version`. */
function backend(capsFor: (q: URLSearchParams) => SwitchCaps) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url === '/api/tenants/t1/radius') return json(200, { settings: null, clients: [], agent: { features: ['mab'] }, unattributed: null })
    if (url.startsWith('/api/tenants/t1/radius/cisco/platforms')) {
      const q = new URLSearchParams(url.split('?')[1])
      return json(200, { platforms: ['ibns2', 'classic', 'nxos', 'cbs'], series: SERIES, series_labels: LABELS, capabilities: capsFor(q) })
    }
    if (url === '/api/tenants/t1/radius/cisco/detect') {
      return json(200, { detected: { platform: 'nxos', series: 'n9k-fx', version: '9.3(8)', lan_lite: false, model: 'C93180YC-FX', family: 'Nexus 9000 (NX-OS)', evidence: '', unsupported: '' }, capabilities: NEXUS })
    }
    return json(404, { detail: 'not found' })
  }))
  return calls
}

let latest: WiredProfile = defaultWiredProfile
function Harness({ vendor, initial }: { vendor: string; initial: WiredProfile }) {
  const [plan, setPlan] = useState(initial)
  latest = plan
  return <PortPlanForm vendor={vendor} value={plan} onChange={setPlan} touched={false} />
}
function show(vendor: string, initial: WiredProfile = defaultWiredProfile) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><TenantProvider tenant={tenant}><Harness vendor={vendor} initial={initial} /></TenantProvider></QueryClientProvider>)
}

afterEach(() => vi.unstubAllGlobals())

describe('PortPlanForm (Cisco)', () => {
  it('sets the family, model and release from a pasted show version', async () => {
    backend((q) => (q.get('platform') === 'nxos' ? NEXUS : caps()))
    show('cisco-switch')
    fireEvent.click(screen.getByRole('button', { name: 'Paste show version' }))
    fireEvent.change(screen.getByLabelText('Output of show version'), { target: { value: 'Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(8)\n  cisco Nexus9000 C93180YC-FX Chassis' } })
    fireEvent.click(screen.getByRole('button', { name: 'Read it' }))
    expect(await screen.findByText(/Nexus 9000 \(NX-OS\) · C93180YC-FX · 9\.3\(8\)/)).toBeInTheDocument()
    expect(latest).toMatchObject({ platform: 'nxos', series: 'n9k-fx', version: '9.3(8)' })
    expect(screen.getByRole('radio', { name: 'Nexus' })).toHaveAttribute('data-state', 'on')
    expect(screen.getByPlaceholderText('Ethernet1/1 - 48')).toBeInTheDocument()
  })

  it('moves choices the switch can’t make to ones it can, and says what it can’t do', async () => {
    backend(() => NEXUS)
    show('cisco-switch', { ...defaultWiredProfile, platform: 'nxos', series: 'n9k-fx', host_mode: 'multi-auth', server_down: 'open', no_supplicant: 'vlan', no_supplicant_vlan: 30 })
    await waitFor(() => expect(latest).toMatchObject({ host_mode: 'multi-host', server_down: 'wait', no_supplicant: 'block' }))
    expect(screen.getByText('NX-OS has no open (monitor) mode.')).toBeInTheDocument()
    // EasyEAP monitors a switch without open mode through MAC authentication: no switch to turn it off.
    expect(screen.getByText('MAC authentication: on')).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: /Admit devices without 802.1X/ })).not.toBeInTheDocument()
    // AAA new-model is an IOS question.
    expect(screen.queryByText('The switch already uses AAA')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Change' }))
    expect(screen.getByText(/Blocked: this switch has no VLAN for them/)).toBeInTheDocument()
    expect(screen.getByText(/Wait: this switch has no way to let new devices through/)).toBeInTheDocument()
  })

  it('says when the switch can’t do MAC authentication at all', async () => {
    backend(() => caps({ dialect: 'sx', mab: null, monitor: 'none', notes: ['No open (monitor) mode.'] }))
    show('cisco-switch', { ...defaultWiredProfile, platform: 'cbs', series: 'c1200' })
    expect(await screen.findByText(/This switch can’t admit devices by MAC address/)).toBeInTheDocument()
  })

  it('shows what EasyEAP assumed when the release isn’t given, and offers LAN Lite on classic IOS', async () => {
    backend(() => caps({ dialect: 'authmgr', warnings: ['Version unknown: EasyEAP assumes IOS 15.2(3)E or later.'] }))
    show('cisco-switch', { ...defaultWiredProfile, platform: 'classic' })
    expect(await screen.findByText('EasyEAP assumed')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'LAN Lite image' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText('15.2(7)E3')).toBeInTheDocument()
  })
})

describe('PortPlanForm (Meraki)', () => {
  it('asks for the model, not ports, and asks the backend about Meraki', async () => {
    const calls = backend(() => caps({ dialect: 'meraki', monitor: 'server', mab: 'pap-wired', notes: ['Leave RADIUS CoA off.'] }))
    show('meraki', { ...defaultWiredProfile, series: 'ms' })
    expect(await screen.findByText('Leave RADIUS CoA off.')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Model' })).toHaveTextContent('Meraki MS (any model)')
    expect(screen.queryByLabelText('Access ports')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Paste show version' })).not.toBeInTheDocument()
    expect(calls.some((c) => c.includes('/cisco/platforms?vendor=meraki'))).toBe(true)
  })
})
