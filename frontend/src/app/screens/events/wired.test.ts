import { describe, expect, it } from 'vitest'
import type { AuthEvent } from '../../api/events'
import { eventsUrl } from '../../api/events'
import { wiredVlanOf } from '../../api/policy'
import { networkLine } from './EventTable'

const base: AuthEvent = {
  id: 'e1', at: '2026-11-07T09:00:00Z', result: 'accept', reason_code: null, explanation: null, username: 'alice',
  identity_id: null, device_id: null, cert_serial: null, cert_issuer: null, calling_station_id: null, called_station_id: null,
  ssid: null, nas_ip: '10.0.0.1', nas_client_id: null, vlan_id: 100, network: null, nas_port_id: null, monitor: false,
  rule_id: null, raw_message: null,
}

describe('networkLine', () => {
  it('names the switch port on wired events and the SSID on Wi-Fi', () => {
    expect(networkLine({ ...base, network: 'wired', nas_port_id: 'GigabitEthernet1/0/5' })).toBe('Wired · GigabitEthernet1/0/5')
    expect(networkLine({ ...base, network: 'wired' })).toBe('Wired · port not reported')
    expect(networkLine({ ...base, network: 'wireless', ssid: 'Corp' })).toBe('Wi-Fi · Corp')
    expect(networkLine({ ...base, network: 'wireless' })).toBe('Wi-Fi · SSID not reported')
  })
  it('keeps the old wording for events from before wired 802.1X', () => {
    expect(networkLine({ ...base, ssid: 'Corp' })).toBe('Corp')
    expect(networkLine(base)).toBe('SSID not reported')
  })
})

describe('wiredVlanOf', () => {
  it('maps a VLAN to what switch ports get', () => {
    expect(wiredVlanOf({ vlan_id: 100, wired_mode: 'same', wired_vlan_id: null })).toBe(100)
    expect(wiredVlanOf({ vlan_id: 100, wired_mode: 'port', wired_vlan_id: null })).toBeNull()
    expect(wiredVlanOf({ vlan_id: 100, wired_mode: 'vlan', wired_vlan_id: 110 })).toBe(110)
  })
})

describe('eventsUrl', () => {
  it('passes the network filter through, and leaves it out when empty', () => {
    const f = { result: '' as const, reason: '', q: '', hours: 24 }
    expect(eventsUrl('t-1', { ...f, network: 'wired' })).toContain('network=wired')
    expect(eventsUrl('t-1', { ...f, network: '' })).not.toContain('network=')
    expect(eventsUrl('t-1', f)).not.toContain('network=')
  })
})
