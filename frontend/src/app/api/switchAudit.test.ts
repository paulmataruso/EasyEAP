import { describe, expect, it } from 'vitest'
import { fillCredentials, findingTitles } from './switchAudit'

describe('switch audit', () => {
  it('fills the one-time credentials into the configuration block', () => {
    const v2 = 'snmp-server community <community> view EASYEAP-RO RO EASYEAP-SNMP\n'
    expect(fillCredentials(v2, { community: 'Abc123', user: null })).toBe('snmp-server community Abc123 view EASYEAP-RO RO EASYEAP-SNMP\n')
    const v3 = 'snmp-server user easyeap EASYEAP v3 auth sha-2 256 <authentication key> priv aes 128 <privacy key>'
    expect(fillCredentials(v3, { auth_key: 'AK', priv_key: 'PK', user: 'easyeap' })).toBe('snmp-server user easyeap EASYEAP v3 auth sha-2 256 AK priv aes 128 PK')
    expect(fillCredentials(v2, null)).toBe(v2)
  })
  it('has a title for every finding kind the API reports', () => {
    for (const k of ['port_not_covered', 'open_access_in_enforce', 'authorized_without_easyeap', 'authorized_despite_reject', 'authorized_after_deny', 'vlan_mismatch',
      'mab_not_expected', 'critical_auth', 'err_disabled', 'caf_missing', 'switch_changed', 'snmp_unreachable', 'snmp_auth']) {
      expect(findingTitles[k]).toBeTruthy()
    }
  })
})
