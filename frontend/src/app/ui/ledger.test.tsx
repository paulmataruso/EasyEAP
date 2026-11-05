import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { DecisionLedger, type LedgerRule } from './ledger'
import type { Outcome } from '../api/types'

const groups = { it: { id: 'g-it', name: 'IT Dept' }, staff: { id: 'g-staff', name: 'Staff' }, contractors: { id: 'g-c', name: 'Contractors' } }
const rules: LedgerRule[] = [
  { id: 'r-deny', name: 'Deny Contractors', action: 'deny', priority: 10, enabled: true, groups: [groups.contractors] },
  { id: 'r-it', name: 'IT Dept', action: 'allow', priority: 20, enabled: true, groups: [groups.it] },
  { id: 'r-staff', name: 'Staff', action: 'allow', priority: 30, enabled: true, groups: [groups.staff] },
]
const vlans = [{ vlan_id: 120, name: 'IT', color: 'teal' }, { vlan_id: 100, name: 'Staff', color: 'blue' }]

describe('DecisionLedger', () => {
  it('shows the deciding allow rule, the VLAN and the reply attributes', () => {
    const outcome: Outcome = {
      outcome: 'allow', reason_code: null, deciding_rule_id: 'r-it', vlan_id: 120,
      attributes: [{ name: 'Tunnel-Type', value: '13 (VLAN)' }, { name: 'Tunnel-Medium-Type', value: '6 (IEEE-802)' }, { name: 'Tunnel-Private-Group-ID', value: '120' }],
      steps: [
        { kind: 'account', ok: true, detail: 'enabled' },
        { kind: 'certificate', ok: true, detail: 'Valid until 2027' },
        { kind: 'rule', ruleId: 'r-deny', matched: false, action: 'deny', detail: '' },
        { kind: 'rule', ruleId: 'r-it', matched: true, action: 'allow', detail: '' },
        { kind: 'rule', ruleId: 'r-staff', matched: true, action: 'allow', detail: '' },
      ],
    }
    render(<DecisionLedger outcome={outcome} rules={rules} identityGroups={[groups.it, groups.staff]} vlans={vlans} />)
    const ledger = screen.getByRole('list', { name: 'Decision ledger' })
    expect(within(ledger).getByText(/Access-Accept/)).toBeInTheDocument()
    expect(within(ledger).getByText(/Rule “IT Dept” · Allow/).textContent).toMatch(/Decides/)
    expect(within(ledger).getByText(/Member of IT Dept · position 1 among Allow rules/)).toBeInTheDocument()
    expect(within(ledger).getByText(/an Allow rule higher in the order decided/)).toBeInTheDocument()
    expect(screen.getByText('Tunnel-Private-Group-ID')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /1 rule did not match/ })).toBeInTheDocument()
  })

  it('says deny wins and names the rule', () => {
    const outcome: Outcome = {
      outcome: 'deny', reason_code: 'policy_deny', deciding_rule_id: 'r-deny', vlan_id: null, attributes: [],
      steps: [
        { kind: 'account', ok: true, detail: 'enabled' },
        { kind: 'rule', ruleId: 'r-deny', matched: true, action: 'deny', detail: '' },
        { kind: 'rule', ruleId: 'r-staff', matched: true, action: 'allow', detail: '' },
      ],
    }
    render(<DecisionLedger outcome={outcome} rules={rules} identityGroups={[groups.contractors, groups.staff]} vlans={vlans} policyOnly />)
    expect(screen.getByText(/Access-Reject/)).toBeInTheDocument()
    expect(screen.getByText('Denied by “Deny Contractors”')).toBeInTheDocument()
    expect(screen.getByText(/Deny rules always win/)).toBeInTheDocument()
    expect(screen.getByText(/Matched, but a Deny rule already decided/)).toBeInTheDocument()
    // Policy-only evaluation must not read as "can connect".
    expect(screen.getByText('Certificate not checked here')).toBeInTheDocument()
    expect(screen.queryByText('Tunnel-Private-Group-ID')).not.toBeInTheDocument()
  })

  it('evaluates the certificate gate against the certificates on record', () => {
    const outcome: Outcome = {
      outcome: 'allow', reason_code: null, deciding_rule_id: 'r-it', vlan_id: 120, attributes: [],
      steps: [{ kind: 'account', ok: true, detail: 'enabled' }, { kind: 'rule', ruleId: 'r-it', matched: true, action: 'allow', detail: '' }],
    }
    const later = new Date(Date.now() + 200 * 864e5).toISOString()
    const sooner = new Date(Date.now() + 30 * 864e5).toISOString()
    const { unmount } = render(<DecisionLedger outcome={outcome} rules={rules} identityGroups={[groups.it]} vlans={vlans} policyOnly
      certificates={[{ name: 'old-phone', not_after: sooner }, { name: 'nina-laptop', not_after: later }]} />)
    expect(screen.getByText('Certificate valid')).toBeInTheDocument()
    expect(screen.getByText(/nina-laptop · valid for .* · and 1 more/)).toBeInTheDocument()
    expect(screen.queryByText('Certificate not checked here')).not.toBeInTheDocument()
    unmount()

    render(<DecisionLedger outcome={outcome} rules={rules} identityGroups={[groups.it]} vlans={vlans} policyOnly certificates={[]} />)
    expect(screen.getByText('No valid certificate')).toBeInTheDocument()
    expect(screen.getByText(/Until then RADIUS sends Access-Reject/)).toBeInTheDocument()
  })

  it('stops at a disabled account and does not evaluate rules', () => {
    const outcome: Outcome = {
      outcome: 'deny', reason_code: 'account_disabled', deciding_rule_id: null, vlan_id: null, attributes: [],
      steps: [{ kind: 'account', ok: false, detail: 'disabled' }],
    }
    render(<DecisionLedger outcome={outcome} rules={rules} identityGroups={[groups.it]} vlans={vlans} accountState="disabled" />)
    expect(screen.getByText('Account disabled')).toBeInTheDocument()
    expect(screen.getByText(/No rule can override this/)).toBeInTheDocument()
    expect(screen.getByText('Access rules were not evaluated.')).toBeInTheDocument()
    expect(screen.getByText('Account is disabled, locked or deleted')).toBeInTheDocument()
  })
})
