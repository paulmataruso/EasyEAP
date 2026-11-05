import { useState } from 'react'
import { Activity, ArrowLeft, BadgeCheck, Ban, FlaskConical, MonitorSmartphone, Plus, UserRoundX } from 'lucide-react'
import { now, useDecision, useTenantData } from '@/prototype/store'
import { revocationReasonLabels } from '@/domain/explain'
import type { Certificate, Device } from '@/domain/types'
import { daysUntil, formatDate, formatSerial } from '@/ui/lib'
import { useConcept, type Intent } from '../app/context'
import { Button } from '../ui/Button'
import { DefList, Empty, Lede, Note, Section } from '../ui/Layout'
import { CertMark, StatusMark } from '../ui/Status'
import { DecisionTrace, ReplyAttributes } from '../parts/DecisionTrace'
import { AuthEventsTable } from '../parts/AuthEvents'
import { RevokeSheet } from '../parts/RevokeSheet'
import { IssueFlow } from '../parts/IssueFlow'
import { iconForDevice, platformLabel } from '../parts/Platform'
import { firstName, keyOriginLabel, plural, since, shortSerial } from '../lib/format'

export function UserDetail({ identityId, intent }: { identityId?: string; intent: Intent }) {
  const d = useTenantData()
  const { go } = useConcept()
  const identity = d.identities.find((i) => i.id === identityId)
  const decision = useDecision(identity)
  const [issueOpen, setIssueOpen] = useState(Boolean(intent.user?.issue))
  const [issueInitial, setIssueInitial] = useState(intent.user?.issue)
  const [revoking, setRevoking] = useState<Certificate | null>(null)

  if (!identity || !decision) {
    return (
      <>
        <Lede page="User" state="This person isn’t in the current tenant." detail="The link may point to someone in another tenant, or the account was removed by a directory sync." />
        <Empty icon={UserRoundX} title="Person not found" action={<Button icon={<ArrowLeft size={16} aria-hidden="true" />} onClick={() => go('users')}>Back to users</Button>} />
      </>
    )
  }

  const vlan = d.vlans.find((v) => v.id === decision.vlanId)
  const rule = d.rules.find((r) => r.id === decision.decidingRuleId)
  const devices = d.devices.filter((x) => x.identityId === identity.id)
  const certs = d.certificates.filter((c) => c.identityId === identity.id)
  const events = d.authEvents.filter((e) => e.identityId === identity.id).slice(0, 12)
  const groups = d.groups.filter((g) => identity.groupIds.includes(g.id))
  const first = firstName(identity.displayName)
  const accountBlocked = identity.accountState !== 'enabled'

  const verdict =
    decision.outcome === 'allow' ? (
      <>
        {identity.displayName} can join <span className="c-nowrap">Wi-Fi</span> <span className="c-lede-rest">on VLAN {vlan?.vlanId} · {vlan?.name}.</span>
      </>
    ) : accountBlocked ? (
      <>
        {identity.displayName} cannot join <span className="c-nowrap">Wi-Fi.</span> <span className="c-lede-rest">The directory account is {identity.accountState}.</span>
      </>
    ) : (
      <>
        {identity.displayName} cannot join <span className="c-nowrap">Wi-Fi.</span> <span className="c-lede-rest">{rule ? `The rule “${rule.name}” denies access.` : 'No rule allows any of their groups.'}</span>
      </>
    )

  const openIssue = (init?: { deviceName?: string; platform?: string }) => {
    setIssueInitial(init)
    setIssueOpen(true)
  }

  return (
    <>
      <Lede
        page="User"
        state={verdict}
        detail={[identity.title, identity.department, identity.upn ?? identity.username].filter(Boolean).join(' · ')}
        actions={
          <>
            <Button variant="secondary" icon={<FlaskConical size={16} aria-hidden="true" />} onClick={() => go('policies', { intent: { policies: { testIdentityId: identity.id, focus: 'test' } } })}>
              Test in policies
            </Button>
            <Button variant="primary" icon={<Plus size={16} aria-hidden="true" />} onClick={() => openIssue()} disabled={accountBlocked} title={accountBlocked ? `The directory account is ${identity.accountState}; certificates can be issued once it is enabled.` : undefined}>
              Issue Wi-Fi certificate
            </Button>
          </>
        }
      />
      {accountBlocked ? (
        <div style={{ marginTop: 16 }}>
          <Note icon={Ban} tone="crit">
            <strong>Issuing is paused for this person.</strong> Active Directory reports the account as {identity.accountState}; re-enable it in the directory, then run a sync.
          </Note>
        </div>
      ) : null}

      <div className="c-split" style={{ marginTop: 8 }}>
        <div style={{ minWidth: 0 }}>
          <Section title="Access decision" description="How the policy engine evaluated this person, step by step. Deny rules are checked before any Allow rule.">
            <DecisionTrace decision={decision} identity={identity} rules={d.rules} vlans={d.vlans} groups={d.groups} />
            <div style={{ marginTop: 24 }}>
              <h3 className="c-h3">RADIUS reply</h3>
              <ReplyAttributes decision={decision} />
            </div>
          </Section>

          <Section
            title="Devices and certificates"
            description={`One certificate per device, each revocable on its own.`}
            aside={devices.length ? <Button size="sm" variant="ghost" icon={<Plus size={15} aria-hidden="true" />} onClick={() => openIssue()} disabled={accountBlocked}>Add device</Button> : null}
          >
            {devices.length === 0 ? (
              <Empty icon={MonitorSmartphone} title={`${first} has no enrolled devices`} action={!accountBlocked ? <Button variant="secondary" onClick={() => openIssue()}>Issue the first certificate</Button> : null}>
                Issue a certificate to send {first} a one-time enrollment link for a phone or laptop.
              </Empty>
            ) : (
              <ul className="c-list">
                {devices.map((dev) => (
                  <DeviceRow key={dev.id} device={dev} cert={certs.find((c) => c.deviceId === dev.id)} onRevoke={setRevoking} onIssue={() => openIssue({ deviceName: dev.name, platform: dev.platform })} canIssue={!accountBlocked} />
                ))}
              </ul>
            )}
          </Section>

          <Section title="Recent authentications" description="Last 24 hours. Open a row for the explanation and the raw RADIUS message.">
            <AuthEventsTable
              events={events}
              showPerson={false}
              caption={`Recent authentications for ${identity.displayName}`}
              empty={<Empty icon={Activity} title="No authentications in the last 24 hours">{devices.length ? `${first}’s devices have not tried to join recently.` : 'Attempts appear here once a device is enrolled.'}</Empty>}
            />
          </Section>
        </div>

        <aside aria-label="Directory details" style={{ minWidth: 0 }}>
          <Section title="Directory">
            <DefList
              stacked
              items={[
                { label: 'Source', value: identity.source === 'ad' ? 'Active Directory' : 'Local EasyEAP account' },
                { label: 'User principal name', value: identity.upn ?? '—' },
                { label: 'Username', value: identity.username },
                { label: 'Email', value: identity.email ?? '—' },
                { label: 'Department', value: identity.department ?? '—' },
                { label: 'Title', value: identity.title ?? '—' },
                {
                  label: 'Account state',
                  value: identity.accountState === 'enabled' ? <StatusMark tone="ok" icon={BadgeCheck} label="Enabled" /> : <StatusMark tone="crit" icon={Ban} label={identity.accountState[0].toUpperCase() + identity.accountState.slice(1)} />,
                },
                { label: 'Last directory sync', value: since(identity.lastSyncedAt) },
                { label: 'Last authentication', value: since(identity.lastAuthAt) },
              ]}
            />
          </Section>
          <Section title="Groups" description={`${plural(groups.length, 'group')}, including nested membership.`}>
            <ul className="c-list">
              {groups.map((g) => {
                const rules = d.rules.filter((r) => r.groupIds.includes(g.id) && r.enabled)
                return (
                  <li key={g.id}>
                    <div className="c-listrow" style={{ minHeight: 48 }}>
                      <span className="c-listrow-main">
                        <span style={{ fontWeight: 500 }}>{g.name}</span>
                        <span className="c-cell-secondary">{rules.length ? rules.map((r) => `${r.action === 'deny' ? 'Deny' : 'Allow'}: ${r.name}`).join(' · ') : 'No access rule uses this group'}</span>
                      </span>
                      <span className="c-faint c-small tnum">{g.memberCount}</span>
                    </div>
                  </li>
                )
              })}
            </ul>
          </Section>
        </aside>
      </div>

      <IssueFlow identity={identity} open={issueOpen} onOpenChange={setIssueOpen} initial={issueInitial} key={`${issueInitial?.deviceName ?? ''}`} />
      <RevokeSheet certificate={revoking} open={Boolean(revoking)} onOpenChange={(o) => !o && setRevoking(null)} />
    </>
  )
}

function DeviceRow({ device, cert, onRevoke, onIssue, canIssue }: { device: Device; cert?: Certificate; onRevoke: (c: Certificate) => void; onIssue: () => void; canIssue: boolean }) {
  const Icon = iconForDevice(device)
  const days = cert ? daysUntil(cert.notAfter, now()) : 0
  return (
    <li>
      <div className="c-listrow" style={{ alignItems: 'center', flexWrap: 'wrap', padding: '14px 0' }}>
        <Icon size={20} strokeWidth={1.6} aria-hidden="true" style={{ color: 'var(--c-text-2)', flex: 'none' }} />
        <span className="c-listrow-main" style={{ minWidth: 180 }}>
          <span style={{ fontWeight: 500 }}>{device.name}</span>
          <span className="c-cell-secondary">
            {platformLabel(device.platform)} · enrolled {formatDate(device.createdAt)}
          </span>
          {device.lastSeenMac ? (
            <span className="c-cell-secondary">
              Last seen as <span className="c-mono">{device.lastSeenMac}</span>
            </span>
          ) : null}
        </span>
        {cert ? (
          <>
            <span style={{ minWidth: 220 }}>
              <CertMark status={cert.status} sub={cert.status === 'revoked' ? (cert.revocationReason ? revocationReasonLabels[cert.revocationReason] : undefined) : cert.status === 'expired' ? `${formatDate(cert.notAfter)}` : `${days} days left`} />
              <span className="c-cell-secondary">
                <span className="c-mono" title={formatSerial(cert.serial)}>
                  {shortSerial(cert.serial)}
                </span>{' '}
                · {cert.status === 'revoked' && cert.revokedAt ? `revoked ${since(cert.revokedAt)}` : keyOriginLabel[cert.keyOrigin]}
              </span>
            </span>
            <span style={{ width: 112, display: 'flex', justifyContent: 'flex-end' }}>
              {cert.status === 'revoked' || cert.status === 'expired' ? (
                <Button size="sm" variant="ghost" onClick={onIssue} disabled={!canIssue}>
                  Reissue
                </Button>
              ) : (
                <Button size="sm" variant="danger" onClick={() => onRevoke(cert)}>
                  Revoke
                </Button>
              )}
            </span>
          </>
        ) : (
          <>
            <span style={{ minWidth: 220 }}>
              <CertMark status="none" />
            </span>
            <span style={{ width: 112, display: 'flex', justifyContent: 'flex-end' }}>
              <Button size="sm" variant="ghost" onClick={onIssue} disabled={!canIssue}>
                Issue
              </Button>
            </span>
          </>
        )}
      </div>
    </li>
  )
}

