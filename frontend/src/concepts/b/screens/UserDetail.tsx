import { useEffect, useMemo, useRef } from 'react'
import { ArrowLeft, Ban, CircleCheck, CircleX, Eye, FileKey2, SearchX, Smartphone } from 'lucide-react'
import { now, useDecision, useTenantData, useTenants } from '@/prototype/store'
import { failureExplanations, platformLabels } from '@/domain/explain'
import type { Identity } from '@/domain/types'
import { daysUntil, formatDate, formatDateTime } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { EmptyState, KeyValue, Notice, Panel, PanelHead } from '../ui/Panel'
import { Button, IconButton } from '../ui/Button'
import { AccessBadge, CertStatusBadge, SourceBadge, StatusBadge, VlanChip } from '../ui/Badge'
import { DecisionTrace, AttributeTable } from '../features/DecisionTrace'
import { PlatformIcon } from '../features/PlatformIcon'
import { useInspector } from '../shell/Inspectors'
import { useShell } from '../shell/context'
import { formatAge, rel, secondsSince, shortSerial } from '../lib/format'
import { accountStateLabels, keyOriginLabels } from '../lib/labels'

function distance(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) dp[0][j] = j
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
  return dp[a.length][b.length]
}

/** Exact match, else the closest username in the tenant (same initial first), so a stale link still lands somewhere useful. */
function resolve(identities: Identity[], entityId: string | undefined): { identity: Identity | undefined; fuzzy: boolean } {
  if (!entityId) return { identity: undefined, fuzzy: false }
  const exact = identities.find((i) => i.id === entityId)
  if (exact) return { identity: exact, fuzzy: false }
  const wanted = entityId.split(':u-')[1]?.toLowerCase()
  if (!wanted) return { identity: undefined, fuzzy: false }
  const ranked = identities
    .map((i) => ({ i, score: distance(wanted, i.username) + (i.username[0] === wanted[0] ? 0 : 4) }))
    .sort((a, b) => a.score - b.score)
  const best = ranked[0]
  return best && best.score <= Math.max(6, wanted.length * 0.7) ? { identity: best.i, fuzzy: true } : { identity: undefined, fuzzy: false }
}

export function UserDetail({ entityId }: { entityId?: string }) {
  const { tenants, current, switchTenant } = useTenants()
  const d = useTenantData()
  const { go } = useShell()
  const { openIssue, openCertificate, openEvent } = useInspector()

  // Deep links carry the tenant in the id: open the user's own tenant once per link.
  const followed = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (!entityId || followed.current === entityId) return
    followed.current = entityId
    const tenantId = entityId.split(':')[0]
    if (tenantId !== current.id && tenants.some((t) => t.id === tenantId)) switchTenant(tenantId)
  }, [entityId, current.id, tenants, switchTenant])

  const { identity, fuzzy } = useMemo(() => resolve(d.identities, entityId), [d.identities, entityId])
  const decision = useDecision(identity)

  if (!identity) {
    return (
      <>
        <BackLink onClick={() => go('users')} />
        <Panel>
          <EmptyState icon={SearchX} title="No such user in this tenant" action={<Button onClick={() => go('users')}>Browse users</Button>}>
            Nothing matches <span className="b-mono text-[var(--b-text)]">{entityId ?? 'this link'}</span> in {current.name}. The account may have been removed from Active Directory, or the link belongs to another tenant.
          </EmptyState>
        </Panel>
      </>
    )
  }

  const devices = d.devices.filter((x) => x.identityId === identity.id)
  const certs = d.certificates.filter((c) => c.identityId === identity.id)
  const events = d.authEvents.filter((e) => e.identityId === identity.id)
  // The RADIUS log is the source of truth for the last authentication; the directory stamp covers older ones.
  const lastAuthAt = events.reduce<string | null>((latest, e) => (latest && latest > e.at ? latest : e.at), null) ?? identity.lastAuthAt
  const groups = d.groups.filter((g) => identity.groupIds.includes(g.id))
  const vlan = d.vlans.find((v) => v.id === decision?.vlanId)
  const decidingRule = d.rules.find((r) => r.id === decision?.decidingRuleId)
  const canIssue = identity.accountState === 'enabled'
  const first = identity.displayName.split(' ')[0]

  return (
    <>
      <BackLink onClick={() => go('users')} />
      {fuzzy && (
        <Notice tone="info" className="mb-3" title="Showing the closest match">
          No identity has the id <span className="b-mono text-[var(--b-text)]">{entityId}</span>. The nearest username in {current.name} is <span className="b-mono text-[var(--b-text)]">{identity.username}</span>.
        </Notice>
      )}
      <PageHeader
        title={identity.displayName}
        context={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="b-mono text-[12.5px] text-[var(--b-text)]">{identity.upn ?? identity.username}</span>
            <span>
              <span aria-hidden className="mr-2">·</span>
              {identity.department} · {identity.title}
            </span>
          </span>
        }
        actions={
          <Button variant="primary" icon={FileKey2} disabled={!canIssue} title={canIssue ? undefined : 'Certificates cannot be issued to disabled, locked or deleted accounts'} onClick={() => openIssue(identity.id)}>
            Issue Wi-Fi certificate
          </Button>
        }
      >
        <span className="flex flex-wrap items-center gap-1.5">
          <SourceBadge source={identity.source} />
          {identity.accountState === 'enabled' ? <StatusBadge tone="ok">Account enabled</StatusBadge> : <StatusBadge tone={identity.accountState === 'locked' ? 'warn' : 'crit'}>{accountStateLabels[identity.accountState]}</StatusBadge>}
          {decision && <AccessBadge outcome={decision.outcome} />}
        </span>
      </PageHeader>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div className="min-w-0 space-y-3">
          <Panel aria-labelledby="dir-title">
            <PanelHead id="dir-title" title={identity.source === 'ad' ? 'Active Directory' : 'Local account'} meta={identity.lastSyncedAt ? `synced ${formatAge(secondsSince(identity.lastSyncedAt))} ago` : identity.source === 'ad' ? 'never synced' : undefined} />
            <div className="px-3 pt-1 pb-3">
              <KeyValue
                labelWidth="132px"
                rows={[
                  ['User principal name', <span key="upn" className="b-mono break-all">{identity.upn ?? '—'}</span>],
                  ['sAMAccountName', <span key="sam" className="b-mono">{identity.username}</span>],
                  ['Email', identity.email ?? '—'],
                  ['Department', identity.department ?? '—'],
                  ['Title', identity.title ?? '—'],
                  [
                    'Account state',
                    identity.accountState === 'enabled' ? (
                      <span key="st" className="b-ink-ok inline-flex items-center gap-1.5">
                        <CircleCheck className="size-3.5" aria-hidden /> Enabled
                      </span>
                    ) : (
                      <span key="st" className="b-ink-crit inline-flex items-center gap-1.5">
                        <CircleX className="size-3.5" aria-hidden /> {accountStateLabels[identity.accountState]}
                      </span>
                    ),
                  ],
                  ['Last authentication', lastAuthAt ? `${rel(lastAuthAt)} · ${formatDateTime(lastAuthAt)}` : 'Never'],
                  !!identity.objectGuid && ['objectGUID', <span key="g" className="b-mono text-[11.5px] break-all text-[var(--b-text-2)]">{identity.objectGuid}</span>],
                ]}
              />
              <h3 className="b-label mt-3 mb-1.5">Groups ({groups.length})</h3>
              <ul className="flex flex-wrap gap-1.5">
                {groups.map((g) => (
                  <li key={g.id} className="b-chip" title={g.dn}>
                    {g.name}
                  </li>
                ))}
              </ul>
            </div>
          </Panel>

          <Panel aria-labelledby="ev-title">
            <PanelHead id="ev-title" title="Recent authentications" meta={events.length ? `${events.length} in 24 h` : undefined} />
            {events.length === 0 ? (
              <p className="b-t2 px-3 py-4 text-[12.5px]">No authentication attempts in the last 24 hours.</p>
            ) : (
              <ul className="b-divide-y">
                {events.slice(0, 8).map((e) => {
                  const why = e.failureCode ? failureExplanations[e.failureCode] : null
                  const dev = d.devices.find((x) => x.id === e.deviceId)
                  const nas = d.radiusClients.find((n) => n.id === e.nasClientId)
                  return (
                    <li key={e.id}>
                      <button type="button" className="grid w-full grid-cols-[64px_minmax(0,1fr)] gap-x-3 px-3 py-2 text-left transition-colors hover:bg-[var(--b-hover)]" onClick={() => openEvent(e.id)}>
                        <span className="flex flex-col">
                          <span className="b-mono text-[12px]">{e.at.slice(11, 19)}</span>
                          <span className="b-num text-[11.5px] text-[var(--b-text-3)]">{formatAge(secondsSince(e.at))} ago</span>
                        </span>
                        <span className="min-w-0">
                          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px]">
                            {why ? <CircleX className="b-ink-crit size-3.5" aria-hidden /> : <CircleCheck className="b-ink-ok size-3.5" aria-hidden />}
                            <span className={why ? 'b-ink-crit font-medium' : 'font-medium text-[var(--b-text)]'}>{why ? why.title : 'Accepted'}</span>
                            {!why && e.vlanId && <VlanChip vlan={d.vlans.find((v) => v.id === e.vlanId)} showName={false} />}
                          </span>
                          <span className="block truncate text-[12px] text-[var(--b-text-2)]">
                            {dev?.name ?? 'Unknown device'} · {nas?.name ?? 'unknown controller'}
                          </span>
                          {why && <span className="mt-1 block text-[12.5px] leading-snug text-[var(--b-text-2)]">{why.explanation} <span className="text-[var(--b-text)]">{why.fix}</span></span>}
                        </span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            )}
          </Panel>
        </div>

        <div className="min-w-0 space-y-3">
          <Panel aria-labelledby="dec-title">
            <PanelHead id="dec-title" title="Access decision" meta="evaluated against the current rules" />
            {decision && (
              <>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-[var(--b-line)] px-3 py-3">
                  <span className={`b-figure text-[24px] ${decision.outcome === 'allow' ? 'b-ink-ok' : 'b-ink-crit'}`}>{decision.outcome === 'allow' ? 'Allowed' : 'Denied'}</span>
                  {vlan && <VlanChip vlan={vlan} />}
                  <span className="text-[13px] text-[var(--b-text-2)]">
                    Decided by{' '}
                    <span className="font-medium text-[var(--b-text)]">
                      {decidingRule ? `“${decidingRule.name}” (priority ${decidingRule.priority})` : identity.accountState !== 'enabled' ? 'the account check' : 'the tenant default'}
                    </span>
                  </span>
                  <Button size="sm" variant="ghost" className="ml-auto" onClick={() => go('policies', { section: 'rules' })}>
                    Edit rules
                  </Button>
                </div>
                <div className="grid gap-4 p-3 lg:grid-cols-[minmax(0,1fr)_minmax(220px,260px)]">
                  <DecisionTrace decision={decision} rules={d.rules} vlans={d.vlans} groups={d.groups} />
                  <div>
                    <h3 className="b-label mb-1.5">RADIUS reply</h3>
                    <AttributeTable attributes={decision.attributes} />
                  </div>
                </div>
              </>
            )}
          </Panel>

          <Panel aria-labelledby="dev-title">
            <PanelHead
              id="dev-title"
              title="Devices and certificates"
              meta={devices.length ? `${devices.length} ${devices.length === 1 ? 'device' : 'devices'} · one certificate each` : undefined}
              actions={
                canIssue && (
                  <Button size="sm" icon={FileKey2} onClick={() => openIssue(identity.id)}>
                    Add device
                  </Button>
                )
              }
            />
            {devices.length === 0 ? (
              <EmptyState
                icon={Smartphone}
                title="No enrolled devices"
                action={
                  canIssue && (
                    <Button size="sm" variant="primary" icon={FileKey2} onClick={() => openIssue(identity.id)}>
                      Issue Wi-Fi certificate
                    </Button>
                  )
                }
              >
                {canIssue ? `Issue a certificate to send ${first} a one-time enrollment link for their first device.` : 'Re-enable the account in Active Directory before issuing a certificate.'}
              </EmptyState>
            ) : (
              <ul className="b-divide-y">
                {devices.map((dev, i) => {
                  const cert = certs.filter((c) => c.deviceId === dev.id).sort((a, b) => b.notBefore.localeCompare(a.notBefore))[0]
                  const days = cert ? daysUntil(cert.notAfter, now()) : null
                  return (
                    <li key={`${dev.id}#${i}`} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 px-3 py-2.5 sm:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_auto]">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <span className="grid size-8 shrink-0 place-items-center rounded-md border border-[var(--b-line-strong)] bg-[var(--b-sunken)] text-[var(--b-text-2)]">
                          <PlatformIcon platform={dev.platform} className="size-4" />
                        </span>
                        <div className="min-w-0">
                          <p className="truncate text-[13px] font-medium text-[var(--b-text)]">{dev.name}</p>
                          <p className="truncate text-[12px] text-[var(--b-text-2)]">
                            {platformLabels[dev.platform]} · <span className="b-mono text-[11.5px]">{dev.lastSeenMac ?? 'no MAC seen'}</span>
                          </p>
                        </div>
                      </div>
                      <div className="col-span-2 row-start-2 min-w-0 sm:col-span-1 sm:row-start-auto">
                        {cert ? (
                          <>
                            <p className="flex flex-wrap items-center gap-2">
                              <CertStatusBadge status={cert.status} />
                              <span className="b-mono text-[11.5px] text-[var(--b-text-2)]">{shortSerial(cert.serial)}</span>
                            </p>
                            <p className="b-num mt-0.5 truncate text-[12px] text-[var(--b-text-2)]">
                              {cert.status === 'revoked'
                                ? `Revoked ${cert.revokedAt ? formatDate(cert.revokedAt) : ''}`
                                : days !== null && days < 0
                                  ? `Expired ${formatDate(cert.notAfter)}`
                                  : `Expires ${formatDate(cert.notAfter)}${days !== null && days <= 30 ? ` · ${days} days` : ''}`}{' '}
                              · {keyOriginLabels[cert.keyOrigin].replace('Generated ', 'key ').replace('Submitted as a CSR', 'key from CSR')}
                            </p>
                          </>
                        ) : (
                          <p className="text-[12.5px] text-[var(--b-text-3)]">No certificate</p>
                        )}
                      </div>
                      <div className="flex items-center justify-end gap-1">
                        {cert && <IconButton icon={Eye} label={`View certificate for ${dev.name}`} onClick={() => openCertificate(cert.id)} />}
                        {cert && cert.status !== 'revoked' && (
                          <Button size="sm" variant="danger" icon={Ban} onClick={() => openCertificate(cert.id, 'revoke')} aria-label={`Revoke certificate for ${dev.name}`}>
                            Revoke
                          </Button>
                        )}
                        {cert && cert.status !== 'active' && cert.status !== 'expiring' && canIssue && (
                          <Button size="sm" icon={FileKey2} onClick={() => openIssue(identity.id, { deviceName: dev.name, platform: dev.platform })}>
                            Reissue
                          </Button>
                        )}
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </>
  )
}

function BackLink({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className="b-link mb-2 inline-flex items-center gap-1 text-[12.5px]">
      <ArrowLeft className="size-3.5" aria-hidden /> Users
    </button>
  )
}
