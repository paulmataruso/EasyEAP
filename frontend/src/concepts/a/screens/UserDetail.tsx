import { useMemo, useState } from 'react'
import { DropdownMenu } from 'radix-ui'
import { ArrowLeft, Ban, Copy, Ellipsis, FileBadge, Radio, Smartphone, UserX, Waypoints } from 'lucide-react'
import type { Certificate } from '@/domain/types'
import { platformLabels, revocationReasonLabels } from '@/domain/explain'
import { copyText, formatSerial } from '@/ui/lib'
import { useTenantData, useTenants } from '@/prototype/store'
import { AccessPill, AccountPill, CertStatusPill, RuleActionPill, SourceBadge, VlanChip } from '../ui/badges'
import { Avatar, Button, EmptyState, KeyValues, Mono, Panel, Tip } from '../ui/primitives'
import { usePortalContainer } from '../ui/portal'
import { useToast } from '../ui/toast'
import { AuthEventList } from '../features/activity'
import { CertificateInspector } from '../features/CertificateInspector'
import { DecisionTrace } from '../features/DecisionTrace'
import { IssueCertificateDialog } from '../features/IssueCertificateDialog'
import { keyOriginLabels, PlatformIcon } from '../features/platform'
import { RevokeDialog } from '../features/RevokeDialog'
import { decide, useLookups } from '../lib/model'
import { ago, day, expiryText } from '../lib/time'
import { useNav } from '../shell/nav'

function CertLine({ cert, onRevoke, onOpen }: { cert: Certificate; onRevoke: () => void; onOpen: () => void }) {
  const revoked = cert.status === 'revoked'
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 py-2">
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
        <CertStatusPill status={cert.status} />
        <button type="button" onClick={onOpen} className="a-mono rounded text-[13px] text-[var(--a-text)] underline-offset-[3px] hover:underline" title="Open certificate details">
          {formatSerial(cert.serial)}
        </button>
        <span className="a-num text-[12px] text-[var(--a-text-3)]">
          {revoked ? `Revoked ${ago(cert.revokedAt)} · ${cert.revocationReason ? revocationReasonLabels[cert.revocationReason] : 'no reason'}` : `${day(cert.notAfter)} · ${expiryText(cert.notAfter)}`}
        </span>
      </div>
      <span className="hidden text-[12px] text-[var(--a-text-3)] md:inline">{keyOriginLabels[cert.keyOrigin]}</span>
      {!revoked && (
        <Button size="sm" variant="danger-ghost" icon={Ban} onClick={onRevoke}>
          Revoke
        </Button>
      )}
    </div>
  )
}

function ActionsMenu({ upn, onTest }: { upn: string; onTest: () => void }) {
  const container = usePortalContainer()
  const toast = useToast()
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="a-btn a-btn-secondary !w-9 !px-0" aria-label="More actions">
        <Ellipsis aria-hidden />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal container={container}>
        <DropdownMenu.Content align="end" sideOffset={6} className="a-menu a-overlay-glass">
          <DropdownMenu.Item className="a-menu-item" onSelect={onTest}>
            <Waypoints aria-hidden /> Open in policy tester
          </DropdownMenu.Item>
          <DropdownMenu.Item
            className="a-menu-item"
            onSelect={async () => {
              await copyText(upn)
              toast({ title: 'UPN copied', description: upn, tone: 'info' })
            }}
          >
            <Copy aria-hidden /> Copy UPN
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

export function UserDetail() {
  const { entityId, navigate } = useNav()
  const d = useTenantData()
  const { current } = useTenants()
  const { groupById, vlanById } = useLookups()
  const identity = d.identities.find((i) => i.id === entityId)
  const [issueOpen, setIssueOpen] = useState(false)
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [inspectId, setInspectId] = useState<string | null>(null)

  const decision = useMemo(() => (identity ? decide(identity, d) : null), [identity, d])
  const devices = useMemo(() => (identity ? d.devices.filter((x) => x.identityId === identity.id) : []), [d.devices, identity])
  const certs = useMemo(() => (identity ? d.certificates.filter((c) => c.identityId === identity.id) : []), [d.certificates, identity])
  const events = useMemo(() => (identity ? d.authEvents.filter((e) => e.identityId === identity.id) : []), [d.authEvents, identity])

  if (!identity || !decision) {
    const seen = new Set<string>()
    const recent = [...d.identities]
      .filter((i) => i.lastAuthAt && !seen.has(i.id) && seen.add(i.id))
      .sort((a, b) => (b.lastAuthAt ?? '').localeCompare(a.lastAuthAt ?? ''))
      .slice(0, 4)
    return (
      <Panel depth="record" className="mx-auto mt-8 max-w-[560px]">
        <EmptyState icon={UserX} title={`No such user in ${current.name}`} action={<Button icon={ArrowLeft} onClick={() => navigate('users')}>Back to users</Button>}>
          The user may belong to another tenant or may have been removed from the directory. Switch tenant or search the user list.
        </EmptyState>
        {recent.length > 0 && (
          <div className="border-t border-[var(--a-line)] px-[18px] py-4">
            <h2 className="text-[13px] font-semibold text-[var(--a-text-2)]">Recently authenticated in {current.name}</h2>
            <ul className="mt-2 flex flex-col">
              {recent.map((i) => (
                <li key={i.id}>
                  <a
                    href={`#/c/a/user/${encodeURIComponent(i.id)}`}
                    onClick={(e) => {
                      e.preventDefault()
                      navigate('user', i.id)
                    }}
                    className="-mx-2 flex items-center gap-3 rounded-md px-2 py-2 no-underline transition-colors hover:bg-white/[0.05]"
                  >
                    <Avatar name={i.displayName} size={28} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[14px] font-medium text-[var(--a-text)]">{i.displayName}</span>
                      <Mono className="block truncate text-[12px] text-[var(--a-text-3)]">{i.upn ?? i.username}</Mono>
                    </span>
                    <span className="a-num shrink-0 text-[12px] text-[var(--a-text-3)]">{ago(i.lastAuthAt)}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Panel>
    )
  }

  const vlan = decision.vlanId ? vlanById.get(decision.vlanId) : null
  const first = identity.displayName.split(' ')[0]
  const revokeCert = certs.find((c) => c.id === revokeId) ?? null
  const inspectCert = d.certificates.find((c) => c.id === inspectId) ?? null
  const activeCerts = certs.filter((c) => c.status === 'active' || c.status === 'expiring').length
  const rulesFor = (groupId: string) => d.rules.filter((r) => r.groupIds.includes(groupId))

  return (
    <>
      {/* Record header: the closest glass depth — this page is about one record. */}
      <section aria-labelledby="a-user-name" className="a-panel a-depth-record mb-5 p-5">
        <div className="flex flex-wrap items-start gap-x-5 gap-y-4">
          <Avatar name={identity.displayName} size={52} />
          <div className="min-w-0 flex-1">
            <h1 id="a-user-name" className="text-[22px] leading-tight font-semibold text-[var(--a-text)]">
              {identity.displayName}
            </h1>
            <p className="mt-0.5 text-[14px] text-[var(--a-text-2)]">
              {[identity.title, identity.department].filter(Boolean).join(' · ')}
              {' · '}
              <Mono className="text-[var(--a-text-3)]">{identity.upn ?? identity.username}</Mono>
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <AccessPill outcome={decision.outcome} />
              {vlan && <VlanChip vlan={vlan} />}
              <AccountPill state={identity.accountState} />
              <SourceBadge source={identity.source} />
              <span className="text-[13px] text-[var(--a-text-3)]">
                {activeCerts} of {certs.length} certificates valid · last authenticated {ago(identity.lastAuthAt)}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ActionsMenu upn={identity.upn ?? identity.username} onTest={() => navigate('policies', identity.id)} />
            <Button variant="primary" icon={FileBadge} onClick={() => setIssueOpen(true)}>
              Issue Wi-Fi certificate
            </Button>
          </div>
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-4 xl:col-span-8">
          <Panel
            title="Access decision"
            description={`What RADIUS answers when ${first} connects, under the current rules.`}
            actions={
              <Button size="sm" variant="ghost" icon={Waypoints} onClick={() => navigate('policies', identity.id)}>
                Policy tester
              </Button>
            }
          >
            <div className="px-[18px] pb-5">
              <DecisionTrace decision={decision} identity={identity} />
            </div>
          </Panel>

          <Panel
            title="Devices and certificates"
            description="One certificate per device. Revoking one device leaves the others connected."
            actions={
              <Button size="sm" icon={FileBadge} onClick={() => setIssueOpen(true)}>
                Issue certificate
              </Button>
            }
          >
            {devices.length ? (
              <ul className="divide-y divide-white/[0.07] border-t border-[var(--a-line)]">
                {devices.map((dev, i) => {
                  const devCerts = certs.filter((c) => c.deviceId === dev.id)
                  return (
                    <li key={`${dev.id}-${i}`} className="px-[18px] py-3">
                      <div className="flex flex-wrap items-center gap-3">
                        <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-white/10 bg-white/[0.04]">
                          <PlatformIcon platform={dev.platform} className="size-[18px] text-[var(--a-text-2)]" />
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="text-[14px] font-medium text-[var(--a-text)]">{dev.name}</p>
                          <p className="text-[12px] text-[var(--a-text-3)]">
                            {platformLabels[dev.platform]}
                            {dev.lastSeenMac && (
                              <>
                                {' · '}
                                <Mono>{dev.lastSeenMac}</Mono>
                              </>
                            )}
                            {' · enrolled '}
                            {day(dev.createdAt)}
                          </p>
                        </div>
                      </div>
                      <div className="mt-1 pl-12">
                        {devCerts.length ? (
                          devCerts.map((c) => <CertLine key={c.id} cert={c} onRevoke={() => setRevokeId(c.id)} onOpen={() => setInspectId(c.id)} />)
                        ) : (
                          <p className="py-2 text-[13px] text-[var(--a-text-3)]">No certificate on this device.</p>
                        )}
                      </div>
                    </li>
                  )
                })}
              </ul>
            ) : (
              <EmptyState icon={Smartphone} title="No devices enrolled" action={<Button variant="primary" icon={FileBadge} onClick={() => setIssueOpen(true)}>Issue Wi-Fi certificate</Button>}>
                {first} has no Wi-Fi certificate yet. Issue one and send the enrollment link to the device.
              </EmptyState>
            )}
          </Panel>

          <Panel title="Recent authentications" description={events.length ? `${events.length} attempts in the last 24 hours. Failures are explained in plain language.` : undefined}>
            {events.length ? (
              <div className="border-t border-[var(--a-line)]">
                <AuthEventList events={events} limit={8} />
              </div>
            ) : (
              <EmptyState icon={Radio} title="No authentication attempts">
                {first} has not tried to join Wi-Fi in the last 24 hours.
              </EmptyState>
            )}
          </Panel>
        </div>

        <div className="flex min-w-0 flex-col gap-4 xl:col-span-4">
          <Panel title="Directory" description={identity.source === 'ad' ? `Active Directory · ${current.domain}` : 'Local EasyEAP account'}>
            <div className="px-[18px] pb-3">
              <KeyValues
                items={[
                  { label: 'UPN', value: <Mono className="break-all">{identity.upn ?? '—'}</Mono> },
                  { label: 'Username', value: <Mono>{identity.username}</Mono> },
                  { label: 'Email', value: <span className="break-all">{identity.email ?? '—'}</span> },
                  { label: 'Department', value: identity.department ?? '—' },
                  { label: 'Title', value: identity.title ?? '—' },
                  { label: 'Account', value: <AccountPill state={identity.accountState} /> },
                  { label: 'Object GUID', value: <Mono className="text-[12px] break-all">{identity.objectGuid ?? '—'}</Mono> },
                  { label: 'Last synced', value: ago(identity.lastSyncedAt) },
                ]}
              />
            </div>
          </Panel>
          <Panel title="Groups" description={`${identity.groupIds.length} groups, including nested membership.`}>
            <ul className="divide-y divide-white/[0.07] border-t border-[var(--a-line)]">
              {identity.groupIds.map((gid) => {
                const g = groupById.get(gid)
                const rules = rulesFor(gid)
                return (
                  <li key={gid} className="px-[18px] py-2.5">
                    <Tip content={<Mono className="break-all">{g?.dn ?? gid}</Mono>}>
                      <p className="w-fit text-[14px] font-medium text-[var(--a-text)]" tabIndex={0}>
                        {g?.name ?? gid}
                      </p>
                    </Tip>
                    {rules.length ? (
                      <div className="mt-1.5 flex flex-col gap-1.5">
                        {rules.map((r) => (
                          <div key={r.id} className="flex flex-wrap items-center gap-2 text-[12px] text-[var(--a-text-3)]">
                            <RuleActionPill action={r.action} />
                            <span className="text-[var(--a-text-2)]">{r.name}</span>
                            {r.vlanId && <VlanChip vlan={vlanById.get(r.vlanId)} compact />}
                            {!r.enabled && <span>(disabled)</span>}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="mt-0.5 text-[12px] text-[var(--a-text-3)]">Not used by any access rule</p>
                    )}
                  </li>
                )
              })}
            </ul>
          </Panel>
        </div>
      </div>

      <IssueCertificateDialog open={issueOpen} onOpenChange={setIssueOpen} identity={identity} />
      {revokeCert && <RevokeDialog key={revokeCert.id} certificate={revokeCert} open={!!revokeId} onOpenChange={(o) => !o && setRevokeId(null)} />}
      <CertificateInspector certificate={inspectCert} open={!!inspectId} onOpenChange={(o) => !o && setInspectId(null)} />
    </>
  )
}
