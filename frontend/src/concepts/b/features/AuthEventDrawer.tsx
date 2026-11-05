import { CircleCheck, FileKey2, ShieldX, UserRound } from 'lucide-react'
import { useTenantData } from '@/prototype/store'
import { failureExplanations, vendorLabels } from '@/domain/explain'
import { formatDateTime, formatSerial } from '@/ui/lib'
import { Drawer } from '../ui/Drawer'
import { Button } from '../ui/Button'
import { StatusBadge, VlanChip } from '../ui/Badge'
import { KeyValue, Notice } from '../ui/Panel'
import { rel } from '../lib/format'

/** One RADIUS authentication, explained in plain language with the raw module output one click away. */
export function AuthEventDrawer({ eventId, open, onOpenChange, onOpenUser, onOpenCertificate }: { eventId: string; open: boolean; onOpenChange: (o: boolean) => void; onOpenUser: (id: string) => void; onOpenCertificate: (id: string) => void }) {
  const d = useTenantData()
  const ev = d.authEvents.find((e) => e.id === eventId)
  if (!ev) {
    return (
      <Drawer open={open} onOpenChange={onOpenChange} title="Event not found">
        <Notice tone="warn">This authentication belongs to another tenant.</Notice>
      </Drawer>
    )
  }
  const identity = d.identities.find((i) => i.id === ev.identityId)
  const device = d.devices.find((x) => x.id === ev.deviceId)
  const nas = d.radiusClients.find((n) => n.id === ev.nasClientId)
  const vlan = d.vlans.find((v) => v.id === ev.vlanId)
  const rule = d.rules.find((r) => r.id === ev.ruleId)
  const cert = ev.certSerial ? d.certificates.find((c) => c.serial === ev.certSerial) : undefined
  const why = ev.failureCode ? failureExplanations[ev.failureCode] : null
  const accepted = ev.result === 'accept'

  return (
    <Drawer
      open={open}
      onOpenChange={onOpenChange}
      width={520}
      title={`${accepted ? 'Accepted' : 'Rejected'}: ${identity?.displayName ?? ev.username ?? 'Unknown user'}`}
      description={`${formatDateTime(ev.at)} · ${rel(ev.at)}`}
      meta={
        <>
          {accepted ? <StatusBadge tone="ok">Access-Accept</StatusBadge> : <StatusBadge tone="crit">Access-Reject</StatusBadge>}
          {vlan && <VlanChip vlan={vlan} />}
          {ev.failureCode && <span className="b-chip b-mono">{ev.failureCode}</span>}
        </>
      }
      footer={
        <>
          {identity && (
            <Button icon={UserRound} onClick={() => onOpenUser(identity.id)}>
              Open user
            </Button>
          )}
          {cert && (
            <Button icon={FileKey2} onClick={() => onOpenCertificate(cert.id)}>
              View certificate
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        {why ? (
          <Notice tone="crit" title={why.title} icon={ShieldX}>
            <p>{why.explanation}</p>
            <p className="mt-1.5">
              <span className="font-semibold text-[var(--b-text)]">Fix: </span>
              {why.fix}
            </p>
          </Notice>
        ) : (
          <Notice tone="ok" title="Authenticated with EAP-TLS" icon={CircleCheck}>
            {rule ? `Allowed by “${rule.name}”` : 'Allowed'}
            {vlan ? `, placed on VLAN ${vlan.vlanId} (${vlan.name}).` : '.'}
          </Notice>
        )}
        <KeyValue
          rows={[
            ['User', identity ? <button type="button" className="b-link" onClick={() => onOpenUser(identity.id)}>{identity.displayName}</button> : ev.username ?? '—'],
            ['Identity', <span key="u" className="b-mono break-all">{ev.username ?? '—'}</span>],
            ['Device', device?.name ?? 'Unknown device'],
            ['Certificate', ev.certSerial ? (cert ? <button type="button" className="b-link b-mono" onClick={() => onOpenCertificate(cert.id)}>{formatSerial(ev.certSerial)}</button> : <span className="b-mono">{formatSerial(ev.certSerial)} <span className="b-t3">(not issued by EasyEAP)</span></span>) : 'None presented'],
            ['Client MAC', <span key="m" className="b-mono">{ev.callingStationId ?? '—'}</span>],
            ['Access point', <span key="ap" className="b-mono break-all">{ev.calledStationId ?? '—'}</span>],
            ['SSID', ev.ssid ?? '—'],
            ['Controller', nas ? `${nas.name} · ${vendorLabels[nas.vendor]}` : '—'],
            ['Decided by', rule ? rule.name : accepted ? 'Tenant default' : ev.failureCode === 'policy_deny' ? 'Deny rule' : 'Certificate or account check'],
          ]}
        />
        {ev.rawMessage && (
          <details className="group rounded-md border border-[var(--b-line)] bg-[var(--b-sunken)]">
            <summary className="flex items-center gap-2 px-3 py-2 text-[12.5px] font-medium text-[var(--b-text-2)] hover:text-[var(--b-text)]">Technical details (FreeRADIUS)</summary>
            <pre className="b-mono overflow-x-auto border-t border-[var(--b-line)] px-3 py-2.5 text-[12px] whitespace-pre-wrap text-[var(--b-text)]">{ev.rawMessage}</pre>
          </details>
        )}
      </div>
    </Drawer>
  )
}
