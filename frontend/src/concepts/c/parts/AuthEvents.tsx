import { useState, type ReactNode } from 'react'
import { CircleCheck, CircleX, Wrench } from 'lucide-react'
import { useTenantData } from '@/prototype/store'
import { failureExplanations } from '@/domain/explain'
import type { AuthEvent } from '@/domain/types'
import { formatDateTime, formatSerial } from '@/ui/lib'
import { Cell, DataTable, toggleInSet, type ColumnDef } from '../ui/DataTable'
import { StatusMark } from '../ui/Status'
import { VlanTag } from '../ui/Vlan'
import { DefList, Note } from '../ui/Layout'
import { since } from '../lib/format'
import { INTENDED_REJECTIONS } from '../lib/posture'

/**
 * Authentication events as list rows. Failures read in plain language; the raw FreeRADIUS
 * message and identifiers sit one click away in the inline expansion.
 */
export function AuthEventsTable({ events, showPerson = true, caption, empty, onOpenPerson }: { events: AuthEvent[]; showPerson?: boolean; caption: string; empty?: ReactNode; onOpenPerson?: (identityId: string) => void }) {
  const d = useTenantData()
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const person = (e: AuthEvent) => d.identities.find((i) => i.id === e.identityId)
  const nas = (e: AuthEvent) => d.radiusClients.find((n) => n.id === e.nasClientId)
  const device = (e: AuthEvent) => d.devices.find((x) => x.id === e.deviceId)

  const columns: ColumnDef<AuthEvent>[] = [
    { key: 'at', header: 'When', tight: true, cell: (e) => <span className="c-muted tnum">{since(e.at)}</span> },
    ...(showPerson
      ? [
          {
            key: 'who',
            header: 'Person',
            cell: (e: AuthEvent) => {
              const p = person(e)
              return (
                <Cell
                  primary={p && onOpenPerson ? <button type="button" className="c-rowlink" onClick={() => onOpenPerson(p.id)}>{p.displayName}</button> : (p?.displayName ?? e.username ?? 'Unknown identity')}
                  secondary={device(e)?.name ?? (e.certSerial ? 'Unrecognised certificate' : 'No certificate presented')}
                />
              )
            },
          } satisfies ColumnDef<AuthEvent>,
        ]
      : [{ key: 'device', header: 'Device', cell: (e: AuthEvent) => <Cell primary={device(e)?.name ?? 'Unknown device'} secondary={e.ssid ?? undefined} /> } satisfies ColumnDef<AuthEvent>]),
    {
      key: 'result',
      header: 'Result',
      cell: (e) =>
        e.result === 'accept' ? (
          <span style={{ display: 'grid', gap: 2 }}>
            <StatusMark tone="ok" icon={CircleCheck} label="Accepted" />
          </span>
        ) : (
          <span style={{ display: 'grid', gap: 2 }}>
            <StatusMark tone="crit" icon={CircleX} label={e.failureCode ? failureExplanations[e.failureCode].title : 'Rejected'} />
          </span>
        ),
    },
    {
      key: 'vlan',
      header: 'VLAN',
      hide: 'md',
      cell: (e) => {
        const v = d.vlans.find((x) => x.id === e.vlanId)
        return v ? <VlanTag vlan={v} showName={false} /> : <span className="c-faint">None</span>
      },
    },
    { key: 'nas', header: 'Controller', hide: 'lg', cell: (e) => <Cell primary={<span style={{ fontWeight: 400 }}>{nas(e)?.name ?? 'Unknown'}</span>} secondary={e.ssid ?? undefined} /> },
  ]

  return (
    <DataTable
      caption={caption}
      columns={columns}
      rows={events}
      rowKey={(e) => e.id}
      expanded={expanded}
      onToggle={(k) => setExpanded((s) => toggleInSet(s, k))}
      expandLabel={(e) => `${person(e)?.displayName ?? 'event'} at ${formatDateTime(e.at)}`}
      empty={empty}
      renderExpanded={(e) => <EventDetail event={e} />}
    />
  )
}

function EventDetail({ event: e }: { event: AuthEvent }) {
  const d = useTenantData()
  const x = e.failureCode ? failureExplanations[e.failureCode] : null
  const rule = d.rules.find((r) => r.id === e.ruleId)
  const nas = d.radiusClients.find((n) => n.id === e.nasClientId)
  const intended = e.failureCode ? INTENDED_REJECTIONS.includes(e.failureCode) : false
  return (
    <div style={{ display: 'grid', gap: 18, gridTemplateColumns: 'minmax(0, 1fr)', maxWidth: 920 }}>
      {x ? (
        <div style={{ display: 'grid', gap: 10 }}>
          <p style={{ margin: 0, maxWidth: '72ch' }}>{x.explanation}</p>
          <Note icon={Wrench}>
            <strong>{intended ? 'Working as intended. ' : 'To fix: '}</strong>
            {x.fix}
          </Note>
        </div>
      ) : (
        <p style={{ margin: 0 }} className="c-muted">
          Accepted{rule ? ` by “${rule.name}”` : ''} and placed on VLAN {d.vlans.find((v) => v.id === e.vlanId)?.vlanId ?? '—'}.
        </p>
      )}
      <div>
        <div className="c-faint c-small" style={{ marginBottom: 6 }}>
          Technical details
        </div>
        <DefList
          items={[
            { label: 'Time', value: <span className="tnum">{formatDateTime(e.at)}</span> },
            { label: 'Identity', value: e.username ?? 'Not presented' },
            { label: 'Certificate serial', value: e.certSerial ? <span className="c-mono">{formatSerial(e.certSerial)}</span> : 'None' },
            { label: 'Client MAC', value: <span className="c-mono">{e.callingStationId ?? '—'}</span> },
            { label: 'Access point / SSID', value: <span className="c-mono">{e.calledStationId ?? '—'}</span> },
            { label: 'Controller', value: nas ? `${nas.name} (${nas.address})` : 'Unknown' },
            ...(e.rawMessage ? [{ label: 'FreeRADIUS message', value: <code className="c-raw" style={{ display: 'block' }}>{e.rawMessage}</code> }] : []),
          ]}
        />
      </div>
    </div>
  )
}
