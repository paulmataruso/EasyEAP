import { useMemo, type ReactNode } from 'react'
import { ChevronRight, FileKey2, KeyRound, ServerCog, ShieldCheck } from 'lucide-react'
import { now, useTenantData, useTenants } from '@/prototype/store'
import { certStatusLabels, revocationReasonLabels } from '@/domain/explain'
import type { Certificate, CertStatus } from '@/domain/types'
import { cn, daysUntil, formatDate } from '@/ui/lib'
import { PageHeader } from '../ui/PageHeader'
import { EmptyState, Panel, PanelHead } from '../ui/Panel'
import { Button } from '../ui/Button'
import { CertStatusBadge, StatusText } from '../ui/Badge'
import { SearchInput } from '../ui/SearchInput'
import { ALL, DataTable, useDataTable, type ColumnDef } from '../ui/DataTable'
import { useInspector } from '../shell/Inspectors'
import { useIntent, useShell } from '../shell/context'
import { formatAge, secondsSince, shortSerial } from '../lib/format'
import { keyAlgorithmLabels } from '../lib/labels'
import { certTone } from '../lib/status'

const STATUSES: CertStatus[] = ['active', 'expiring', 'expired', 'revoked']

export function CertificatesScreen() {
  const { current } = useTenants()
  const d = useTenantData()
  const { openCertificate, active } = useInspector()
  const { go } = useShell()
  const root = d.cas.find((c) => c.role === 'root')
  const issuing = d.cas.find((c) => c.role === 'issuing')

  const lookup = useMemo(
    () => ({
      identity: new Map(d.identities.map((i) => [i.id, i])),
      device: new Map(d.devices.map((x) => [x.id, x])),
      ca: new Map(d.cas.map((c) => [c.id, c])),
      template: new Map(d.templates.map((t) => [t.id, t])),
    }),
    [d.identities, d.devices, d.cas, d.templates],
  )

  const columns = useMemo<ColumnDef<Certificate>[]>(
    () => [
      {
        id: 'serial',
        header: 'Serial',
        sticky: true,
        width: 150,
        sort: (c) => c.serial,
        search: (c) => c.serial,
        cell: (c) => <span className="b-mono text-[12px] text-[var(--b-text)]">{shortSerial(c.serial)}</span>,
      },
      {
        id: 'subject',
        header: 'Subject',
        sort: (c) => c.commonName,
        search: (c) => c.subject,
        cell: (c) => <span className="b-mono block max-w-[230px] truncate text-[12px] text-[var(--b-text-2)]">{c.commonName}</span>,
      },
      {
        id: 'owner',
        header: 'User · device',
        sort: (c) => (c.identityId ? lookup.identity.get(c.identityId)?.displayName ?? '' : 'zz'),
        search: (c) => [c.identityId ? lookup.identity.get(c.identityId)?.displayName : 'RADIUS server', c.deviceId ? lookup.device.get(c.deviceId)?.name : ''].join(' '),
        cell: (c) => {
          if (!c.identityId)
            return (
              <span className="inline-flex items-center gap-1.5 text-[var(--b-text)]">
                <ServerCog className="size-3.5 text-[var(--b-text-2)]" aria-hidden /> RADIUS server
              </span>
            )
          const who = lookup.identity.get(c.identityId)
          const dev = c.deviceId ? lookup.device.get(c.deviceId) : undefined
          return (
            <span className="block max-w-[240px] truncate">
              <span className="text-[var(--b-text)]">{who?.displayName ?? 'Unknown user'}</span>
              {dev && <span className="text-[var(--b-text-3)]"> · {dev.name.replace(`${who?.displayName.split(' ')[0]}'s `, '')}</span>}
            </span>
          )
        },
      },
      {
        id: 'ca',
        header: 'Issuing CA',
        sort: (c) => lookup.ca.get(c.issuerCaId)?.commonName ?? '',
        filter: { kind: 'select', allLabel: 'Any CA', options: d.cas.filter((c) => c.role === 'issuing').map((c) => ({ value: c.id, label: c.commonName })), test: (c, v) => c.issuerCaId === v },
        cell: (c) => <span className="text-[var(--b-text-2)]">{lookup.ca.get(c.issuerCaId)?.commonName}</span>,
      },
      { id: 'issued', header: 'Issued', align: 'end', sort: (c) => c.notBefore, cell: (c) => <span className="b-num text-[var(--b-text-2)]">{formatDate(c.notBefore)}</span> },
      {
        id: 'expires',
        header: 'Expires',
        align: 'end',
        sort: (c) => c.notAfter,
        cell: (c) => {
          const days = daysUntil(c.notAfter, now())
          return (
            <span className={cn('b-num', c.status === 'expiring' ? 'b-ink-warn' : c.status === 'expired' ? 'b-ink-crit' : 'text-[var(--b-text-2)]')}>
              {formatDate(c.notAfter)}
              {c.status !== 'revoked' && days > -60 && days <= 30 && <span className="ml-1.5 text-[12px]">{days < 0 ? `${-days}d ago` : `${days}d`}</span>}
            </span>
          )
        },
      },
      {
        id: 'status',
        header: 'Status',
        width: 132,
        sort: (c) => STATUSES.indexOf(c.status),
        filter: { kind: 'select', allLabel: 'Any status', options: STATUSES.map((s) => ({ value: s, label: certStatusLabels[s] })), test: (c, v) => c.status === v },
        cell: (c) => <CertStatusBadge status={c.status} />,
      },
      {
        id: 'revocation',
        header: 'Revocation',
        sort: (c) => c.revokedAt,
        search: (c) => (c.revocationReason ? revocationReasonLabels[c.revocationReason] : null),
        cell: (c) =>
          c.status === 'revoked' ? (
            <span className="block max-w-[200px] truncate text-[12.5px] text-[var(--b-text-2)]" title={c.revokedBy ?? undefined}>
              {c.revocationReason ? revocationReasonLabels[c.revocationReason] : 'Revoked'} · {c.revokedAt ? formatDate(c.revokedAt) : ''}
            </span>
          ) : (
            <span className="text-[var(--b-text-3)]">—</span>
          ),
      },
    ],
    [d.cas, lookup],
  )

  const table = useDataTable(d.certificates, columns, { initialSort: { key: 'expires', dir: 'asc' } })
  useIntent('certificates', (intent) => {
    if (intent.filters) {
      table.setFilters({ status: intent.filters.status ?? ALL })
      table.setQuery('')
    }
  })

  const client = d.certificates.filter((c) => c.identityId)
  const counts = Object.fromEntries(STATUSES.map((s) => [s, client.filter((c) => c.status === s).length])) as Record<CertStatus, number>
  const statusFilter = table.filters.status ?? ALL
  const revocations = d.audit.filter((a) => a.action === 'certificate.revoke' || a.action === 'pki.crl.publish').slice(0, 5)

  return (
    <>
      <PageHeader title="Certificates" context={`${client.length} Wi-Fi certificates${issuing ? ` · issued by ${issuing.commonName}` : ''} · ${current.name}`} />

      <Panel id="b-sec-authorities" aria-labelledby="pki-title" className="mb-3">
        <PanelHead id="pki-title" title="Certificate authorities" meta="chain of trust and revocation status" />
        <div className="grid xl:grid-cols-[minmax(0,1fr)_auto]">
          <div className="grid md:grid-cols-[minmax(0,1fr)_20px_minmax(0,1fr)_20px_minmax(0,1fr)]">
            <ChainStage
              icon={KeyRound}
              title={root?.commonName ?? 'No root CA'}
              status={root ? <StatusText tone="ok">Offline root · key not held by EasyEAP</StatusText> : <StatusText tone="neutral">Not initialised</StatusText>}
              lines={root ? [`${keyAlgorithmLabels[root.keyAlgorithm]} · valid until ${formatDate(root.notAfter)}`, root.crl?.nextUpdate ? `Root CRL #${root.crl.number} · next ${formatDate(root.crl.nextUpdate)}` : 'No root CRL'] : []}
            />
            <ChainArrow />
            <ChainStage
              icon={ShieldCheck}
              title={issuing?.commonName ?? 'No issuing CA'}
              status={issuing ? <StatusText tone="ok">Online · signs Wi-Fi certificates</StatusText> : <StatusText tone="neutral">Not initialised</StatusText>}
              lines={issuing ? [`${keyAlgorithmLabels[issuing.keyAlgorithm]} · expires ${formatDate(issuing.notAfter)}`, `in ${Math.round(daysUntil(issuing.notAfter, now()) / 365.25 * 10) / 10} years · serial ${issuing.serial.slice(0, 8)}…`] : []}
            />
            <ChainArrow />
            <ChainStage
              icon={FileKey2}
              title="Revocation"
              role="CRL and OCSP"
              status={issuing?.crl?.nextUpdate ? <StatusText tone="ok">CRL #{issuing.crl.number} current</StatusText> : <StatusText tone="neutral">No CRL yet</StatusText>}
              lines={
                issuing?.crl
                  ? [
                      `Published ${formatAge(secondsSince(issuing.crl.lastIssued))} ago · next update in ${formatAge(issuing.crl.nextUpdate ? (new Date(issuing.crl.nextUpdate).getTime() - now().getTime()) / 1000 : null)}`,
                      issuing.ocsp?.enabled ? `OCSP responding · ${issuing.ocsp.url?.replace(/^https?:\/\//, '')}` : 'OCSP not enabled',
                    ]
                  : []
              }
            />
          </div>
          <div className="border-t border-[var(--b-line)] px-3 py-3 xl:border-t-0 xl:border-l xl:pl-4" role="group" aria-label="Filter by status">
            <p className="mb-1.5 text-[12.5px] text-[var(--b-text-2)]">Wi-Fi certificates by status</p>
            <div className="grid grid-cols-4 gap-1 xl:w-[300px]">
              {STATUSES.map((s) => (
                <button
                  key={s}
                  type="button"
                  aria-pressed={statusFilter === s}
                  onClick={() => table.setFilter('status', statusFilter === s ? ALL : s)}
                  className={cn('rounded-md px-2 py-1.5 text-left transition-colors hover:bg-[var(--b-hover)]', statusFilter === s && 'bg-[var(--b-cyan-wash)] ring-1 ring-[rgba(34,211,238,0.35)] ring-inset')}
                >
                  <span className="b-figure block text-[24px] text-[var(--b-text)]">{counts[s]}</span>
                  <StatusText tone={certTone[s]} className="mt-1 text-[12px]">
                    {certStatusLabels[s].replace(' soon', '')}
                  </StatusText>
                </button>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      <Panel id="b-sec-inventory" aria-label="Certificate inventory" className="mb-3">
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--b-line)] px-3 py-2">
          <h2 className="b-panel-title mr-2">All certificates</h2>
          <SearchInput className="w-full sm:ml-auto sm:w-[320px]" value={table.query} onChange={table.setQuery} placeholder="Serial, user, device or reason" label="Search certificates" />
        </div>
        {d.certificates.length === 0 ? (
          <EmptyState icon={FileKey2} title="No certificates issued yet" action={<Button variant="primary" onClick={() => go('users')}>Choose a user</Button>}>
            Certificates are issued per device from a user’s page. Open a user, choose <span className="text-[var(--b-text)]">Issue Wi-Fi certificate</span>, and send them the one-time enrollment link.
          </EmptyState>
        ) : (
          <DataTable
            table={table}
            label="Certificates"
            noun="certificates"
            rowKey={(c) => c.id}
            rowLabel={(c) => `${c.commonName} ${certStatusLabels[c.status]}`}
            isActive={(c) => active?.kind === 'cert' && active.id === c.id}
            onActivate={(c) => openCertificate(c.id)}
          />
        )}
      </Panel>

      <Panel aria-labelledby="rev-title">
        <PanelHead id="rev-title" title="Revocation activity" meta="from the audit trail" />
        {revocations.length === 0 ? (
          <p className="b-t2 px-3 py-4 text-[12.5px]">No revocations recorded for this tenant.</p>
        ) : (
          <ul className="b-divide-y">
            {revocations.map((a) => (
              <li key={a.id} className="grid gap-x-3 px-3 py-2 text-[13px] sm:grid-cols-[110px_150px_minmax(0,1fr)]">
                <span className="b-num text-[12px] text-[var(--b-text-2)]">{a.at > now().toISOString() ? 'just now' : `${formatAge(secondsSince(a.at))} ago`}</span>
                <span className="b-mono text-[12px] text-[var(--b-text-2)]">{a.action}</span>
                <span className="min-w-0">
                  <span className="text-[var(--b-text)]">{a.target}</span> <span className="text-[var(--b-text-2)]">· {a.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  )
}

function ChainStage({ icon: Icon, title, role, status, lines }: { icon: typeof KeyRound; title: string; role?: string; status: ReactNode; lines: string[] }) {
  return (
    <div className="min-w-0 px-3 py-3">
      <div className="flex items-center gap-2">
        <span className="grid size-7 shrink-0 place-items-center rounded-md border border-[var(--b-line-strong)] bg-[var(--b-sunken)] text-[var(--b-cyan)]">
          <Icon className="size-3.5" aria-hidden />
        </span>
        <h3 className="min-w-0 truncate text-[13.5px] font-semibold text-[var(--b-text)]">
          {title}
          {role && <span className="font-normal text-[var(--b-text-2)]"> · {role}</span>}
        </h3>
      </div>
      <div className="mt-2 text-[12.5px]">{status}</div>
      {lines.map((l) => (
        <p key={l} className="b-num mt-0.5 truncate text-[12px] text-[var(--b-text-2)]" title={l}>
          {l}
        </p>
      ))}
    </div>
  )
}

function ChainArrow() {
  return (
    <div className="hidden items-center justify-center md:flex" aria-hidden>
      <ChevronRight className="size-4 text-[var(--b-text-3)]" />
    </div>
  )
}
