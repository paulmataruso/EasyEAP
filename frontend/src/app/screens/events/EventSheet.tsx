// One authentication attempt in full: the plain-language explanation and fix from the API, the certificate, the
// deciding rule, where it came from, and the raw RADIUS message. Opens as a side sheet; focus returns to the row.
import type { ReactNode, RefObject } from 'react'
import { Link } from 'react-router'
import { Dialog } from 'radix-ui'
import { ArrowRight, Check, ChevronDown, Minus, X } from 'lucide-react'
import { cn } from '@/ui/lib'
import { controllerFor, useEvent, type AuthEvent, type ClientLite, type RuleLite, type VlanLite } from '../../api/events'
import type { DecisionStep } from '../../api/types'
import { ago, fmtDateTime, fmtSerial } from '../../lib/format'
import { useNow } from '../../lib/useNow'
import { paths } from '../../routes'
import { Btn, Callout, CopyButton, Dl, ErrorState, LoadingBlock, OutcomeChip, VlanTag } from '../../ui'

const linkCls = 'underline decoration-[var(--ee-line-3)] underline-offset-[3px] hover:decoration-[var(--ee-ink)]'

function StepList({ steps, rules }: { steps: DecisionStep[]; rules?: RuleLite[] }) {
  return (
    <ol className="space-y-2">
      {steps.map((s, i) => {
        const ok = s.kind === 'rule' ? s.matched : s.kind === 'default' ? s.action === 'allow' : s.ok
        const skip = s.kind === 'rule' && !s.matched
        const rule = s.ruleId ? rules?.find((r) => r.id === s.ruleId) : undefined
        const kind = s.kind === 'account' ? 'Account' : s.kind === 'certificate' ? 'Certificate' : s.kind === 'default' ? 'Tenant default' : `${s.action === 'deny' ? 'Deny' : 'Allow'} rule${rule ? ` “${rule.name}”` : ''}`
        return (
          <li key={i} className="flex gap-2.5 text-[13px]">
            <span className={cn('mt-[1px] grid size-[18px] shrink-0 place-items-center rounded-full border [&_svg]:size-3',
              skip ? 'border-[var(--ee-line-2)] text-[var(--ee-ink-3)]' : ok && !(s.kind === 'rule' && s.action === 'deny') ? 'border-[rgba(45,212,191,0.55)] text-[var(--ee-valid)]' : 'border-[rgba(244,63,94,0.6)] text-[var(--ee-crit-ink)]')} aria-hidden>
              {skip ? <Minus /> : ok && !(s.kind === 'rule' && s.action === 'deny') ? <Check /> : <X />}
            </span>
            <span className="min-w-0">
              <span className="font-medium">{kind}</span>
              <span className="ee-ink-2"> · {s.detail}</span>
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/** One recovery destination per failure type, only where a real screen fixes it. */
function fixAction(e: AuthEvent, tid: string, can: (p: string) => boolean): { to: string; label: string } | null {
  switch (e.reason_code) {
    case 'cert_expired':
    case 'cert_revoked':
    case 'unknown_ca':
    case 'cert_unknown':
      return e.identity_id && can('certificates:issue') ? { to: paths.user(tid, e.identity_id, { issue: true }), label: 'Issue a new certificate' } : e.identity_id && can('identities:read') ? { to: paths.user(tid, e.identity_id), label: 'Open the user' } : null
    case 'identity_unauthorized':
    case 'policy_deny':
      return can('policy:read') ? { to: paths.policy(tid, e.identity_id ? { test: e.identity_id } : undefined), label: e.identity_id ? 'Test this user against the policy' : 'Review the access policy' } : null
    case 'account_disabled':
      return can('directory:read') ? { to: paths.directory(tid), label: 'Open directory settings' } : null
    case 'snapshot_stale':
      return { to: paths.dashboard(tid), label: 'Check enforcement on the dashboard' }
    case 'vlan_assignment':
      return can('radius:read') ? { to: paths.radius(tid), label: 'Review controllers' } : null
    default:
      return null
  }
}

export function EventSheet({ tid, eventId, seed, open, onOpenChange, returnFocus, lookups, can }: {
  tid: string
  eventId: string | null
  seed?: AuthEvent
  open: boolean
  onOpenChange: (o: boolean) => void
  returnFocus: RefObject<HTMLElement | null>
  lookups: { clients?: ClientLite[]; rules?: RuleLite[]; vlans?: VlanLite[] }
  can: (p: string) => boolean
}) {
  const now = useNow()
  const q = useEvent(tid, open ? eventId : null)
  const e = q.data ?? seed
  const rule = e?.rule_id ? lookups.rules?.find((r) => r.id === e.rule_id) : undefined
  const vlan = e?.vlan_id !== null && e?.vlan_id !== undefined ? lookups.vlans?.find((v) => v.vlan_id === e.vlan_id) : undefined
  const ctrl = e ? controllerFor(lookups.clients, e) : undefined
  const fix = e && e.result === 'reject' ? fixAction(e, tid, can) : null
  const certId = q.data?.certificate_id

  let body: ReactNode
  if (!e) body = q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} title="This attempt couldn’t be loaded" /> : <LoadingBlock rows={6} label="Loading attempt" />
  else {
    const ruleText = rule
      ? (can('policy:read') ? <Link to={paths.policy(tid)} className={linkCls}>{rule.name}</Link> : rule.name)
      : e.rule_id ? 'A rule that has since been deleted'
      : e.result === 'accept' ? 'No rule recorded (tenant default)' : 'None, rejected before access rules were checked'
    const serial = e.cert_serial
      ? <span className="ee-mono text-[12.5px] break-all">{fmtSerial(e.cert_serial)}</span>
      : <span className="ee-ink-3">No certificate presented</span>
    body = (
      <div className="space-y-6">
        {e.result === 'reject' ? (
          <Callout tone="crit" title={e.explanation?.title ?? (e.reason_code ? `Rejected (${e.reason_code})` : 'Rejected')}>
            {e.explanation ? (
              <div className="space-y-2.5">
                <p>{e.explanation.explanation}</p>
                <p><span className="font-semibold text-[var(--ee-ink)]">How to fix it: </span>{e.explanation.fix}</p>
                {fix && (
                  <Link to={fix.to} className="ee-btn ee-btn-sm mt-1">{fix.label}<ArrowRight aria-hidden /></Link>
                )}
              </div>
            ) : (
              <p>RADIUS didn’t report a reason EasyEAP recognises. Check the raw message below.</p>
            )}
          </Callout>
        ) : (
          <Callout tone="valid" title="Accepted">
            RADIUS accepted this device{rule ? <> under the rule “{rule.name}”</> : ''}{e.vlan_id !== null ? <> and placed it on VLAN {e.vlan_id}{vlan ? ` (${vlan.name})` : ''}</> : ''}.
          </Callout>
        )}

        <section aria-labelledby="ev-who">
          <h3 id="ev-who" className="ee-h3 mb-3">Details</h3>
          <Dl
            items={[
              ['User', e.identity_id && can('identities:read')
                ? <Link to={paths.user(tid, e.identity_id)} className={cn('font-medium', linkCls)}>{e.username ?? 'Open user'}</Link>
                : <span className={cn(!e.username && 'ee-ink-3')}>{e.username ?? 'Unknown user'}{e.username && !e.identity_id && <span className="ee-ink-3"> · not matched to a user</span>}</span>],
              ['Device MAC', e.calling_station_id ? <span className="ee-mono text-[12.5px]">{e.calling_station_id}</span> : <span className="ee-ink-3">Not reported</span>],
              ['Certificate serial', <span className="flex flex-col gap-1">
                {certId && can('certificates:read') ? <Link to={paths.certificate(tid, certId)} className={linkCls}>{serial}</Link> : serial}
                {e.cert_serial && q.data && !certId && <span className="ee-small ee-ink-3">Not issued by this tenant’s EasyEAP CA</span>}
              </span>, 'wide'],
              ['Certificate issuer', e.cert_issuer ? <span className="ee-mono text-[12.5px] break-all">{e.cert_issuer}</span> : <span className="ee-ink-3">—</span>, 'wide'],
              ['Deciding rule', ruleText],
              ['VLAN', e.vlan_id !== null ? <VlanTag vlanId={e.vlan_id} name={vlan?.name} color={vlan?.color} /> : <span className="ee-ink-3">None assigned</span>],
              ['Controller', ctrl
                ? (can('radius:read') ? <Link to={paths.radius(tid)} className={linkCls}>{ctrl.name}</Link> : ctrl.name)
                : <span className="ee-ink-3">{e.nas_ip ? 'Not a registered controller' : 'Unknown'}</span>],
              ['NAS address', e.nas_ip ? <span className="ee-mono text-[12.5px]">{e.nas_ip}</span> : <span className="ee-ink-3">—</span>],
              ['SSID', e.ssid ?? <span className="ee-ink-3">Not reported</span>],
              ['Called station', e.called_station_id ? <span className="ee-mono text-[12.5px] break-all">{e.called_station_id}</span> : <span className="ee-ink-3">—</span>],
              ['Reason code', e.reason_code ? <span className="ee-mono text-[12.5px]">{e.reason_code}</span> : <span className="ee-ink-3">—</span>],
              ['Event ID', <span className="ee-mono text-[12.5px]">{e.id}</span>],
            ]}
          />
        </section>

        {q.data?.decision_steps && q.data.decision_steps.length > 0 && (
          <section aria-labelledby="ev-now">
            <h3 id="ev-now" className="ee-h3">How EasyEAP decides for this certificate now</h3>
            <p className="ee-small ee-ink-3 mt-1 mb-3">Recomputed after every policy or directory change, so it can differ from the decision RADIUS made at the time of this attempt.</p>
            <StepList steps={q.data.decision_steps} rules={lookups.rules} />
          </section>
        )}

        <details className="group rounded-[8px] border border-[var(--ee-line)]">
          <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-[13px] font-medium [&::-webkit-details-marker]:hidden">
            <ChevronDown className="size-4 ee-ink-3 transition-transform group-open:rotate-180" aria-hidden />
            Raw RADIUS message
          </summary>
          <div className="space-y-2 px-3 pb-3">
            {e.raw_message ? (
              <>
                <pre className="ee-code whitespace-pre-wrap break-all">{e.raw_message}</pre>
                <CopyButton text={e.raw_message} what="raw RADIUS message" />
              </>
            ) : (
              <p className="ee-small ee-ink-2">RADIUS didn’t log a message for this attempt.</p>
            )}
          </div>
        </details>
      </div>
    )
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="ee-backdrop" />
        <Dialog.Content
          className="ee-sheet"
          aria-describedby={undefined}
          onCloseAutoFocus={(ev) => {
            ev.preventDefault()
            const t = returnFocus.current
            ;(t && t.isConnected ? t : document.querySelector<HTMLElement>('[data-page-heading]'))?.focus()
          }}
        >
          <div className="sticky top-0 z-[1] flex items-start justify-between gap-4 border-b border-[var(--ee-line)] bg-[#10172a] px-5 py-4 sm:px-6">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                {e && <OutcomeChip outcome={e.result} />}
                <Dialog.Title className="ee-h2 text-[17px]">{!e ? 'Authentication attempt' : e.result === 'reject' ? (e.explanation?.title ?? 'Rejected') : `Accepted${e.vlan_id !== null ? ` to VLAN ${e.vlan_id}` : ''}`}</Dialog.Title>
              </div>
              {e && <p className="ee-small ee-ink-2 mt-1.5">{fmtDateTime(e.at)} · {ago(e.at, now)}</p>}
            </div>
            <Dialog.Close asChild>
              <Btn variant="ghost" size="sm" icon aria-label="Close"><X aria-hidden /></Btn>
            </Dialog.Close>
          </div>
          <div className="px-5 py-5 sm:px-6">{body}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
