import type { ReactNode } from 'react'
import { ArrowDown, ArrowUp } from 'lucide-react'
import type { AccessRule, Decision, DirectoryGroup, PolicyDefaults, Vlan } from '@/domain/types'
import { cn } from '@/ui/lib'
import { INK, LINE, REJECT } from './theme'
import { Button, LineBullet, RejectBullet, Switch } from './ui'

type Stop =
  | { kind: 'gate'; id: string; title: string; detail: string }
  | { kind: 'rule'; id: string; rule: AccessRule }
  | { kind: 'default'; id: string }
  | { kind: 'heading'; id: string; title: string; detail: string }

type Pass = 'passed' | 'stop' | 'unreached' | 'skipped' | null

/**
 * Policy precedence drawn as a route: rules are stops in evaluation order (gates, then every deny
 * rule, then allow rules by priority, then the tenant default). A tested identity's route runs solid
 * to the first stop that decides and fades after it.
 */
export function PolicyRoute({ rules, vlans, groups, defaults, decision, editable, onMove, onToggle, showCertGate }: {
  rules: AccessRule[]
  vlans: Vlan[]
  groups: DirectoryGroup[]
  defaults: PolicyDefaults
  decision?: Decision | null
  editable?: boolean
  onMove?: (id: string, dir: -1 | 1) => void
  onToggle?: (id: string) => void
  showCertGate?: boolean
}) {
  const deny = rules.filter((r) => r.action === 'deny')
  const allow = rules.filter((r) => r.action === 'allow')
  const certStep = decision?.steps.find((s) => s.kind === 'certificate')
  const stops: Stop[] = [
    { kind: 'gate', id: 'account', title: 'Account check', detail: 'Disabled, locked or deleted directory accounts are always denied.' },
    ...(showCertGate || certStep ? [{ kind: 'gate' as const, id: 'certificate', title: 'Certificate check', detail: 'Revoked or expired certificates are always denied.' }] : []),
    { kind: 'heading', id: 'h-deny', title: 'Deny rules', detail: 'Checked before any allow rule, wherever they sit. Deny always wins.' },
    ...deny.map((r) => ({ kind: 'rule' as const, id: r.id, rule: r })),
    { kind: 'heading', id: 'h-allow', title: 'Allow rules', detail: 'Lowest priority number first. The first match assigns the VLAN.' },
    ...allow.map((r) => ({ kind: 'rule' as const, id: r.id, rule: r })),
    { kind: 'default', id: 'default' },
  ]

  // Where does the tested route stop?
  let stopId: string | null = null
  if (decision) {
    const acct = decision.steps.find((s) => s.kind === 'account')
    if (acct && acct.kind === 'account' && !acct.ok) stopId = 'account'
    else if (certStep && certStep.kind === 'certificate' && !certStep.ok) stopId = 'certificate'
    else if (decision.decidingRuleId) stopId = decision.decidingRuleId
    else stopId = 'default'
  }
  const stopIndex = stopId ? stops.findIndex((s) => s.id === stopId) : -1
  const passOf = (s: Stop, i: number): Pass => {
    if (!decision) return null
    if (s.kind === 'rule' && !s.rule.enabled) return i < stopIndex ? 'skipped' : 'unreached'
    if (i < stopIndex) return 'passed'
    if (i === stopIndex) return 'stop'
    return 'unreached'
  }
  const vlanOf = (id: string | null) => vlans.find((v) => v.id === id)
  const groupNames = (ids: string[]) => ids.map((g) => groups.find((x) => x.id === g)?.name ?? g)

  const lastRuleIdx = (list: AccessRule[], r: AccessRule) => list.indexOf(r)

  return (
    <ol className="relative" aria-label={decision ? 'Decision route' : 'Access rules in evaluation order'}>
      {stops.map((s, i) => {
        const pass = passOf(s, i)
        const isLast = i === stops.length - 1
        const reachedAbove = decision ? i <= stopIndex : true
        const reachedBelow = decision ? i < stopIndex : !isLast
        if (s.kind === 'heading') {
          return (
            <li key={s.id} className="e-stop-row !min-h-[44px]">
              <Rail top={reachedAbove} bottom={reachedBelow} tested={!!decision} marker={null} />
              <div className="pt-3">
                <p className="text-[12.5px] font-bold">{s.title}</p>
                <p className="t2 text-[12px]">{s.detail}</p>
              </div>
              <span />
            </li>
          )
        }
        let marker: ReactNode
        let body: ReactNode
        let aside: ReactNode = null
        if (s.kind === 'gate') {
          marker = <Marker color={INK.station} shape="circle" pass={pass} />
          const st = decision?.steps.find((x) => x.kind === s.id)
          body = (
            <>
              <p className="font-semibold">{s.title}</p>
              <p className="t2 text-[12.5px]">{st && 'detail' in st ? st.detail : s.detail}</p>
            </>
          )
        } else if (s.kind === 'default') {
          const v = vlanOf(defaults.defaultVlanId)
          marker = <Marker color={defaults.defaultAction === 'deny' ? REJECT.hex : v ? LINE[v.color].hex : INK.station} shape="square" pass={pass} />
          body = (
            <>
              <p className="font-semibold">Tenant default: {defaults.defaultAction === 'deny' ? 'Deny' : 'Allow'}</p>
              <p className="t2 text-[12.5px]">When no rule matches. Missing or stale authorization data also denies.</p>
            </>
          )
          aside = defaults.defaultAction === 'deny' ? <Terminus reject /> : v ? <Terminus vlan={v} /> : null
        } else {
          const r = s.rule
          const v = vlanOf(r.vlanId)
          const color = r.action === 'deny' ? REJECT.hex : v ? LINE[v.color].hex : INK.station
          marker = <Marker color={color} shape={r.action === 'deny' ? 'diamond' : 'circle'} pass={pass} disabled={!r.enabled} />
          const list = r.action === 'deny' ? deny : allow
          const idx = lastRuleIdx(list, r)
          body = (
            <>
              <p className={cn('flex flex-wrap items-center gap-x-2 font-semibold', !r.enabled && 'line-through decoration-[1.5px] opacity-60')}>
                <span className="t3 num text-[12px] font-semibold no-underline">P{r.priority}</span>
                {r.name}
                {!r.enabled && <span className="e-tag !h-5 no-underline">Disabled</span>}
              </p>
              <p className="t2 text-[12.5px]">
                {r.action === 'deny' ? 'Deny' : 'Allow'} if member of {groupNames(r.groupIds).join(', ') || 'no groups'}
                {r.extraAttributes.length > 0 && <> · also sends {r.extraAttributes.map((a) => a.name).join(', ')}</>}
              </p>
            </>
          )
          aside = (
            <div className="flex items-center gap-2">
              {pass === 'stop' || !decision ? (r.action === 'deny' ? <Terminus reject compact={!!editable} /> : v ? <Terminus vlan={v} compact={!!editable} /> : null) : null}
              {decision && pass !== 'stop' && <PassLabel pass={pass} matched={!!decision.steps.find((x) => x.kind === 'rule' && x.ruleId === r.id && x.matched)} />}
              {editable && (
                <div className="ml-2 flex items-center gap-1">
                  <Button size="sm" variant="ghost" icon aria-label={`Move ${r.name} up`} disabled={idx === 0} onClick={() => onMove?.(r.id, -1)}><ArrowUp /></Button>
                  <Button size="sm" variant="ghost" icon aria-label={`Move ${r.name} down`} disabled={idx === list.length - 1} onClick={() => onMove?.(r.id, 1)}><ArrowDown /></Button>
                  <span className="ml-1.5"><Switch checked={r.enabled} onCheckedChange={() => onToggle?.(r.id)} label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`} /></span>
                </div>
              )}
            </div>
          )
        }
        return (
          <li key={s.id} className={cn('e-stop-row py-1.5', pass === 'unreached' && 'opacity-55')} aria-current={pass === 'stop' ? 'step' : undefined}>
            <Rail top={i > 0 && reachedAbove} bottom={!isLast && reachedBelow} tested={!!decision} marker={marker} dimTop={i === 0} dimBottom={isLast} />
            <div className="min-w-0 py-1 text-[13.5px]">
              {body}
              {pass === 'stop' && <p className="mt-1 text-[12.5px] font-bold">Route stops here{s.kind === 'rule' ? `: ${s.rule.action === 'deny' ? 'access denied' : 'access allowed'}` : s.kind === 'default' ? `: ${defaults.defaultAction === 'deny' ? 'access denied' : 'access allowed'}` : ': access denied'}</p>}
            </div>
            <div className="flex items-center justify-end">{aside}</div>
          </li>
        )
      })}
    </ol>
  )
}

function Rail({ top, bottom, tested, marker, dimTop, dimBottom }: { top: boolean; bottom: boolean; tested: boolean; marker: ReactNode; dimTop?: boolean; dimBottom?: boolean }) {
  const on = tested ? INK.station : '#465166'
  const off = '#5B677C'
  const seg = (solid: boolean) => (solid ? { backgroundImage: `linear-gradient(${on}, ${on})` } : { backgroundImage: `repeating-linear-gradient(to bottom, ${off} 0 5px, transparent 5px 9px)` })
  return (
    <div className="e-stop-rail" aria-hidden>
      {!dimTop && <span className="absolute left-[16px] top-0 h-1/2 w-[4px]" style={seg(top)} />}
      {!dimBottom && <span className="absolute bottom-0 left-[16px] h-1/2 w-[4px]" style={seg(bottom)} />}
      {marker && <span className="absolute left-[18px] top-1/2 -translate-x-1/2 -translate-y-1/2">{marker}</span>}
    </div>
  )
}

function Marker({ color, shape, pass, disabled }: { color: string; shape: 'circle' | 'diamond' | 'square'; pass: Pass; disabled?: boolean }) {
  const big = pass === 'stop'
  const s = big ? 24 : 16
  return (
    <svg width={s + 6} height={s + 6} viewBox={`0 0 ${s + 6} ${s + 6}`} className="block">
      <g transform={`translate(3,3)`}>
        {shape === 'circle' && <circle cx={s / 2} cy={s / 2} r={s / 2} fill={disabled ? INK.ground : INK.station} stroke={disabled ? '#6B768A' : color} strokeWidth={big ? 5 : 4} />}
        {shape === 'diamond' && <rect x={s * 0.15} y={s * 0.15} width={s * 0.7} height={s * 0.7} transform={`rotate(45 ${s / 2} ${s / 2})`} fill={disabled ? INK.ground : INK.station} stroke={disabled ? '#6B768A' : color} strokeWidth={big ? 4.5 : 3.5} />}
        {shape === 'square' && <rect x={1} y={1} width={s - 2} height={s - 2} rx={3} fill={INK.station} stroke={color} strokeWidth={big ? 5 : 4} />}
        {disabled && <path d={`M${s * 0.15} ${s * 0.85} L${s * 0.85} ${s * 0.15}`} stroke={INK.station} strokeWidth={2} strokeLinecap="round" />}
      </g>
    </svg>
  )
}

function Terminus({ vlan, reject, compact }: { vlan?: Vlan; reject?: boolean; compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap text-[12.5px] font-semibold">
      {reject ? <RejectBullet size={22} /> : vlan ? <LineBullet vlan={vlan} size={22} /> : null}
      {!compact && <span className="max-sm:hidden">{reject ? 'Rejected' : vlan?.name}</span>}
      {compact && <span className="sr-only">{reject ? 'Rejected' : `VLAN ${vlan?.vlanId} ${vlan?.name}`}</span>}
    </span>
  )
}

function PassLabel({ pass, matched }: { pass: Pass; matched: boolean }) {
  if (pass === 'passed') return <span className="t2 whitespace-nowrap text-[12px]">{matched ? 'Matched, outranked' : 'No match, continue'}</span>
  if (pass === 'skipped') return <span className="t2 whitespace-nowrap text-[12px]">Disabled, skipped</span>
  if (pass === 'unreached') return <span className="t3 whitespace-nowrap text-[12px]">Not reached</span>
  return null
}
