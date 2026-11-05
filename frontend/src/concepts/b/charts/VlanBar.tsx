import type { Vlan } from '@/domain/types'
import { inkOn, VLAN_HEX } from '../lib/vlan'
import { Tip } from '../ui/Tip'

/** Accepted sessions by VLAN: one whole split into parts (tall segmented bar) + legend in block order. */
export function VlanBar({ usage, vlans }: { usage: Array<[string, number]>; vlans: Vlan[] }) {
  const counts = new Map(usage)
  const parts = vlans.map((v) => ({ vlan: v, count: counts.get(v.id) ?? 0 })).filter((p) => p.count > 0)
  const total = parts.reduce((s, p) => s + p.count, 0)
  if (!total) return <p className="b-t2 text-[12.5px]">No accepted sessions in the last 24 hours.</p>
  return (
    <div>
      <div className="flex h-7 w-full gap-[2px]" role="img" aria-label={`Accepted sessions by VLAN: ${parts.map((p) => `VLAN ${p.vlan.vlanId} ${p.count}`).join(', ')}`}>
        {parts.map((p) => {
          const share = p.count / total
          const pct = Math.round(share * 100)
          return (
            <Tip key={p.vlan.id} label={`VLAN ${p.vlan.vlanId} · ${p.vlan.name}: ${p.count} sessions (${pct}%)`}>
              <span
                tabIndex={0}
                aria-label={`VLAN ${p.vlan.vlanId} ${p.vlan.name}: ${p.count} sessions, ${pct}%`}
                className="flex h-full min-w-[4px] items-center overflow-hidden rounded-[4px] px-1.5 transition-[filter] hover:brightness-110"
                style={{ flexGrow: p.count, flexBasis: 0, background: VLAN_HEX[p.vlan.color] }}
              >
                {share >= 0.12 && (
                  <span className="b-cond b-num text-[12.5px] font-semibold" style={{ color: inkOn(VLAN_HEX[p.vlan.color]) }}>
                    {pct}%
                  </span>
                )}
              </span>
            </Tip>
          )
        })}
      </div>
      <ul className="mt-3 space-y-1">
        {parts.map((p) => (
          <li key={p.vlan.id} className="flex items-center gap-2 text-[12.5px]">
            <i className="b-swatch" style={{ background: VLAN_HEX[p.vlan.color] }} aria-hidden />
            <span className="b-cond b-num w-8 font-semibold text-[var(--b-text)]">{p.vlan.vlanId}</span>
            <span className="b-t2 min-w-0 flex-1 truncate">{p.vlan.name}</span>
            <span className="b-cond b-num text-[13.5px] font-semibold text-[var(--b-text)]">{p.count}</span>
            <span className="b-num w-9 text-right text-[var(--b-text-3)]">{Math.round((p.count / total) * 100)}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
