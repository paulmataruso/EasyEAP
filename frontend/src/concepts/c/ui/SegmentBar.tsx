import { useState } from 'react'

export interface Segment {
  key: string
  label: string
  value: number
  color: string
}

/**
 * Thin segmented bar: one whole split into parts. 2px surface gaps, rounded ends, hover names the
 * part; the legend beneath carries every value so the tooltip never gates information.
 */
export function SegmentBar({ segments, label }: { segments: Segment[]; label: string }) {
  const total = segments.reduce((s, x) => s + x.value, 0)
  const [hover, setHover] = useState<string | null>(null)
  const visible = segments.filter((s) => s.value > 0)
  const active = visible.find((s) => s.key === hover)
  const summary = segments.map((s) => `${s.label} ${s.value}`).join(', ')
  return (
    <div>
      <div style={{ position: 'relative' }}>
        <div className="c-segbar" role="img" aria-label={`${label}: ${summary}`} onPointerLeave={() => setHover(null)}>
          {total === 0 ? (
            <span style={{ flex: 1, background: 'rgba(255,255,255,0.08)' }} />
          ) : (
            visible.map((s) => <span key={s.key} style={{ flex: s.value, background: s.color }} onPointerEnter={() => setHover(s.key)} />)
          )}
        </div>
        {active ? (
          <div className="c-tip" style={{ position: 'absolute', bottom: 16, left: `${(offsetOf(visible, active.key, total) / total) * 100}%`, whiteSpace: 'nowrap', pointerEvents: 'none' }} aria-hidden="true">
            <b className="tnum">{active.value}</b> {active.label.toLowerCase()} · {Math.round((active.value / total) * 100)}%
          </div>
        ) : null}
      </div>
      <ul className="c-legend">
        {segments.map((s) => (
          <li key={s.key}>
            <span className="c-key" style={{ background: s.color }} aria-hidden="true" />
            {s.label} <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  )
}

function offsetOf(segments: Segment[], key: string, total: number) {
  let acc = 0
  for (const s of segments) {
    if (s.key === key) return Math.min(acc, total * 0.7)
    acc += s.value
  }
  return 0
}
