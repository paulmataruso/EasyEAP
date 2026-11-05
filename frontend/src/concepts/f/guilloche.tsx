import { memo, useMemo } from 'react'

// Fine-line guilloché, generated rather than drawn: hypotrochoid rosettes plus an interference
// band of phase-shifted sine waves. Parameters derive from the credential serial, so every
// certificate carries its own rosette (the security-printing idea), and it is used ONLY as a
// faint watermark on credential panels.

function seededRandom(seed: string) {
  let h = 2166136261
  for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 16777619)
  return () => {
    h = Math.imul(h ^ (h >>> 15), 2246822507)
    h = Math.imul(h ^ (h >>> 13), 3266489909)
    h ^= h >>> 16
    return (h >>> 0) / 4294967296
  }
}

const gcd = (a: number, b: number): number => (b === 0 ? a : gcd(b, a % b))

/** Closed hypotrochoid with integer ratio R:r = p:q. */
function hypotrochoid(cx: number, cy: number, R: number, p: number, q: number, dRatio: number, rot: number, steps: number) {
  const r = (R * q) / p
  const d = r * dRatio
  const turns = q / gcd(p, q)
  const total = Math.PI * 2 * turns
  const n = Math.max(240, Math.round(steps * turns))
  let out = ''
  for (let i = 0; i <= n; i++) {
    const t = (i / n) * total
    const x0 = (R - r) * Math.cos(t) + d * Math.cos(((R - r) / r) * t)
    const y0 = (R - r) * Math.sin(t) - d * Math.sin(((R - r) / r) * t)
    const x = cx + x0 * Math.cos(rot) - y0 * Math.sin(rot)
    const y = cy + x0 * Math.sin(rot) + y0 * Math.cos(rot)
    out += `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`
  }
  return out
}

function waveBand(width: number, y: number, amp: number, lines: number, period: number, phase: number) {
  const paths: string[] = []
  for (let k = 0; k < lines; k++) {
    let d = ''
    const shift = phase + (k / lines) * Math.PI * 2
    for (let x = 0; x <= width; x += 6) {
      const yy = y + amp * Math.sin((x / period) * Math.PI * 2 + shift) + (amp / 3) * Math.sin((x / (period * 0.37)) * Math.PI * 2 - shift)
      d += `${x === 0 ? 'M' : 'L'}${x} ${yy.toFixed(1)}`
    }
    paths.push(d)
  }
  return paths
}

function buildPattern(seed: string, width: number, height: number) {
  const rnd = seededRandom(seed)
  const ratios: Array<[number, number]> = [[7, 3], [9, 4], [11, 4], [13, 5], [8, 3], [10, 3], [12, 5]]
  const R = Math.min(height * 0.62, 210)
  const cx = width - R * 0.78
  const cy = height * 0.42
  const rosettes: string[] = []
  const layers = 3
  for (let i = 0; i < layers; i++) {
    const [p, q] = ratios[Math.floor(rnd() * ratios.length)]
    rosettes.push(hypotrochoid(cx, cy, R * (1 - i * 0.18), p, q, 0.72 + rnd() * 0.5, rnd() * Math.PI, 160))
  }
  const band = waveBand(width, height - 34, 9, 9, 120 + rnd() * 80, rnd() * Math.PI)
  return { rosettes, band }
}

/** Absolutely positioned watermark; parent must be `position: relative; overflow: hidden`. */
export const Guilloche = memo(function Guilloche({ seed, width = 900, height = 320 }: { seed: string; width?: number; height?: number }) {
  const { rosettes, band } = useMemo(() => buildPattern(seed, width, height), [seed, width, height])
  return (
    <svg className="f-guilloche" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMaxYMid slice" aria-hidden="true" focusable="false">
      <g fill="none" strokeWidth="0.6">
        {rosettes.map((d, i) => (
          <path key={i} d={d} stroke={i === 1 ? 'var(--f-valid)' : 'var(--f-gold)'} />
        ))}
        {band.map((d, i) => (
          <path key={`b${i}`} d={d} stroke="var(--f-ink)" />
        ))}
      </g>
    </svg>
  )
})
