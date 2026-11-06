import { useId } from 'react'
import { cn } from './lib'

/** EasyEAP mark: an amber geometric E and wireless signal with a silver-gold security key, on a charcoal tile.
 *  Full colour, so it ignores `currentColor`. The source artwork is design/brand/mark.svg (also public/favicon.svg).
 *  Gradient ids come from useId: the sidebar and the mobile top bar can both be mounted, and a duplicate id would
 *  resolve to whichever copy is first in the document, even a hidden one. */
export function LogoMark({ className, title = 'EasyEAP', decorative = false }: { className?: string; title?: string; decorative?: boolean }) {
  const uid = useId().replace(/:/g, '')
  const amber = `ee-logo-amber-${uid}`
  const glass = `ee-logo-glass-${uid}`
  return (
    <svg viewBox="0 0 256 256" className={cn('shrink-0', className)}
      {...(decorative ? { 'aria-hidden': true } : { role: 'img', 'aria-label': title })}>
      <defs>
        <linearGradient id={amber} x1="32" y1="28" x2="220" y2="224" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#E2C477" />
          <stop offset="1" stopColor="#A9822F" />
        </linearGradient>
        <linearGradient id={glass} x1="32" y1="24" x2="220" y2="232" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#FFFFFF" stopOpacity=".12" />
          <stop offset="1" stopColor="#FFFFFF" stopOpacity=".025" />
        </linearGradient>
      </defs>
      <rect x="8" y="8" width="240" height="240" rx="58" fill="#202326" />
      <rect x="9" y="9" width="238" height="238" rx="57" fill={`url(#${glass})`} stroke="#FFFFFF" strokeOpacity=".12" strokeWidth="2" />
      <path d="M65 66h105a13 13 0 0 1 0 26H91v25h66a13 13 0 0 1 0 26H91v25h79a13 13 0 0 1 0 26H65a13 13 0 0 1-13-13V79a13 13 0 0 1 13-13Z" fill={`url(#${amber})`} />
      <path d="M150 62c22 8 38 24 46 46" fill="none" stroke="#E2C477" strokeWidth="9" strokeLinecap="round" />
      <path d="M159 88c12 5 21 14 26 26" fill="none" stroke="#E2C477" strokeWidth="8" strokeLinecap="round" opacity=".82" />
      <circle cx="179" cy="132" r="7" fill="#E2C477" />
      <g transform="rotate(43 183 169)" fill="none" stroke="#E5E7E8" strokeWidth="9" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="183" cy="155" r="13" />
        <path d="M183 168v48m0-13h12m-12 2h-9" />
      </g>
      <circle cx="183" cy="155" r="5" fill="#D5B45E" />
    </svg>
  )
}

/** Wordmark: the mark plus "Easy" regular + "EAP" bold, set in the surrounding font. Read once as "EasyEAP". */
export function Wordmark({ className, markClassName }: { className?: string; markClassName?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2.5', className)}>
      <LogoMark decorative className={cn('size-8', markClassName)} />
      <span className="tracking-tight" aria-hidden="true">
        <span className="font-normal">Easy</span>
        <span className="font-bold">EAP</span>
      </span>
      <span className="sr-only">EasyEAP</span>
    </span>
  )
}
