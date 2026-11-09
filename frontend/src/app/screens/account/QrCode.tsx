// A QR code for an otpauth:// setup link, drawn as one SVG path (qr.ts). Used by Account (the console's own
// two-factor) and Device administration (codes for local switch logins).
import { useMemo } from 'react'
import { qrMatrix, qrPath } from './qr'

export function QrCode({ text, label = 'QR code for your authenticator app' }: { text: string; label?: string }) {
  const qr = useMemo(() => { const m = qrMatrix(text); return m ? qrPath(m) : null }, [text])
  if (!qr) return null
  return (
    <svg viewBox={`0 0 ${qr.size} ${qr.size}`} className="size-[184px] shrink-0 rounded-[8px]" role="img" aria-label={label} shapeRendering="crispEdges">
      <rect width={qr.size} height={qr.size} fill="#ffffff" />
      <path d={qr.d} fill="#0b0f1a" />
    </svg>
  )
}
