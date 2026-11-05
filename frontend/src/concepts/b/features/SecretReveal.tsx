import { useState } from 'react'
import { Eye, EyeOff, KeyRound } from 'lucide-react'
import { Notice } from '../ui/Panel'
import { CopyButton } from '../ui/CopyButton'
import { Button } from '../ui/Button'

/** 32-character shared secret from the platform CSPRNG. */
export function generateSecret(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

/** Shows a RADIUS shared secret exactly once. Closing the panel discards it from the page. */
export function SecretReveal({ secret, controllerName }: { secret: string; controllerName: string }) {
  const [masked, setMasked] = useState(false)
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-3">
      <Notice tone="warn" title="Copy the shared secret now" icon={KeyRound}>
        This is the only time EasyEAP shows it. The secret is encrypted at rest and never displayed or logged again; if it is lost, rotate it.
      </Notice>
      <div className="rounded-md border border-[var(--b-line-strong)] bg-[var(--b-sunken)] p-3">
        <p className="b-label mb-1.5">Shared secret for {controllerName}</p>
        <p className="b-mono text-[14px] tracking-[0.06em] break-all text-[var(--b-text)]" aria-label={masked ? 'Secret hidden' : `Secret: ${secret.split('').join(' ')}`}>
          {masked ? '•'.repeat(secret.length) : secret}
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <CopyButton text={secret} label="Copy secret" onCopied={() => setCopied(true)} />
          <Button size="sm" variant="ghost" icon={masked ? Eye : EyeOff} onClick={() => setMasked(!masked)}>
            {masked ? 'Show' : 'Hide'}
          </Button>
          <span className="b-num ml-auto text-[12px] text-[var(--b-text-3)]">{secret.length} characters</span>
        </div>
      </div>
      <p className="text-[12.5px] text-[var(--b-text-2)]">
        {copied ? 'Copied. Paste it into the controller’s RADIUS server entry, then close this panel.' : 'Paste it into the controller’s RADIUS server entry (and the CoA client entry, if CoA is on).'}
      </p>
    </div>
  )
}
