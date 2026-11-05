import { useEffect, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { copyText } from '@/ui/lib'
import { Button } from './Button'

/** Copies text and confirms in place ("Copied") for two seconds. */
export function CopyButton({ text, label = 'Copy', copiedLabel = 'Copied', size = 'sm', variant = 'secondary', onCopied }: { text: string; label?: string; copiedLabel?: string; size?: 'sm' | 'md'; variant?: 'secondary' | 'ghost' | 'primary'; onCopied?: () => void }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  useEffect(() => {
    if (state === 'idle') return
    const t = setTimeout(() => setState('idle'), 2000)
    return () => clearTimeout(t)
  }, [state])
  return (
    <Button
      size={size}
      variant={variant}
      icon={state === 'copied' ? Check : Copy}
      onClick={async () => {
        const ok = await copyText(text)
        setState(ok ? 'copied' : 'failed')
        if (ok) onCopied?.()
      }}
    >
      <span aria-live="polite">{state === 'copied' ? copiedLabel : state === 'failed' ? 'Select and copy manually' : label}</span>
    </Button>
  )
}
