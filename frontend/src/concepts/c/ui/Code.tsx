import { useState, type ReactNode } from 'react'
import { Check, Copy } from 'lucide-react'
import { copyText } from '@/ui/lib'
import type { Snippet } from '../lib/snippets'
import { Button } from './Button'

/** A hostname in mono that wraps only after its dots, never mid-label. */
export function Host({ name }: { name: string }) {
  const parts = name.split('.')
  return (
    <span className="c-mono" style={{ overflowWrap: 'normal' }}>
      {parts.map((p, i) => (
        <span key={i}>
          {p}
          {i < parts.length - 1 ? (
            <>
              .<wbr />
            </>
          ) : null}
        </span>
      ))}
    </span>
  )
}

/** Copy button that confirms in place ("Copied") and announces it. */
export function CopyButton({ text, label = 'Copy', size = 'sm', variant = 'ghost' }: { text: string; label?: string; size?: 'sm' | 'md'; variant?: 'ghost' | 'secondary' | 'primary' }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size={size}
      variant={variant}
      icon={copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
      onClick={async () => {
        const ok = await copyText(text)
        setCopied(ok)
        if (ok) window.setTimeout(() => setCopied(false), 1800)
      }}
    >
      <span aria-live="polite">{copied ? 'Copied' : label}</span>
    </Button>
  )
}

/** Renders **bold** markers inside a step string without innerHTML. */
function richText(s: string): ReactNode[] {
  return s.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((part, i) => (part.startsWith('**') ? <strong key={i}>{part.slice(2, -2)}</strong> : <span key={i}>{part}</span>))
}

/** Vendor configuration block: CLI with copy, or numbered UI steps. */
export function SnippetBlock({ snippet, caption }: { snippet: Snippet; caption?: string }) {
  const plain = typeof snippet.body === 'string' ? snippet.body : snippet.body.map((s, i) => `${i + 1}. ${s.replaceAll('**', '')}`).join('\n')
  return (
    <figure className="c-code" style={{ margin: 0 }}>
      <figcaption className="c-code-head">
        <span>{caption ?? snippet.label}</span>
        <CopyButton text={plain} label={snippet.kind === 'cli' ? 'Copy commands' : 'Copy steps'} />
      </figcaption>
      {typeof snippet.body === 'string' ? (
        <pre tabIndex={0} aria-label={`${snippet.label} configuration`}>
          <code>{snippet.body}</code>
        </pre>
      ) : (
        <ol className="c-steps">
          {snippet.body.map((s, i) => (
            <li key={i}>{richText(s)}</li>
          ))}
        </ol>
      )}
    </figure>
  )
}

/** A secret shown exactly once, with copy. The parent discards it when the view closes. */
export function SecretOnce({ secret, label = 'Shared secret' }: { secret: string; label?: string }) {
  return (
    <div className="c-secret">
      <div style={{ minWidth: 0 }}>
        <div className="c-faint c-small" style={{ marginBottom: 4 }}>
          {label}
        </div>
        <code>{secret}</code>
      </div>
      <CopyButton text={secret} label="Copy secret" variant="secondary" />
    </div>
  )
}
