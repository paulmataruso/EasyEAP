import { cn } from './lib'

/** EasyEAP mark: a lowercase "e" whose crossbar becomes a key shank — identity carried by a credential. */
export function LogoMark({ className, title = 'EasyEAP' }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={cn('shrink-0', className)} role="img" aria-label={title}>
      <path d="M20.37 10.84 A9 9 0 1 0 19.89 21.79" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" />
      <path d="M4.6 16 H28.6 M24 16 V20.2 M28.4 16 V19.4" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/** Wordmark: "Easy" regular + "EAP" bold, set in the surrounding font. */
export function Wordmark({ className, markClassName }: { className?: string; markClassName?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <LogoMark className={cn('size-7', markClassName)} />
      <span className="tracking-tight" aria-hidden="true">
        <span className="font-normal">Easy</span>
        <span className="font-bold">EAP</span>
      </span>
      <span className="sr-only">EasyEAP</span>
    </span>
  )
}
