import { Ban, CircleX, Clock, Link2Off, RefreshCw, TriangleAlert, WifiOff } from 'lucide-react'
import type { ReactNode } from 'react'
import { EnrollError } from './api'
import type { GoneReason } from './model'
import { Button } from './ui'

function Message({ icon, title, children, action, tone = 'neutral' }: { icon: ReactNode; title: string; children: ReactNode; action?: ReactNode; tone?: 'neutral' | 'crit' | 'warn' }) {
  const color = tone === 'crit' ? 'var(--ee-crit-ink)' : tone === 'warn' ? 'var(--ee-warn)' : 'var(--ee-ink-3)'
  return (
    <div className="en-enter">
      <span className="mb-4 inline-grid size-11 place-items-center rounded-[12px] border border-[var(--ee-line-2)] bg-[rgba(6,9,17,0.4)] [&_svg]:size-[22px]" style={{ color }} aria-hidden>{icon}</span>
      <h1 className="en-h1" tabIndex={-1} data-autofocus>{title}</h1>
      <div className="en-lede mt-3 space-y-3">{children}</div>
      {action && <div className="en-actions">{action}</div>}
    </div>
  )
}

const ASK = 'Ask your IT administrator for a new link.'
const ask = 'ask your IT administrator for a new link.'

export function GoneScreen({ reason, tenant }: { reason: GoneReason; tenant?: string }) {
  const org = tenant ? `${tenant}’s` : 'Your organisation’s'
  switch (reason) {
    case 'no-token':
      return (
        <Message icon={<Link2Off />} title="Open the link from your IT administrator">
          <p>This page needs the full link your IT administrator sent you. Open it from the email or message, or copy the whole link into your browser’s address bar.</p>
        </Message>
      )
    case 'expired':
      return (
        <Message icon={<Clock />} title="This link has expired" tone="warn">
          <p>{org} setup links only work for a limited time, and this one has run out. {ASK}</p>
        </Message>
      )
    case 'used-meanwhile':
      return (
        <Message icon={<Link2Off />} title="This link has just been used" tone="warn">
          <p>It was used before this page could finish: perhaps on another device or in another tab. Nothing was installed on this device.</p>
          <p>If you already set up this device another way, there’s nothing more to do. Otherwise, {ask} If you didn’t use it yourself, tell them.</p>
        </Message>
      )
    case 'lost-response':
      return (
        <Message icon={<WifiOff />} title="Your certificate didn’t reach this page" tone="crit">
          <p>The connection dropped while your certificate was being created. It may have been created, but this page never received it, and the link now can’t be used again.</p>
          <p>Nothing was installed on this device. {ASK}</p>
        </Message>
      )
    case 'used':
      return (
        <Message icon={<Link2Off />} title="This link has already been used">
          <p>Each setup link works once. If you used this one to set up your device, there’s nothing more to do: you can close this page.</p>
          <p>To set up another device, {ask} If you didn’t use this link yourself, tell them.</p>
        </Message>
      )
    case 'cancelled':
      return (
        <Message icon={<Ban />} title="This link was cancelled">
          <p>{tenant ? `Your IT administrator at ${tenant}` : 'Your IT administrator'} cancelled this link, so it can’t be used. Nothing was installed on this device.</p>
          <p>If you still need to set up Wi-Fi on this device, {ask}</p>
        </Message>
      )
    case 'invalid':
      return (
        <Message icon={<CircleX />} title="This link isn’t valid">
          <p>This page doesn’t recognise the link. If you copied it from an email or message, part of it may be missing: open it again, or copy the whole link into your browser’s address bar.</p>
          <p>If it still doesn’t work, {ask}</p>
        </Message>
      )
    case 'closed':
    default:
      return (
        <Message icon={<CircleX />} title="This link can’t be used">
          <p>It may have been used already, it may have expired, or your IT administrator may have cancelled it. Each link works once.</p>
          <p>If you’ve already set up this device, there’s nothing more to do. Otherwise, {ask}</p>
        </Message>
      )
  }
}

/** The link couldn't be checked (network, rate limit, server). Retrying is always safe here: nothing has happened yet. */
export function LoadFailure({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const kind = error instanceof EnrollError ? error.kind : 'server'
  const title = kind === 'network' ? 'This device couldn’t reach the enrollment service' : kind === 'rate' ? 'Too many attempts' : 'Something went wrong'
  const body = kind === 'network'
    ? 'Check that you’re connected to the internet, using mobile data or your usual Wi-Fi, then try again.'
    : kind === 'rate'
      ? 'Wait a minute, then try again.'
      : 'The enrollment service hit a problem. Try again in a few minutes. If it keeps happening, tell your IT administrator.'
  return (
    <Message icon={kind === 'network' ? <WifiOff /> : <TriangleAlert />} title={title} tone="warn" action={<Button variant="primary" block onClick={onRetry}><RefreshCw aria-hidden />Try again</Button>}>
      <p>{body}</p>
    </Message>
  )
}
