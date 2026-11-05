import type { ReactNode } from 'react'
import type { AccessRule, Certificate, CertificateAuthority, DirectoryGroup, RadiusClient, Vlan } from '@/domain/types'
import { cn } from '@/ui/lib'
import { caCode, certCode, codeText, groupCode, groupTone, nasCode, ruleCode, ruleTone, vlanCode, vlanTone, type TapeCode, type Tone } from '../model/codes'

type Size = 'sm' | 'md' | 'lg' | 'xl'

interface TapeProps {
  code: TapeCode | string
  tone?: Tone
  size?: Size
  off?: boolean
  title?: string
  className?: string
  /** Renders the tape as a button (e.g. a group tape that filters a list). */
  onClick?: () => void
  children?: ReactNode
}

/** Label tape: a structured identifier printed in dark ink on tape tinted by the object's colour code. */
export function Tape({ code, tone = 'white', size = 'md', off, title, className, onClick }: TapeProps) {
  const text = typeof code === 'string' ? code : codeText(code)
  const body =
    typeof code === 'string' ? (
      code
    ) : (
      <>
        <span className="d-tape-site">{code.site}</span>
        <span className="d-tape-dot" aria-hidden="true">·</span>
        {code.body}
      </>
    )
  const cls = cn('d-tape', size !== 'md' && `d-tape--${size}`, className)
  if (onClick) {
    return (
      <button type="button" className={cls} data-tone={tone} data-off={off || undefined} title={title} aria-label={title ? `${text}, ${title}` : text} onClick={onClick}>
        {body}
      </button>
    )
  }
  return (
    <span className={cls} data-tone={tone} data-off={off || undefined} title={title}>
      {typeof code === 'string' ? body : <><span className="sr-only">{text}</span><span aria-hidden="true" className="inline-flex items-center">{body}</span></>}
    </span>
  )
}

export function VlanTape({ vlan, size, title }: { vlan: Vlan | null | undefined; size?: Size; title?: string }) {
  if (!vlan) return <span className="ink-3">—</span>
  return <Tape code={vlanCode(vlan)} tone={vlanTone(vlan)} size={size} title={title ?? `VLAN ${vlan.vlanId} · ${vlan.name}`} />
}

export function GroupTape({ group, rules, vlans, size, off, onClick }: { group: DirectoryGroup; rules: AccessRule[]; vlans: Vlan[]; size?: Size; off?: boolean; onClick?: () => void }) {
  return <Tape code={groupCode(group)} tone={groupTone(group.id, rules, vlans)} size={size} off={off} title={group.name} onClick={onClick} />
}

export function RuleTape({ rule, vlans, size }: { rule: AccessRule; vlans: Vlan[]; size?: Size }) {
  return <Tape code={ruleCode(rule)} tone={ruleTone(rule, vlans)} size={size} off={!rule.enabled} title={`${rule.name}${rule.enabled ? '' : ' (disabled)'}`} />
}

export function CertTape({ cert, size, onClick }: { cert: Pick<Certificate, 'tenantId' | 'serial'>; size?: Size; onClick?: () => void }) {
  return <Tape code={certCode(cert)} tone="white" size={size} title={`Serial ${cert.serial}`} onClick={onClick} />
}

export function CaTape({ ca, size }: { ca: CertificateAuthority; size?: Size }) {
  return <Tape code={caCode(ca)} tone="white" size={size} title={ca.commonName} />
}

export function NasTape({ nas, all, size }: { nas: RadiusClient; all: RadiusClient[]; size?: Size }) {
  return <Tape code={nasCode(nas, all)} tone="white" size={size} title={nas.name} />
}
