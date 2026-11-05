// TIA-606-style administration identifiers and colour codes.
// Every object gets a structured identifier `SITE·CLASS·ID` and a field colour, so a person
// can be traced to their VLAN by label and colour on every screen.
import type { AccessRule, Certificate, CertificateAuthority, DirectoryGroup, Identity, RadiusClient, Tenant, Vlan } from '@/domain/types'

/** Field colours. Five TIA hues for VLANs, white for neutral identifiers, deny = black tape. */
export type Tone = 'blue' | 'purple' | 'green' | 'orange' | 'yellow' | 'white' | 'deny'

/** Fixed categorical order (VLAN id order in every tenant) — never cycled. */
export const VLAN_TONE_ORDER: Tone[] = ['blue', 'purple', 'green', 'orange', 'yellow']

export const TONE_HEX: Record<Tone, string> = {
  blue: '#4990e8',
  purple: '#7f47c7',
  green: '#3aa85b',
  orange: '#b14500',
  yellow: '#ac8c0e',
  white: '#4a5563',
  deny: '#4a5563',
}

const VLAN_TONE: Record<Vlan['color'], Tone> = {
  blue: 'blue',
  violet: 'purple',
  teal: 'green',
  green: 'green',
  orange: 'orange',
  amber: 'yellow',
  rose: 'orange',
  slate: 'white',
}

export const vlanTone = (vlan: Pick<Vlan, 'color'> | null | undefined): Tone => (vlan ? VLAN_TONE[vlan.color] : 'white')

const SITE_CODES: Record<string, string> = { 't-harborview': 'HV', 't-cedar': 'CR', 't-northgate': 'NG', 't-atlas': 'AF' }

export function siteCode(tenant: Pick<Tenant, 'id' | 'name'> | string): string {
  const id = typeof tenant === 'string' ? tenant : tenant.id
  if (SITE_CODES[id]) return SITE_CODES[id]
  const name = typeof tenant === 'string' ? tenant.replace(/^t-/, '') : tenant.name
  const words = name.split(/[\s-]+/).filter(Boolean)
  return (words.length > 1 ? words[0][0] + words[1][0] : name.slice(0, 2)).toUpperCase()
}

const KEY_CODES: Record<string, string> = {
  du: 'DU', mgmt: 'MGMT', it: 'IT', net: 'NET', wh: 'WH', guest: 'GST', contract: 'CTR', former: 'FMR',
}
const keyCode = (key: string) => KEY_CODES[key] ?? key.replace(/[^a-z0-9]/gi, '').slice(0, 5).toUpperCase()

export interface TapeCode { site: string; body: string }

export const vlanCode = (v: Vlan): TapeCode => ({ site: siteCode(v.tenantId), body: `VL${v.vlanId}` })
export const groupCode = (g: DirectoryGroup): TapeCode => ({ site: siteCode(g.tenantId), body: `GRP·${keyCode(g.id.split(':g-')[1] ?? g.name)}` })
export const ruleCode = (r: AccessRule): TapeCode => ({ site: siteCode(r.tenantId), body: `RUL·${keyCode(r.id.split(':r-')[1] ?? r.name)}` })
export const certCode = (c: Pick<Certificate, 'tenantId' | 'serial'>): TapeCode => ({ site: siteCode(c.tenantId), body: `CRT·${c.serial.slice(0, 4)}` })
export const caCode = (ca: CertificateAuthority): TapeCode => ({ site: siteCode(ca.tenantId), body: ca.role === 'root' ? 'CA·R1' : 'CA·I1' })
export const userCode = (i: Identity): TapeCode => ({ site: siteCode(i.tenantId), body: `USR·${i.username.slice(0, 12).toUpperCase()}` })

export function nasCode(n: RadiusClient, all: RadiusClient[]): TapeCode {
  const idx = all.findIndex((x) => x.id === n.id)
  return { site: siteCode(n.tenantId), body: `NAS·${String((idx < 0 ? all.length : idx) + 1).padStart(2, '0')}` }
}

export const codeText = (c: TapeCode) => `${c.site}·${c.body}`

/** Colour of a rule: its VLAN's field colour, or black tape for deny. */
export function ruleTone(rule: AccessRule, vlans: Vlan[]): Tone {
  if (rule.action === 'deny') return 'deny'
  return vlanTone(vlans.find((v) => v.id === rule.vlanId))
}

/**
 * Colour of a group = where a member of only that group would land:
 * an enabled deny rule wins, otherwise the first enabled allow rule by precedence.
 */
export function groupRoute(groupId: string, rules: AccessRule[]): AccessRule | null {
  const enabled = rules.filter((r) => r.enabled && r.groupIds.includes(groupId)).sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id))
  return enabled.find((r) => r.action === 'deny') ?? enabled.find((r) => r.action === 'allow') ?? null
}

export function groupTone(groupId: string, rules: AccessRule[], vlans: Vlan[]): Tone {
  const route = groupRoute(groupId, rules)
  return route ? ruleTone(route, vlans) : 'white'
}
