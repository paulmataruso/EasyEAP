// Access policy: VLANs, rules (staged as a draft, previewed and published atomically), tenant settings and the
// decision simulator. Shapes match backend/app/routers/policy.py and backend/app/policy/draft.py exactly.
import { useQuery } from '@tanstack/react-query'
import { api, qs } from './client'
import { qk } from './keys'
import type { DecisionStep, Enforcement, Outcome } from './types'

export type RuleAction = 'allow' | 'deny'
export type Purpose = 'user' | 'device'

export interface Vlan {
  id: string
  vlan_id: number
  name: string
  description: string
  color: string
  /** What a switch port gets when a rule assigns this VLAN: the same VLAN ID, the port's own VLAN (none assigned), or
   * another VLAN (`wired_vlan_id`). */
  wired_mode: WiredMode
  wired_vlan_id: number | null
  /** Certificates whose current decision places them on this VLAN. */
  certificates: number
}

export type WiredMode = 'same' | 'port' | 'vlan'

/** The VLAN a switch port gets for a decision on `v` (null: none assigned, the port keeps its own). */
export const wiredVlanOf = (v: Pick<Vlan, 'vlan_id' | 'wired_mode' | 'wired_vlan_id'>): number | null =>
  v.wired_mode === 'port' ? null : v.wired_mode === 'vlan' ? v.wired_vlan_id : v.vlan_id

export interface RuleGroup { id: string; name: string; deleted: boolean }
export interface ExtraAttribute { name: string; value: string }

export interface Rule {
  id: string
  name: string
  description: string
  priority: number
  enabled: boolean
  action: RuleAction
  vlan_ref: string | null
  purposes: string[]
  extra_attributes: ExtraAttribute[]
  groups: RuleGroup[]
}

export interface PolicySettings {
  default_action: RuleAction
  default_vlan_ref: string | null
  max_snapshot_age_seconds: number
  allow_server_keygen: boolean
  expiry_warning_days: number
}

export interface PolicyResponse {
  vlans: Vlan[]
  rules: Rule[]
  settings: PolicySettings
  allowed_extra_attributes: string[]
  /** Fingerprint of the rules (in order) and the tenant default. Publishing a draft started from an older one fails with 409. */
  revision: string
}

export interface DraftRuleBody {
  id: string | null
  name: string
  description: string
  enabled: boolean
  action: RuleAction
  vlan_ref: string | null
  group_ids: string[]
  purposes: string[]
  extra_attributes: ExtraAttribute[]
}

export interface DraftBody {
  revision: string
  rules: DraftRuleBody[]
  default_action: RuleAction
  default_vlan_ref: string | null
}

export interface PreviewSummary {
  /** People evaluated (directory users that aren't deleted). */
  evaluated: number
  /** People holding an active user or device certificate. */
  with_certificates: number
  newly_allowed: number
  newly_denied: number
  vlan_changed: number
  /** Same decision and VLAN, but a different rule decides it. */
  rule_only: number
  unchanged: number
}

export interface BriefOutcome {
  outcome: RuleAction
  vlan_id: number | null
  reason_code: string | null
  rule_id: string | null
  rule_name: string | null
}

export type ChangeKind = 'newly_allowed' | 'newly_denied' | 'vlan_changed'

export interface PreviewChange {
  kind: ChangeKind
  purpose: Purpose
  has_certificate: boolean
  identity: { id: string; display_name: string; username: string; account_state: string }
  before: BriefOutcome
  after: BriefOutcome
  /** Decision trace under the draft. New rules are referred to as "draft-<index in the submitted rules>". */
  steps: DecisionStep[]
}

export interface PreviewResponse {
  summary: PreviewSummary
  changes: PreviewChange[]
  truncated: boolean
  warnings: string[]
  computed_at: string
  /** False when the live policy changed after the draft's revision (publishing would be refused). */
  revision_current: boolean
}

export interface PublishResponse extends PolicyResponse { impact: PreviewSummary }

export interface VlanBody { vlan_id: number; name: string; description: string; color: string; wired_mode?: WiredMode; wired_vlan_id?: number | null }

/** The simulator's answer: the decision, and its VLAN on switch ports (null: none assigned). */
export type SimulatedOutcome = Outcome & { wired_vlan_id?: number | null }

const base = (tid: string) => `/api/tenants/${tid}/policy`

export function usePolicy(tid: string) {
  return useQuery({ queryKey: qk.policy(tid), queryFn: ({ signal }) => api.get<PolicyResponse>(base(tid), signal) })
}

export const policyApi = {
  preview: (tid: string, body: DraftBody) => api.post<PreviewResponse>(`${base(tid)}/preview`, body),
  publish: (tid: string, body: DraftBody) => api.post<PublishResponse>(`${base(tid)}/publish`, body),
  simulate: (tid: string, identity_id: string, purpose: Purpose) => api.post<SimulatedOutcome>(`${base(tid)}/simulate`, { identity_id, purpose }),
  createVlan: (tid: string, body: VlanBody) => api.post<Omit<Vlan, 'certificates'>>(`${base(tid)}/vlans`, body),
  updateVlan: (tid: string, id: string, body: VlanBody) => api.put<Omit<Vlan, 'certificates'>>(`${base(tid)}/vlans/${id}`, body),
  deleteVlan: (tid: string, id: string) => api.del<{ ok: true }>(`${base(tid)}/vlans/${id}`),
  updateSettings: (tid: string, body: Omit<PolicySettings, 'default_action' | 'default_vlan_ref'>) => api.put<PolicySettings>(`${base(tid)}/settings`, body),
}

/** Strip the publish-only `impact` so the cache keeps the raw GET /policy shape. */
export function policyFromPublish(r: PublishResponse): PolicyResponse {
  const { vlans, rules, settings, allowed_extra_attributes, revision } = r
  return { vlans, rules, settings, allowed_extra_attributes, revision }
}

// ── Supporting reads (raw responses under their canonical keys) ─────────

export type EnforcementLive = Enforcement

/** The part of GET /dashboard this area reads: RADIUS enforcement and agent sync. */
export interface DashboardLite { enforcement: EnforcementLive; generated_at: string }

export function useEnforcement(tid: string, opts: { watch?: boolean } = {}) {
  return useQuery({
    queryKey: qk.dashboard(tid),
    queryFn: ({ signal }) => api.get<DashboardLite>(`/api/tenants/${tid}/dashboard`, signal),
    select: (d) => d.enforcement,
    refetchInterval: opts.watch ? 3000 : false,
    staleTime: opts.watch ? 0 : 15_000,
  })
}

export interface IdentityLite {
  id: string
  source: string
  username: string
  upn: string | null
  email: string | null
  display_name: string
  department: string | null
  account_state: string
  groups: Array<{ id: string; name: string }>
}

export function useIdentitySearch(tid: string, q: string) {
  const params = { q, page_size: 8 }
  return useQuery({
    queryKey: qk.identities(tid, params),
    queryFn: ({ signal }) => api.get<{ total: number; items: IdentityLite[] }>(`/api/tenants/${tid}/identities${qs(params)}`, signal),
    enabled: q.trim().length > 0,
    staleTime: 15_000,
  })
}

export function useIdentity(tid: string, id: string | null) {
  return useQuery({
    queryKey: qk.identity(tid, id ?? ''),
    queryFn: ({ signal }) => api.get<IdentityLite>(`/api/tenants/${tid}/identities/${id}`, signal),
    enabled: !!id,
    staleTime: 30_000,
  })
}

/** Characters the API refuses in extra reply-attribute values (policy.py _validate_rule). */
export const FORBIDDEN_ATTR_CHARS = ['"', "'", '\\', '\n', '\r', '%', '{', '}']
export function attributeValueProblem(value: string): string | null {
  if (!value.trim()) return 'Enter a value.'
  if (value.length > 253) return 'Use 253 characters or fewer.'
  const bad = FORBIDDEN_ATTR_CHARS.filter((c) => value.includes(c))
  if (bad.length) return `Remove ${bad.map((c) => (c === '\n' || c === '\r' ? 'line breaks' : c)).filter((x, i, a) => a.indexOf(x) === i).join(' ')}: RADIUS reply values can’t contain quotes, backslashes, %, braces or line breaks.`
  return null
}
