// Add or edit one rule in the draft. Nothing here reaches RADIUS: the rule lands in the draft, which is previewed
// and published separately. Validation mirrors backend/app/routers/policy.py (_validate_rule).
import { useState, type FormEvent } from 'react'
import { RadioGroup } from 'radix-ui'
import { Plus, Trash2 } from 'lucide-react'
import { attributeValueProblem, type ExtraAttribute, type RuleAction, type Vlan } from '../../api/policy'
import { Btn, Callout, ESelect, ESwitch, EDialog, Field, vlanVar } from '../../ui'
import { newKey, type DraftRule } from './draft'
import { GroupPicker } from './GroupPicker'

type PurposeChoice = 'any' | 'user' | 'device'
const choiceOf = (p: string[]): PurposeChoice => {
  const s = new Set(p)
  if (s.size === 1 && s.has('user')) return 'user'
  if (s.size === 1 && s.has('device')) return 'device'
  return 'any'
}

interface Props {
  tid: string
  open: boolean
  onOpenChange: (o: boolean) => void
  rule: DraftRule | null
  vlans: Vlan[]
  allowedAttributes: string[]
  onSave: (r: DraftRule) => void
}

export function RuleEditor(props: Props) {
  // Remount per rule so the form starts from that rule's values.
  return <EDialog open={props.open} onOpenChange={props.onOpenChange} wide title={props.rule ? `Edit “${props.rule.name}”` : 'Add a rule'}
    description="This changes your draft only. Nothing reaches RADIUS until you preview and publish.">
    {props.open && <RuleForm key={props.rule?.key ?? 'new'} {...props} />}
  </EDialog>
}

function RuleForm({ tid, rule, vlans, allowedAttributes, onSave, onOpenChange }: Props) {
  const [name, setName] = useState(rule?.name ?? '')
  const [description, setDescription] = useState(rule?.description ?? '')
  const [action, setAction] = useState<RuleAction>(rule?.action ?? 'allow')
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)
  const [groups, setGroups] = useState(rule?.groups ?? [])
  const [vlanRef, setVlanRef] = useState<string | null>(rule?.vlan_ref ?? (vlans.length === 1 ? vlans[0].id : null))
  const [purpose, setPurpose] = useState<PurposeChoice>(choiceOf(rule?.purposes ?? []))
  const [attrs, setAttrs] = useState<ExtraAttribute[]>(rule?.extra_attributes ?? [])
  const [tried, setTried] = useState(false)

  const nameErr = !name.trim() ? 'Give the rule a name.' : name.trim().length > 120 ? 'Use 120 characters or fewer.' : null
  const groupErr = groups.length === 0 ? 'Choose at least one group. A rule matches people who belong to any of its groups.' : null
  const vlanErr = action === 'allow' && !vlanRef ? 'Allow rules need a VLAN.' : action === 'allow' && !vlans.some((v) => v.id === vlanRef) ? 'That VLAN no longer exists. Choose another.' : null
  const attrErrs = attrs.map((a) => (!a.name ? 'Choose an attribute.' : attributeValueProblem(a.value)))
  const invalid = !!(nameErr || groupErr || (action === 'allow' && (vlanErr || attrErrs.some(Boolean))) || description.length > 500)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTried(true)
    if (invalid) return
    const original = rule?.purposes ?? []
    const purposes = purpose === 'any' ? (choiceOf(original) === 'any' ? original : []) : [purpose]
    onSave({
      key: rule?.key ?? newKey(), id: rule?.id ?? null, removed: false,
      name: name.trim(), description, enabled, action,
      vlan_ref: action === 'allow' ? vlanRef : null,
      groups, purposes,
      extra_attributes: action === 'allow' ? attrs.map((a) => ({ name: a.name, value: a.value.trim() })) : [],
    })
    onOpenChange(false)
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto]">
        <Field label="Name" htmlFor="rule-name" error={tried ? nameErr : null}>
          <input id="rule-name" className="ee-input" value={name} maxLength={120} autoComplete="off" onChange={(e) => setName(e.target.value)} aria-invalid={(tried && !!nameErr) || undefined} />
        </Field>
        <div className="flex flex-col gap-1.5">
          <span className="text-[13px] font-semibold" id="rule-enabled-label">Enabled</span>
          <div className="flex h-[34px] items-center gap-2.5">
            <ESwitch id="rule-enabled" checked={enabled} onChange={setEnabled} label="Rule enabled" />
            <span className="ee-small ee-ink-2">{enabled ? 'Checked by RADIUS' : 'Skipped'}</span>
          </div>
        </div>
      </div>
      <Field label="Description" htmlFor="rule-desc" optional error={description.length > 500 ? 'Use 500 characters or fewer.' : null}>
        <input id="rule-desc" className="ee-input" value={description} maxLength={500} onChange={(e) => setDescription(e.target.value)} placeholder="Why this rule exists, for the next person" />
      </Field>

      <fieldset>
        <legend className="mb-1.5 text-[13px] font-semibold">Action</legend>
        <RadioGroup.Root value={action} onValueChange={(v) => setAction(v as RuleAction)} className="grid gap-2 sm:grid-cols-2" aria-label="Action">
          <RadioGroup.Item value="allow" className="ee-radio-card">
            <span className="ee-radio-dot" aria-hidden />
            <span><span className="block text-[13.5px] font-semibold">Allow</span><span className="ee-small ee-ink-2">Accept and place on a VLAN. The first matching Allow rule decides.</span></span>
          </RadioGroup.Item>
          <RadioGroup.Item value="deny" className="ee-radio-card">
            <span className="ee-radio-dot" aria-hidden />
            <span><span className="block text-[13.5px] font-semibold">Deny</span><span className="ee-small ee-ink-2">Reject. Deny rules always win over Allow rules, wherever they sit.</span></span>
          </RadioGroup.Item>
        </RadioGroup.Root>
      </fieldset>

      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-semibold" id="rule-groups-label">Groups</span>
        <p className="ee-small ee-ink-3 -mt-0.5" id="rule-groups-hint">The rule matches anyone in at least one of these groups, including nested membership.</p>
        <GroupPicker tid={tid} value={groups} onChange={setGroups} invalid={tried && !!groupErr} describedBy="rule-groups-hint" />
        {tried && groupErr && <p className="ee-field-error" role="alert">{groupErr}</p>}
      </div>

      {action === 'allow' && (
        <Field label="VLAN" htmlFor="rule-vlan" error={tried ? vlanErr : null} hint="RADIUS returns this VLAN in the RFC 3580 tunnel attributes.">
          {vlans.length === 0 ? (
            <Callout tone="warn">This tenant has no VLANs yet. Close this dialog and create one under VLANs. VLANs apply immediately; they aren’t part of the draft.</Callout>
          ) : (
            <ESelect id="rule-vlan" label="VLAN" value={vlanRef ?? ''} onChange={setVlanRef} placeholder="Choose a VLAN" className="w-full"
              options={vlans.map((v) => ({ value: v.id, label: <span className="inline-flex items-center gap-2"><span className="ee-swatch" style={{ background: vlanVar(v.color) }} aria-hidden /><span className="ee-num font-semibold">{v.vlan_id}</span>{v.name}</span> }))} />
          )}
        </Field>
      )}

      <fieldset>
        <legend className="mb-1.5 text-[13px] font-semibold">Applies to</legend>
        <RadioGroup.Root value={purpose} onValueChange={(v) => setPurpose(v as PurposeChoice)} className="grid gap-2 sm:grid-cols-3" aria-label="Certificate types">
          {([['any', 'Any certificate', 'User and device certificates'], ['user', 'User certificates', 'Issued to a person'], ['device', 'Device certificates', 'Issued to a machine']] as const).map(([v, t, d]) => (
            <RadioGroup.Item key={v} value={v} className="ee-radio-card">
              <span className="ee-radio-dot" aria-hidden />
              <span><span className="block text-[13px] font-semibold">{t}</span><span className="ee-small ee-ink-2">{d}</span></span>
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
      </fieldset>

      {action === 'allow' && (
        <div>
          <div className="mb-1.5 flex items-center justify-between gap-3">
            <span className="text-[13px] font-semibold">Extra reply attributes <span className="font-normal ee-ink-3">optional</span></span>
            <Btn size="sm" variant="ghost" onClick={() => setAttrs([...attrs, { name: allowedAttributes[0] ?? '', value: '' }])} disabled={allowedAttributes.length === 0}>
              <Plus aria-hidden />Add attribute
            </Btn>
          </div>
          {attrs.length === 0 ? (
            <p className="ee-small ee-ink-3">Only the VLAN is sent. Add attributes such as Session-Timeout or a vendor role when your controller needs them.</p>
          ) : (
            <ul className="space-y-2">
              {attrs.map((a, i) => (
                <li key={i} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 sm:grid-cols-[200px_minmax(0,1fr)_auto]">
                  <ESelect label={`Attribute ${i + 1} name`} value={a.name} onChange={(v) => setAttrs(attrs.map((x, j) => (j === i ? { ...x, name: v } : x)))} className="col-span-1 w-full"
                    options={allowedAttributes.map((n) => ({ value: n, label: <span className="ee-mono text-[12.5px]">{n}</span> }))} />
                  <div className="col-span-2 row-start-2 sm:col-span-1 sm:row-start-1 sm:col-start-2">
                    <input className="ee-input ee-mono text-[13px]" aria-label={`Value for ${a.name || `attribute ${i + 1}`}`} value={a.value} maxLength={253}
                      aria-invalid={(tried && !!attrErrs[i]) || undefined} onChange={(e) => setAttrs(attrs.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} placeholder="Value" />
                    {tried && attrErrs[i] && <p className="ee-field-error mt-1" role="alert">{attrErrs[i]}</p>}
                  </div>
                  <Btn variant="ghost" icon aria-label={`Remove ${a.name || `attribute ${i + 1}`}`} className="col-start-2 row-start-1 sm:col-start-3" onClick={() => setAttrs(attrs.filter((_, j) => j !== i))}><Trash2 aria-hidden /></Btn>
                </li>
              ))}
            </ul>
          )}
          <p className="ee-small ee-ink-3 mt-2">Allowed: {allowedAttributes.join(', ')}. Values can’t contain quotes, backslashes, %, braces or line breaks.</p>
        </div>
      )}

      {tried && invalid && <Callout tone="crit">Fix the highlighted fields to add this rule to the draft.</Callout>}

      <div className="-mx-6 -mb-5 flex flex-wrap items-center justify-end gap-2 border-t border-[var(--ee-line)] px-6 py-4">
        <Btn onClick={() => onOpenChange(false)}>Cancel</Btn>
        <Btn type="submit" variant="primary">{rule ? 'Update draft' : 'Add to draft'}</Btn>
      </div>
    </form>
  )
}
