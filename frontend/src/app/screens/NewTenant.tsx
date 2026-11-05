// Create a tenant (POST /api/tenants, platform owners and operators). The short name follows the backend's SLUG rule
// (routers/tenants.py). On success the setup wizard takes over: CA ceremony, directory, RADIUS, policy, activate.
import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus } from 'lucide-react'
import { api, ApiError } from '../api/client'
import { qk } from '../api/keys'
import { useSession } from '../api/session'
import type { Tenant } from '../api/types'
import { paths } from '../routes'
import { Btn, Callout, Field, PageHeader, Panel, toast } from '../ui'

/** Mirrors backend SLUG: ^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$ plus the model's 2–48 length. */
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/i

export const slugFrom = (name: string) =>
  name.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48).replace(/-+$/, '')

function validate(name: string, slug: string, domain: string) {
  const e: { name?: string; slug?: string; domain?: string } = {}
  const n = name.trim()
  if (n.length < 2) e.name = 'Enter the customer’s name (at least 2 characters).'
  else if (n.length > 160) e.name = 'Keep the name to 160 characters or fewer.'
  const s = slug.trim()
  if (s.length < 2) e.slug = 'Use at least 2 characters.'
  else if (s.length > 48) e.slug = 'Use 48 characters or fewer.'
  else if (!SLUG.test(s)) e.slug = 'Use lowercase letters, numbers and hyphens, starting and ending with a letter or number.'
  const d = domain.trim()
  if (d && !DOMAIN.test(d)) e.domain = 'Enter a DNS domain such as corp.example.com, or leave it blank.'
  return e
}

const STEPS: Array<[string, string]> = [
  ['Certificate authority ceremony', 'Choose a passphrase, download the encrypted root key and store it offline. EasyEAP keeps only the issuing CA online.'],
  ['Directory', 'Connect the customer’s Active Directory over LDAPS with a read-only service account, test it and run the first sync. You can skip this and use local accounts.'],
  ['RADIUS', 'Set the server name devices validate and the SSID, then add each wireless controller. Each shared secret is shown once.'],
  ['Access policy', 'Add VLANs and rules, preview who they affect, and publish.'],
  ['Activate', 'RADIUS starts enforcing the tenant within about 15 seconds. Until then it shows as Not enforceable yet and nobody can connect.'],
]

export default function NewTenant() {
  const { canCreateTenants, me } = useSession()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [slugEdited, setSlugEdited] = useState(false)
  const [domain, setDomain] = useState('')
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [submitted, setSubmitted] = useState(false)
  const [serverError, setServerError] = useState<{ field?: 'slug'; message: string } | null>(null)

  const errors = validate(name, slug, domain)
  const show = (f: 'name' | 'slug' | 'domain') => (submitted || touched[f] ? errors[f] : undefined)

  const create = useMutation({
    mutationFn: () => api.post<Tenant>('/api/tenants', { name: name.trim(), slug: slug.trim(), domain: domain.trim() }),
    onSuccess: async (t) => {
      await Promise.all([qc.invalidateQueries({ queryKey: qk.tenants() }), qc.invalidateQueries({ queryKey: qk.overview() })])
      toast('Tenant created', `${t.name} is in setup. Start with its certificate authority.`, 'valid')
      navigate(paths.setup(t.id))
    },
    onError: (e) => {
      if (e instanceof ApiError && (e.status === 409 || (e.status === 400 && /short name/i.test(e.message)))) setServerError({ field: 'slug', message: e.message })
      else setServerError({ message: e instanceof ApiError ? e.message : 'The tenant couldn’t be created. Try again.' })
    },
  })

  const submit = (ev: FormEvent) => {
    ev.preventDefault()
    setSubmitted(true)
    setServerError(null)
    if (Object.keys(errors).length) {
      const first = (['name', 'slug', 'domain'] as const).find((f) => errors[f])
      if (first) document.getElementById(`nt-${first}`)?.focus()
      return
    }
    create.mutate()
  }

  const back = <Link to={paths.tenants()} className="ee-btn ee-btn-ghost"><ArrowLeft aria-hidden />All tenants</Link>

  if (!canCreateTenants) {
    return (
      <div>
        <PageHeader title="New tenant" actions={back} />
        <Callout tone="neutral" title="Only the MSP can create tenants" className="max-w-[70ch]">
          Creating a tenant needs the Super Administrator or MSP Operator role. You’re signed in as {me?.platform_role_label ?? 'a tenant administrator'}.
          Ask the MSP owner to create the tenant, or to change your role on the Administrators page.
        </Callout>
      </div>
    )
  }

  const slugError = show('slug') ?? (serverError?.field === 'slug' ? serverError.message : undefined)
  return (
    <div>
      <PageHeader title="New tenant" lede="One tenant per customer. Each gets its own certificate authority, directory connection, RADIUS settings and policy." actions={back} />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12 [&>*]:min-w-0">
        <Panel className="p-5 sm:p-6 lg:col-span-7" risk="gold">
          <form onSubmit={submit} noValidate className="space-y-5">
            <Field label="Customer name" htmlFor="nt-name" error={show('name')} hint="Shown everywhere in the console, for example Harborview Logistics.">
              <input
                id="nt-name"
                className="ee-input"
                autoComplete="organization"
                value={name}
                maxLength={160}
                aria-invalid={!!show('name') || undefined}
                onChange={(e) => { setName(e.target.value); if (!slugEdited) setSlug(slugFrom(e.target.value)) }}
                onBlur={() => setTouched((t) => ({ ...t, name: true }))}
              />
            </Field>
            <Field label="Short name" htmlFor="nt-slug" error={slugError} hint="Lowercase letters, numbers and hyphens. Used in file names, controller configuration and Wi-Fi profiles. It can’t be changed later.">
              <input
                id="nt-slug"
                className="ee-input ee-mono"
                autoComplete="off"
                spellCheck={false}
                value={slug}
                maxLength={48}
                aria-invalid={!!slugError || undefined}
                onChange={(e) => { setSlug(e.target.value.toLowerCase()); setSlugEdited(true); if (serverError?.field === 'slug') setServerError(null) }}
                onBlur={() => setTouched((t) => ({ ...t, slug: true }))}
              />
            </Field>
            <Field label="Active Directory / DNS domain" htmlFor="nt-domain" optional error={show('domain')} hint="For example corp.harborview.example. Used to build user principal names for local users and certificates. If you leave it blank, it’s taken from the directory connection.">
              <input
                id="nt-domain"
                className="ee-input"
                autoComplete="off"
                spellCheck={false}
                inputMode="url"
                value={domain}
                maxLength={253}
                aria-invalid={!!show('domain') || undefined}
                onChange={(e) => setDomain(e.target.value)}
                onBlur={() => setTouched((t) => ({ ...t, domain: true }))}
              />
            </Field>
            {serverError && !serverError.field && <Callout tone="crit" title="The tenant wasn’t created">{serverError.message}</Callout>}
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <Btn type="submit" variant="primary" size="lg" busy={create.isPending}>{!create.isPending && <Plus aria-hidden />}Create tenant and start setup</Btn>
              <Link to={paths.tenants()} className="ee-btn ee-btn-ghost ee-btn-lg">Cancel</Link>
            </div>
          </form>
        </Panel>

        <Panel as="aside" className="p-5 sm:p-6 lg:col-span-5" aria-labelledby="nt-next">
          <h2 id="nt-next" className="ee-h2">What happens next</h2>
          <p className="ee-small ee-ink-2 mt-1.5">The setup wizard opens straight away and walks through these steps. You can leave and come back; progress is saved.</p>
          <ol className="mt-4 space-y-4">
            {STEPS.map(([title, text], i) => (
              <li key={title} className="grid grid-cols-[22px_minmax(0,1fr)] gap-x-3">
                <span className="ee-num grid size-[22px] place-items-center rounded-full border border-[var(--ee-line-2)] text-[12px] ee-ink-2" aria-hidden>{i + 1}</span>
                <div className="min-w-0">
                  <p className="text-[13.5px] font-semibold">{title}</p>
                  <p className="ee-small ee-ink-2 mt-0.5">{text}</p>
                </div>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </div>
  )
}
