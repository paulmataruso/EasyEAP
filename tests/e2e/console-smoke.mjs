// Console smoke test against a running EasyEAP stack (real API, real data).
//
//   E2E_EMAIL=… E2E_PASSWORD=… node tests/e2e/console-smoke.mjs https://127.0.0.1:18443
//
// Signs in, opens every console screen for the first tenant (or $E2E_TENANT slug), and fails on a missing page
// heading, a render error, an unhandled exception or a failed API call. Run after tests/e2e/run.sh for real data.
import { createRequire } from 'node:module'
import { mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const require = createRequire(join(root, 'frontend', 'package.json'))
const { chromium } = require('playwright')

const base = (process.argv[2] ?? 'https://127.0.0.1').replace(/\/$/, '')
const email = process.env.E2E_EMAIL
const password = process.env.E2E_PASSWORD
const shots = process.env.E2E_SCREENSHOTS
if (!email || !password) { console.error('Set E2E_EMAIL and E2E_PASSWORD.'); process.exit(2) }
if (shots) mkdirSync(shots, { recursive: true })

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true })
const problems = []
page.on('pageerror', (e) => problems.push(`page error: ${e.message}`))
page.on('console', (m) => { if (m.type() === 'error' && !/status of 401/.test(m.text())) problems.push(`console: ${m.text()}`) })
page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) problems.push(`API ${r.status()} ${r.url()}`) })

let passed = 0, failed = 0
const ok = (m) => { passed++; console.log(`  \x1b[32mPASS\x1b[0m ${m}`) }
const bad = (m) => { failed++; console.log(`  \x1b[31mFAIL\x1b[0m ${m}`) }

await page.goto(`${base}/#/login`)
await page.fill('#email', email)
await page.fill('#password', password)
await page.click('button[type=submit]')
await page.waitForURL((u) => !u.hash.includes('login'), { timeout: 15000 }).then(() => ok('sign in'), () => bad('sign in'))
await page.waitForLoadState('networkidle').catch(() => {})
// Anything that went wrong while loading the app (CSP violations, script errors) counts, not only per-screen problems.
if (problems.length) bad(`app load: ${problems.join('; ').slice(0, 400)}`)
else ok('app loads without console errors or CSP violations')

const tenants = await page.evaluate(() => fetch('/api/tenants').then((r) => r.json())).catch(() => ({ tenants: [] }))
const tenant = tenants.tenants.find((t) => t.slug === process.env.E2E_TENANT) ?? tenants.tenants[0]
if (!tenant) { bad('no tenant to inspect'); await browser.close(); process.exit(1) }

const screens = [
  ['tenants', '/tenants'], ['system', '/system'], ['account', '/account'], ['platform audit', '/audit'], ['administrators', '/admins'],
  ['dashboard', `/t/${tenant.id}/dashboard`], ['users', `/t/${tenant.id}/users`], ['certificates', `/t/${tenant.id}/certificates`],
  ['authentication log', `/t/${tenant.id}/events`], ['access policy', `/t/${tenant.id}/policy`], ['RADIUS', `/t/${tenant.id}/radius`],
  ['MAC allow list', `/t/${tenant.id}/mac`], ['device administration', `/t/${tenant.id}/device-admin`],
  ['directory', `/t/${tenant.id}/directory`], ['certificate authority', `/t/${tenant.id}/pki`], ['tenant audit', `/t/${tenant.id}/audit`],
  ['tenant settings', `/t/${tenant.id}/settings`],
]
for (const [name, path] of screens) {
  const before = problems.length
  await page.goto(`${base}/#${path}`)
  const heading = await page.waitForSelector('h1', { timeout: 10000 }).then((h) => h.textContent()).catch(() => null)
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.waitForTimeout(400)
  const text = await page.locator('#ee-main').innerText().catch(() => '')
  if (shots) await page.screenshot({ path: join(shots, `${name.replace(/\s+/g, '-')}.png`), fullPage: true })
  if (!heading) bad(`${name}: no page heading`)
  else if (/Not built yet|Something went wrong|couldn.t be loaded/i.test(text)) bad(`${name}: error state shown`)
  else if (problems.length > before) bad(`${name}: ${problems.slice(before).join('; ')}`)
  else ok(`${name} (“${heading.trim()}”)`)
}

// The first user page and the decision ledger.
const ids = await page.evaluate((tid) => fetch(`/api/tenants/${tid}/identities?page_size=1`).then((r) => r.json()), tenant.id)
if (ids.items?.[0]) {
  await page.goto(`${base}/#/t/${tenant.id}/users/${ids.items[0].id}`)
  const ledger = await page.waitForSelector('[aria-label="Decision ledger"]', { timeout: 10000 }).then(() => true).catch(() => false)
  ledger ? ok('user page shows the decision ledger') : bad('user page: decision ledger missing')
}

// Wired 802.1X through the real UI: the Add switch wizard, the switch panel, Enforce (the change appears only once
// RADIUS runs it), the log's Network filter, VLANs on switch ports and the wired enrollment setting.
{
  const before = problems.length
  const shot = (n) => (shots ? page.screenshot({ path: join(shots, `${n}.png`), fullPage: true }) : null)
  const step = async (name, fn) => {
    try { (await fn()) === false ? bad(name) : ok(name) } catch (e) { bad(`${name}: ${String(e.message ?? e).split('\n')[0].slice(0, 200)}`) }
  }
  const n = Math.floor(Math.random() * 200) + 20
  const name = `Smoke switch ${n}`
  await page.goto(`${base}/#/t/${tenant.id}/radius`)
  await page.waitForSelector('h1')
  await step('RADIUS: “Controllers and switches” with an Add menu', async () => {
    await page.getByRole('heading', { name: 'Controllers and switches' }).waitFor({ timeout: 10000 })
    await page.getByRole('button', { name: 'Add', exact: true }).first().click()
    await page.getByRole('menuitem', { name: /Switch \(wired 802\.1X\)/ }).click()
  })
  const dlg = page.getByRole('dialog')
  await step('Add switch: the switch, then its port plan', async () => {
    await dlg.getByLabel('Name', { exact: true }).fill(name)
    await dlg.getByLabel('Source address or CIDR').fill(`10.250.${n}.10`)
    await shot('wired-1-switch')
    await dlg.getByRole('button', { name: /^Next/ }).click()
    await dlg.getByLabel('Access ports').fill('Gi1/0/1-48')
    await dlg.getByLabel(/Ports to leave alone/).fill('Gi1/0/48')
    await shot('wired-2-ports')
    await dlg.getByRole('button', { name: /Add and generate secret/ }).click()
    await dlg.locator('[aria-label="Switch configuration"]').waitFor({ timeout: 15000 })
  })
  await step('Add switch: the secret once, preflight, safe paste, the configuration without the left-alone uplink, the first-request wait', async () => {
    await dlg.getByText('interface range GigabitEthernet1/0/1 - 47').first().waitFor({ timeout: 15000 })
    const text = await dlg.innerText()
    await shot('wired-3-configure')
    return /reload in 15/.test(text) && /show running-config/.test(text) && (await dlg.locator('[aria-label="First request"]').count()) === 1
  })
  await step('Add switch: Done only after the secret is acknowledged', async () => {
    const done = dlg.getByRole('button', { name: 'Done' })
    if (await done.isEnabled()) return false
    await dlg.getByLabel(/I’ve saved the shared secret/).check()
    await done.click()
    await dlg.waitFor({ state: 'hidden', timeout: 5000 })
  })
  await step('switch panel: monitor mode, readiness, Enforce…', async () => {
    await page.getByRole('heading', { name: `Wired 802.1X on ${name}` }).waitFor({ timeout: 10000 })
    await page.getByText('Monitor mode').first().waitFor({ timeout: 5000 })
    await shot('wired-4-panel')
    await page.getByRole('button', { name: /Enforce…/ }).click()
    await dlg.getByLabel(/I’ve checked which devices would lose access/).check()
    await shot('wired-5-enforce')
    await dlg.getByRole('button', { name: /Enforce and show the change/ }).click()
  })
  await step('Enforce: the closed-mode change appears once RADIUS sends VLANs', async () => {
    await dlg.getByText(/access-session closed/).first().waitFor({ timeout: 60000 })
    const t = await dlg.innerText()
    await shot('wired-6-enforced')
    await dlg.getByRole('button', { name: 'Done' }).click()
    return /RADIUS now sends VLANs/.test(t)
  })
  await step('authentication log: Network filter, wired attempts with their switch port', async () => {
    await page.goto(`${base}/#/t/${tenant.id}/events?network=wired`)
    await page.waitForSelector('h1')
    await page.waitForLoadState('networkidle').catch(() => {})
    await page.getByText(/Wired · GigabitEthernet1\/0\/5/).first().waitFor({ timeout: 10000 })
    await shot('wired-7-log')
  })
  await step('access policy: what switch ports get for each VLAN', async () => {
    await page.goto(`${base}/#/t/${tenant.id}/policy`)
    await page.getByText('On switch ports').first().waitFor({ timeout: 10000 })
    await shot('wired-8-policy')
  })
  await step('RADIUS settings: wired settings in enrollment packages', async () => {
    await page.goto(`${base}/#/t/${tenant.id}/radius`)
    await page.getByText('Wired in packages').first().waitFor({ timeout: 10000 })
  })
  if (problems.length > before) bad(`wired walkthrough: ${problems.slice(before).join('; ').slice(0, 400)}`)
}

// MAC authentication through the real UI (after run.sh: lab-access-1 has it on, the Printers group exists): the switch
// panel, the allow list, allowing a device, its sheet, Seen not allowed, and the command palette finding it.
{
  const before = problems.length
  const shot = (n) => (shots ? page.screenshot({ path: join(shots, `${n}.png`), fullPage: true }) : null)
  const step = async (name, fn) => {
    try { (await fn()) === false ? bad(name) : ok(name) } catch (e) { bad(`${name}: ${String(e.message ?? e).split('\n')[0].slice(0, 200)}`) }
  }
  const dlg = page.getByRole('dialog')
  const n = Math.floor(Math.random() * 200) + 16
  const mac = `02:00:00:00:${n.toString(16).padStart(2, '0')}:${(n + 1).toString(16).padStart(2, '0')}`
  const radius = await page.evaluate((tid) => fetch(`/api/tenants/${tid}/radius`).then((r) => r.json()), tenant.id)
  const sw = radius.clients?.find((c) => c.wired_profile?.mab)
  if (sw) {
    await step('switch panel: MAC authentication on, with a link to the allow list', async () => {
      await page.goto(`${base}/#/t/${tenant.id}/radius?client=${sw.id}`)
      await page.getByText('MAC authentication', { exact: true }).first().waitFor({ timeout: 10000 })
      await shot('mab-1-panel')
      return (await page.getByRole('link', { name: 'MAC allow list' }).count()) > 0
    })
  }
  await step('MAC allow list: devices, Seen not allowed and groups tabs', async () => {
    await page.goto(`${base}/#/t/${tenant.id}/mac`)
    await page.getByRole('heading', { name: 'MAC allow list' }).waitFor({ timeout: 10000 })
    await page.waitForLoadState('networkidle').catch(() => {})
    await shot('mab-2-devices')
    await page.locator('.ee-seg-item', { hasText: 'Seen, not allowed' }).click()
    await page.waitForLoadState('networkidle').catch(() => {})
    await shot('mab-3-seen')
    await page.locator('.ee-seg-item', { hasText: 'Groups' }).click()
    await page.getByText('Printers').first().waitFor({ timeout: 5000 })
    await shot('mab-4-groups')
    await page.locator('.ee-seg-item', { hasText: 'Devices' }).click()
  })
  await step('Allow a device: a bad MAC is explained, then the device is listed', async () => {
    await page.getByRole('button', { name: 'Allow a device' }).click()
    await dlg.getByLabel('MAC address').fill('01:00:5e:00:00:01')
    await dlg.getByLabel('Name', { exact: true }).fill(`Smoke printer ${n}`)
    await dlg.getByRole('button', { name: 'Allow device' }).click()
    await dlg.getByText(/multicast or broadcast/).waitFor({ timeout: 5000 })
    await dlg.getByLabel('MAC address').fill(mac)
    await dlg.getByRole('combobox', { name: 'Group' }).click()
    await page.getByRole('option', { name: /Printers/ }).click()
    await shot('mab-5-allow')
    await dlg.getByRole('button', { name: 'Allow device' }).click()
    await dlg.waitFor({ state: 'hidden', timeout: 10000 })
    await page.getByRole('button', { name: `Smoke printer ${n}` }).waitFor({ timeout: 10000 })
  })
  await step('device sheet: details, recent attempts, block and unblock', async () => {
    await page.getByRole('button', { name: `Smoke printer ${n}` }).click()
    await dlg.getByRole('heading', { name: 'Recent attempts' }).waitFor({ timeout: 10000 })
    await shot('mab-6-sheet')
    await dlg.getByRole('button', { name: 'Block' }).click()
    await dlg.getByText('Blocked', { exact: true }).first().waitFor({ timeout: 10000 })
    await dlg.getByRole('button', { name: 'Unblock' }).click()
    await dlg.getByText('Allowed', { exact: true }).first().waitFor({ timeout: 10000 })
    await page.keyboard.press('Escape')
  })
  await step('command palette finds the device by MAC', async () => {
    await page.keyboard.press('Control+k')
    await page.keyboard.type(mac.replace(/:/g, '').slice(-6))
    await page.getByRole('option', { name: new RegExp(`Smoke printer ${n}`) }).waitFor({ timeout: 10000 })
    await page.keyboard.press('Escape')
  })
  if (problems.length > before) bad(`MAC walkthrough: ${problems.slice(before).join('; ').slice(0, 400)}`)
}

// Device administration through the real UI (after run.sh: ops-local exists, IT Dept and Staff are mapped,
// lab-access-1 has admin logins off again): the tabs, a new account with a password, turning admin logins on (the key
// shown once, filled into the configuration), and the command palette finding the account.
{
  const before = problems.length
  const shot = (n) => (shots ? page.screenshot({ path: join(shots, `${n}.png`), fullPage: true }) : null)
  const step = async (name, fn) => {
    try { (await fn()) === false ? bad(name) : ok(name) } catch (e) { bad(`${name}: ${String(e.message ?? e).split('\n')[0].slice(0, 200)}`) }
  }
  const dlg = page.getByRole('dialog')
  const n = Math.floor(Math.random() * 9000) + 1000
  const da = await page.evaluate((tid) => fetch(`/api/tenants/${tid}/device-admin`).then((r) => r.json()), tenant.id).catch(() => null)
  const sw = da?.devices?.find((d) => d.supported && !d.admin_enabled)
  await step('Device administration: devices, accounts, directory access, admin log and settings', async () => {
    await page.goto(`${base}/#/t/${tenant.id}/device-admin`)
    await page.getByRole('heading', { name: 'Device administration' }).waitFor({ timeout: 10000 })
    await page.waitForLoadState('networkidle').catch(() => {})
    await shot('admin-1-devices')
    await page.locator('.ee-seg-item', { hasText: 'EasyEAP accounts' }).click()
    await page.getByRole('button', { name: 'ops-local' }).waitFor({ timeout: 5000 })
    await shot('admin-2-accounts')
    await page.locator('.ee-seg-item', { hasText: 'Directory access' }).click()
    await page.getByText('IT Dept').first().waitFor({ timeout: 5000 })
    await shot('admin-3-directory')
    await page.locator('.ee-seg-item', { hasText: 'Admin log' }).click()
    await page.getByText('ops-local').first().waitFor({ timeout: 10000 })
    await shot('admin-4-log')
    await page.locator('.ee-seg-item', { hasText: 'Settings' }).click()
    await page.getByText('Network administrator').first().waitFor({ timeout: 5000 })
    await shot('admin-5-settings')
  })
  await step('new EasyEAP account: a short password is explained, then it is created and opens', async () => {
    await page.locator('.ee-seg-item', { hasText: 'EasyEAP accounts' }).click()
    await page.getByRole('button', { name: 'New account' }).first().click()
    await dlg.getByLabel('Username').fill(`smoke-${n}`)
    await dlg.getByLabel('Password (optional)').fill('too-short')
    await dlg.getByLabel('Confirm').fill('too-short')
    await dlg.getByRole('button', { name: 'Create account' }).click()
    await dlg.getByText(/at least 15 characters/).first().waitFor({ timeout: 5000 })
    await dlg.getByLabel('Password (optional)').fill(`Smoke-Harbor-Violet-${n}`)
    await dlg.getByLabel('Confirm').fill(`Smoke-Harbor-Violet-${n}`)
    await shot('admin-6-new')
    await dlg.getByRole('button', { name: 'Create account' }).click()
    await dlg.getByRole('heading', { name: 'Authenticator code' }).waitFor({ timeout: 10000 })
    await shot('admin-7-account')
    await dlg.getByRole('button', { name: 'Close' }).last().click()
    await page.getByRole('button', { name: `smoke-${n}` }).waitFor({ timeout: 10000 })
  })
  if (sw) {
    await step(`admin logins on for ${sw.name}: the key is shown once and filled into the configuration`, async () => {
      await page.locator('.ee-seg-item', { hasText: 'Devices' }).click()
      await page.getByRole('switch', { name: `Admin logins on ${sw.name}` }).click()
      await dlg.getByText('TACACS+ key for').waitFor({ timeout: 10000 })
      const key = (await dlg.getByLabel('TACACS+ key', { exact: true }).innerText()).trim()
      await dlg.getByLabel('Admin login configuration', { exact: true }).waitFor({ timeout: 10000 })
      const cfg = await dlg.getByLabel('Admin login configuration', { exact: true }).innerText()
      await shot('admin-8-config')
      if (key.length !== 40 || !cfg.includes(`key 0 ${key}`)) return false
      await dlg.getByLabel(/I’ve saved the TACACS\+ key/).check()
      await dlg.getByRole('button', { name: 'Done' }).click()
      await dlg.waitFor({ state: 'hidden', timeout: 5000 })
      await page.getByRole('switch', { name: `Admin logins on ${sw.name}` }).click()
      await page.getByRole('switch', { name: `Admin logins on ${sw.name}`, checked: false }).waitFor({ timeout: 10000 })
    })
  }
  await step('command palette finds the EasyEAP account', async () => {
    await page.keyboard.press('Control+k')
    await page.keyboard.type(`smoke-${n}`)
    await page.getByRole('option', { name: new RegExp(`smoke-${n}`) }).waitFor({ timeout: 10000 })
    await page.keyboard.press('Escape')
  })
  if (problems.length > before) bad(`device admin walkthrough: ${problems.slice(before).join('; ').slice(0, 400)}`)
}

// Command palette opens and finds a user.
await page.goto(`${base}/#/t/${tenant.id}/dashboard`)
await page.waitForSelector('h1')
await page.keyboard.press('Control+k')
const palette = await page.waitForSelector('[role=listbox]', { timeout: 5000 }).then(() => true).catch(() => false)
palette ? ok('command palette opens with Ctrl+K') : bad('command palette did not open')

await browser.close()
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
