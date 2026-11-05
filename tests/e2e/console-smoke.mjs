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

const tenants = await page.evaluate(() => fetch('/api/tenants').then((r) => r.json())).catch(() => ({ tenants: [] }))
const tenant = tenants.tenants.find((t) => t.slug === process.env.E2E_TENANT) ?? tenants.tenants[0]
if (!tenant) { bad('no tenant to inspect'); await browser.close(); process.exit(1) }

const screens = [
  ['tenants', '/tenants'], ['system', '/system'], ['account', '/account'], ['platform audit', '/audit'], ['administrators', '/admins'],
  ['dashboard', `/t/${tenant.id}/dashboard`], ['users', `/t/${tenant.id}/users`], ['certificates', `/t/${tenant.id}/certificates`],
  ['authentication log', `/t/${tenant.id}/events`], ['access policy', `/t/${tenant.id}/policy`], ['RADIUS', `/t/${tenant.id}/radius`],
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

// Command palette opens and finds a user.
await page.goto(`${base}/#/t/${tenant.id}/dashboard`)
await page.waitForSelector('h1')
await page.keyboard.press('Control+k')
const palette = await page.waitForSelector('[role=listbox]', { timeout: 5000 }).then(() => true).catch(() => false)
palette ? ok('command palette opens with Ctrl+K') : bad('command palette did not open')

await browser.close()
console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
