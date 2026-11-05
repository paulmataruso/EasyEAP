// Captures every concept × screen from the design prototypes into design/screenshots/<concept>/.
// Usage: node scripts/screenshots.mjs [--base http://localhost:5173/design.html] [--concepts a,b] [--out ../design/screenshots]
import { chromium } from 'playwright'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, arr) => (a.startsWith('--') ? [...acc, [a.slice(2), arr[i + 1]]] : acc), []))
const base = args.base ?? 'http://localhost:5173/design.html'
const concepts = (args.concepts ?? 'a,b,c,d,e,f').split(',')
const out = resolve(args.out ?? '../design/screenshots')
const screens = ['dashboard', 'users', 'user', 'certificates', 'radius', 'policies', 'tenants']

const browser = await chromium.launch()
const failures = []
for (const c of concepts) {
  await mkdir(resolve(out, c), { recursive: true })
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, reducedMotion: 'reduce' })
  const page = await ctx.newPage()
  const errors = []
  page.on('pageerror', (e) => errors.push(String(e)))
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
  for (const s of screens) {
    await page.goto(`${base}#/c/${c}/${s}`, { waitUntil: 'networkidle' })
    // Concepts are lazy-loaded: wait until the screen has really rendered, not just the shell.
    await page.waitForFunction(() => (document.querySelector('#root')?.textContent ?? '').length > 200, null, { timeout: 15000 })
    await page.evaluate(() => document.fonts.ready)
    await page.waitForTimeout(400)
    await page.screenshot({ path: resolve(out, c, `${s}.png`) })
    await page.screenshot({ path: resolve(out, c, `${s}-full.png`), fullPage: true })
  }
  for (const [w, h, name] of [[1920, 1080, 'dashboard-1920'], [390, 844, 'dashboard-390']]) {
    await page.setViewportSize({ width: w, height: h })
    await page.goto(`${base}#/c/${c}/dashboard`, { waitUntil: 'networkidle' })
    await page.waitForFunction(() => (document.querySelector('#root')?.textContent ?? '').length > 200, null, { timeout: 15000 })
    await page.waitForTimeout(400)
    await page.screenshot({ path: resolve(out, c, `${name}.png`), fullPage: name.endsWith('390') })
  }
  if (errors.length) failures.push({ concept: c, errors: [...new Set(errors)].slice(0, 10) })
  await ctx.close()
}
// Comparison page itself
{
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } })
  const page = await ctx.newPage()
  await page.goto(`${base}#/?concept=a&screen=dashboard`, { waitUntil: 'networkidle' })
  const frame = page.frames().find((f) => f.url().includes('frame=1'))
  if (frame) { await frame.waitForLoadState('networkidle'); await frame.evaluate(() => document.fonts.ready) }
  await page.waitForTimeout(1500)
  await page.screenshot({ path: resolve(out, 'compare.png') })
  await ctx.close()
}
await browser.close()
if (failures.length) {
  console.error(JSON.stringify(failures, null, 2))
  process.exitCode = 1
} else console.log(`ok: ${concepts.length} concepts × ${screens.length} screens → ${out}`)
