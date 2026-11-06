import { afterEach, describe, expect, it, vi } from 'vitest'
import { passphraseProblem } from '../screens/system/CreateBackupDialog'
import { uploadBackup } from './backup'
import { ApiError, onMaintenance, onUnauthorized, setCsrfToken } from './client'

/** Just enough of XMLHttpRequest to see what uploadBackup sends and to answer it. */
class FakeXhr {
  static last: FakeXhr
  method = ''
  url = ''
  headers: Record<string, string> = {}
  body: unknown
  status = 0
  responseText = ''
  upload: { onprogress: ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null } = { onprogress: null }
  onload: (() => void) | null = null
  onerror: (() => void) | null = null
  onabort: (() => void) | null = null
  constructor() { FakeXhr.last = this }
  open(method: string, url: string) { this.method = method; this.url = url }
  setRequestHeader(k: string, v: string) { this.headers[k] = v }
  send(body: unknown) { this.body = body }
  abort() { this.onabort?.() }
  answer(status: number, body: unknown) { this.status = status; this.responseText = body === undefined ? '' : JSON.stringify(body); this.onload?.() }
}

const file = () => new File([new Uint8Array(10)], 'easyeap-backup-x.easyeap')

afterEach(() => { vi.unstubAllGlobals(); setCsrfToken(null) })

describe('uploadBackup', () => {
  it('streams the file as the raw body with the CSRF token, and reports progress', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    setCsrfToken('csrf-1')
    const progress: number[] = []
    const p = uploadBackup(file(), { onProgress: (s) => progress.push(s) })
    const x = FakeXhr.last
    expect([x.method, x.url]).toEqual(['POST', '/api/system/restore/upload'])
    expect(x.headers['X-CSRF-Token']).toBe('csrf-1')
    expect(x.headers['Content-Type']).toBe('application/octet-stream')
    expect(x.headers['X-Setup-Token']).toBeUndefined()
    expect(x.body).toBeInstanceOf(File)
    x.upload.onprogress?.({ lengthComputable: true, loaded: 5, total: 10 })
    x.answer(201, { id: 'u1', size: 10, created_at: null, product_version: '1.0.0' })
    await expect(p).resolves.toMatchObject({ id: 'u1' })
    expect(progress).toEqual([5])
  })

  it('uses the first-run endpoint with the setup token, and surfaces the API message on refusal', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    const p = uploadBackup(file(), { setupToken: '  tok-123456  ' })
    const x = FakeXhr.last
    expect(x.url).toBe('/api/setup/restore/upload')
    expect(x.headers['X-Setup-Token']).toBe('tok-123456')
    x.answer(403, { detail: 'The setup token is incorrect.' })
    const err = await p.catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(403)
    expect(err.message).toBe('The setup token is incorrect.')
  })

  it('tells the console about a sign-out or a running restore', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    const unauthorized = vi.fn()
    const maintenance = vi.fn()
    const off1 = onUnauthorized(unauthorized)
    const off2 = onMaintenance(maintenance)
    const p1 = uploadBackup(file(), {})
    FakeXhr.last.answer(401, { detail: 'Sign in' })
    await p1.catch(() => undefined)
    const p2 = uploadBackup(file(), {})
    FakeXhr.last.answer(503, { detail: 'restoring', maintenance: { id: 'r1', steps: [] } })
    await p2.catch(() => undefined)
    off1(); off2()
    expect(unauthorized).toHaveBeenCalledOnce()
    expect(maintenance).toHaveBeenCalledWith({ id: 'r1', steps: [] })
  })

  it('rejects with AbortError when cancelled', async () => {
    vi.stubGlobal('XMLHttpRequest', FakeXhr)
    const ctl = new AbortController()
    const p = uploadBackup(file(), { signal: ctl.signal })
    ctl.abort()
    await expect(p).rejects.toMatchObject({ name: 'AbortError' })
  })
})

describe('passphraseProblem', () => {
  it('matches the server rule', () => {
    expect(passphraseProblem('short')).not.toBeNull()
    expect(passphraseProblem('aaaaaaaaaaaaaaaa')).not.toBeNull()
    expect(passphraseProblem('correct-horse-battery-staple')).toBeNull()
  })
})
