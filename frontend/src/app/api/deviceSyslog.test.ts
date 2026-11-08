import { describe, expect, it } from 'vitest'
import { appendOlder, liveUrl, merge, type LiveMessage } from './deviceSyslog'

const msg = (id: string, seq: number, over: Partial<LiveMessage> = {}): LiveMessage => ({
  id, seq, first_at: '2026-11-08T12:00:00Z', last_at: '2026-11-08T12:00:00Z', count: 1, tag: 'DOT1X-5-FAIL', facility: 'DOT1X', mnemonic: 'FAIL',
  severity: 5, port: null, mac: null, session_id: null, subject: null, text: 'x', notable: true, source: null, client_id: 'c1', device: 'sw1', ...over,
})

describe('live syslog', () => {
  it('puts new messages on top, newest first', () => {
    const held = [msg('b', 2), msg('a', 1)]
    expect(merge(held, [msg('c', 3), msg('d', 4)]).map((m) => m.id)).toEqual(['d', 'c', 'b', 'a'])
  })
  it('moves a repeated message to the top with its new count, once', () => {
    const held = [msg('b', 2), msg('a', 1)]
    const out = merge(held, [msg('a', 3, { count: 2 }), msg('a', 5, { count: 3 }), msg('c', 4)])
    expect(out.map((m) => [m.id, m.count])).toEqual([['a', 3], ['c', 1], ['b', 1]])
  })
  it('holds at most the limit', () => {
    expect(merge([msg('a', 1), msg('b', 0)], [msg('c', 2)], 2).map((m) => m.id)).toEqual(['c', 'a'])
  })
  it('adds older messages below, skipping ones held in a newer version', () => {
    const held = [msg('a', 9, { count: 4 }), msg('b', 8)]
    expect(appendOlder(held, [msg('c', 3), msg('a', 2), msg('d', 5)]).map((m) => m.id)).toEqual(['a', 'b', 'd', 'c'])
    expect(appendOlder(held, [msg('a', 2)])[0].count).toBe(4)
  })
  it('builds the poll URL', () => {
    expect(liveUrl('t1', { after: 0 })).toBe('/api/tenants/t1/syslog/live?after=0')
    expect(liveUrl('t1', { after: 42, client_id: 'c1', limit: 500, meta: true })).toBe('/api/tenants/t1/syslog/live?after=42&client_id=c1&limit=500&meta=true')
    expect(liveUrl('t1', { before: 7 })).toBe('/api/tenants/t1/syslog/live?before=7')
  })
})
