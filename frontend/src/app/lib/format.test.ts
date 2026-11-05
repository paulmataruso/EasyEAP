import { describe, expect, it } from 'vitest'
import { ago, daysUntil, duration, fmtDate, fmtDateTime, fmtFingerprint, fmtSerial, plural, relative, remaining } from './format'

const now = new Date('2026-11-05T10:42:00Z')
const at = (ms: number) => new Date(now.getTime() + ms).toISOString()

describe('dates', () => {
  it('always carries the year', () => {
    expect(fmtDate('2026-11-05T10:42:00Z')).toMatch(/2026/)
    expect(fmtDateTime('2027-01-02T03:04:00Z')).toMatch(/2027/)
    expect(fmtDate(null)).toBe('—')
    expect(fmtDate('not a date')).toBe('—')
  })

  it('describes the future as the future, never "just now"', () => {
    expect(relative(at(5 * 864e5), now)).toBe('in 5 days')
    expect(relative(at(30_000), now)).toBe('in under a minute')
    expect(relative(at(-30_000), now)).toBe('less than a minute ago')
    expect(relative(at(-3 * 6e4), now)).toBe('3 minutes ago')
    expect(relative(at(80 * 6e4), now)).toBe('in 1 hour')
    expect(relative(null, now)).toBe('never')
  })

  it('rounds to the nearest unit, never to zero', () => {
    expect(relative(at(72 * 36e5 - 5000), now)).toBe('in 3 days')
    expect(relative(at(-(36 * 36e5)), now)).toBe('2 days ago')
    expect(relative(at(864e5 + 1), now)).toBe('tomorrow')
    expect(relative(at(23 * 36e5), now)).toBe('in 23 hours')
  })

  it('clamps small clock skew for things that already happened', () => {
    expect(ago(at(4000), now)).toBe('less than a minute ago')
    expect(ago(at(-5 * 6e4), now)).toBe('5 minutes ago')
    expect(ago(at(2 * 36e5), now)).toBe('in 2 hours') // a real clock problem stays visible
    expect(ago(null, now)).toBe('never')
  })

  it('states remaining validity as a figure', () => {
    expect(remaining(at(212 * 864e5 + 5000), now)).toBe('212 days')
    expect(remaining(at(9 * 36e5 + 5000), now)).toBe('9 hours')
    expect(remaining(at(-3 * 864e5), now)).toBe('Expired 3 days ago')
    expect(daysUntil(at(10 * 864e5 + 1000), now)).toBe(10)
  })

  it('formats durations in words', () => {
    expect(duration(86_400)).toBe('1 day')
    expect(duration(28_800)).toBe('8 hours')
    expect(duration(90)).toBe('2 minutes')
    expect(duration(null)).toBe('—')
  })
})

describe('identifiers', () => {
  it('groups serials and fingerprints for reading aloud', () => {
    expect(fmtSerial('3f9a0c11deadbeef')).toBe('3F9A 0C11 DEAD BEEF')
    expect(fmtFingerprint('ab01cd')).toBe('AB:01:CD')
    expect(plural(1, 'certificate')).toBe('1 certificate')
    expect(plural(2400, 'certificate')).toBe('2,400 certificates')
  })
})
