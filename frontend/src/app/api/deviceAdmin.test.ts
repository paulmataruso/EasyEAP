import { describe, expect, test } from 'vitest'
import { fillConfig, lockoutNote, parseSites, passwordProblem, usernameProblem } from './deviceAdmin'

describe('device admin helpers', () => {
  test('password rule mirrors the backend: length, with less needed alongside a code', () => {
    expect(passwordProblem('short', 'bob', false)).toMatch(/15 characters/)
    expect(passwordProblem('correct horse battery', 'bob', false)).toBeNull()
    expect(passwordProblem('k7#vq9!z', 'bob', true)).toBeNull()
    expect(passwordProblem('k7#vq9!', 'bob', true)).toMatch(/8 characters/)
    expect(passwordProblem(' leading space phrase', 'bob', false)).toMatch(/space/)
    expect(passwordProblem('my name is jsmith ok?', 'jsmith', false)).toMatch(/username/)
    expect(passwordProblem('x'.repeat(129), 'bob', false)).toMatch(/128/)
  })
  test('usernames: lowercase letters, digits, dot, dash, underscore', () => {
    expect(usernameProblem('jsmith-net')).toBeNull()
    expect(usernameProblem('a.b_c')).toBeNull()
    expect(usernameProblem('JSmith')).not.toBeNull()
    expect(usernameProblem('j smith')).not.toBeNull()
    expect(usernameProblem('')).not.toBeNull()
  })
  test('sites are trimmed and deduplicated', () => {
    expect(parseSites(' hq, branch-1,,hq ')).toEqual(['hq', 'branch-1'])
    expect(parseSites('')).toEqual([])
  })
  test('the key and address are filled in everywhere', () => {
    const cfg = 'tacacs server X\n address ipv4 <easyeap-radius-ip>\n key 0 <tacacs-key>\nping <easyeap-radius-ip>\n'
    expect(fillConfig(cfg, 'K3y', '10.0.0.5')).toBe('tacacs server X\n address ipv4 10.0.0.5\n key 0 K3y\nping 10.0.0.5\n')
    expect(fillConfig(cfg, null, null)).toBe(cfg)
  })

  test('the lockout note says what EasyEAP actually does', () => {
    const d = { connected: true, usable: true, problem: null, domain: 'corp.example', lockout_window_minutes: 30 }
    expect(lockoutNote({ ...d, lockout_threshold: 5, bind_cap: 2 })).toBe('The domain locks accounts after 5 failures; EasyEAP sends at most 2 wrong passwords per account to AD in 30 minutes.')
    expect(lockoutNote({ ...d, lockout_threshold: 0, bind_cap: 5 })).toMatch(/^The domain doesn’t lock accounts/)
    expect(lockoutNote({ ...d, lockout_threshold: null, bind_cap: 1 })).toMatch(/hasn’t read .* at most one wrong password/)
  })
})
