// The signed-in administrator's own account: password and two-factor authentication (backend/app/routers/auth.py).
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import { qk } from './keys'

/** Mirrors backend/app/security/passwords.py password_problems, so problems show before submitting. */
export const PASSWORD_MIN = 12
export function passwordProblems(password: string, email: string): string[] {
  const problems: string[] = []
  if (password.length < PASSWORD_MIN) problems.push(`Use at least ${PASSWORD_MIN} characters.`)
  const local = email.split('@')[0]?.toLowerCase()
  if (local && password.toLowerCase().includes(local)) problems.push('Don’t include your email name in the password.')
  if (password.length > 0 && new Set(password).size < 6) problems.push('Use a less repetitive password.')
  return problems
}

export function useChangePassword() {
  return useMutation({ mutationFn: (body: { current_password: string; new_password: string }) => api.post<{ ok: boolean }>('/api/auth/password', body) })
}

export interface MfaSetup { secret: string; otpauth_uri: string }

export function useMfaSetup() {
  return useMutation({ mutationFn: () => api.post<MfaSetup>('/api/auth/mfa/setup') })
}

export function useMfaEnable() {
  const qc = useQueryClient()
  return useMutation({ mutationFn: (code: string) => api.post<{ ok: boolean }>('/api/auth/mfa/enable', { code }), onSuccess: () => qc.invalidateQueries({ queryKey: qk.me() }) })
}

export function useMfaDisable() {
  const qc = useQueryClient()
  return useMutation({ mutationFn: (code: string) => api.post<{ ok: boolean }>('/api/auth/mfa/disable', { code }), onSuccess: () => qc.invalidateQueries({ queryKey: qk.me() }) })
}

/** "JBSW Y3DP EHPK 3PXP" for manual entry. */
export const groupSecret = (s: string) => s.replace(/\s+/g, '').match(/.{1,4}/g)?.join(' ') ?? s
