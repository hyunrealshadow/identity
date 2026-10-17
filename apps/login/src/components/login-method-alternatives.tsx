import { ChevronDown } from 'lucide-react'

import { translate, type Locale } from '#/lib/i18n'
import type { LoginStatusResponse } from '#/lib/identity-types'
import { loginChallengeDestination, type LoginCredentialType } from '#/lib/login-navigation'

const methods = [
  { type: 'passkey', label: 'usePasskey' },
  { type: 'password', label: 'usePassword' },
  { type: 'otp', label: 'useAuthenticatorCode' },
  { type: 'recovery_code', label: 'useRecoveryCode' },
] as const

export function LoginMethodAlternatives({ currentMethod, status, loginId, uiLocales, locale }: {
  currentMethod: LoginCredentialType
  status?: LoginStatusResponse
  loginId: string
  uiLocales?: string
  locale: Locale
}) {
  if (!status || (status.status !== 'identifier_verified' && status.status !== 'mfa_required')) return null

  const secondFactor = status.status === 'mfa_required' || status.requires_reauthentication
  const alternatives = methods.filter(({ type }) => {
    if (type === currentMethod || !status.credential_types.includes(type)) return false
    if (type === 'password') return status.status === 'identifier_verified'
    if (type === 'otp' || type === 'recovery_code') return secondFactor
    return true
  })
  if (!alternatives.length) return null

  return (
    <details className="auth-methods group mt-6 border-t border-border">
      <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between pt-4 text-xs font-medium text-muted transition-colors hover:text-foreground [&::-webkit-details-marker]:hidden">
        {translate(locale, 'otherVerificationMethods')}
        <ChevronDown className="size-4 transition-transform group-open:rotate-180" aria-hidden="true" />
      </summary>
      <div className="auth-method-options mt-1 grid gap-1 pb-1">
        {alternatives.map(({ type, label }) => (
          <a key={type} href={loginChallengeDestination(loginId, type, uiLocales)}
            className="flex min-h-9 items-center justify-between rounded-lg bg-surface-secondary px-3 text-sm font-medium text-foreground transition-colors hover:bg-surface-tertiary">
            {translate(locale, label)}
          </a>
        ))}
      </div>
    </details>
  )
}
