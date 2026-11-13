const loginMethods = {
  password: 'password',
  passkey: 'passkey',
  otp: 'otp',
  'recovery-code': 'recovery_code',
} as const

export type LoginCredentialType = (typeof loginMethods)[keyof typeof loginMethods]

export function loginCredentialType(method: string): LoginCredentialType | undefined {
  return Object.hasOwn(loginMethods, method)
    ? loginMethods[method as keyof typeof loginMethods]
    : undefined
}

export function loginMethodPath(credentialType: string) {
  const method = Object.entries(loginMethods).find(([, type]) => type === credentialType)?.[0]
  if (!method) throw new Error(`Unsupported login method: ${credentialType}`)
  return `/login/${method}`
}

export function loginChallengeDestination(
  loginId: string,
  credentialType: string,
  uiLocales?: string,
  restart?: 'required' | 'unavailable',
) {
  const search = new URLSearchParams({
    login_id: loginId,
  })
  if (uiLocales) search.set('ui_locales', uiLocales)
  if (restart) search.set('restart', restart)
  return `${loginMethodPath(credentialType)}?${search}`
}

export const loginMfaSetupPath = '/login/mfa-setup'

/**
 * The enrollment step of an AAL2 sign-in whose account has no second factor:
 * save the recovery codes, add the account to an authenticator, then verify.
 * `recoverySaved` identifies the pending enrollment whose recovery codes the
 * user already saved; `step` selects the verification screen after it.
 */
export function loginMfaSetupDestination(
  loginId: string,
  uiLocales?: string,
  restart?: 'required' | 'unavailable',
  recoverySaved?: string,
  step?: 'verify',
) {
  const search = new URLSearchParams({ login_id: loginId })
  if (uiLocales) search.set('ui_locales', uiLocales)
  if (restart) search.set('restart', restart)
  if (recoverySaved) search.set('recovery_saved', recoverySaved)
  if (step) search.set('step', step)
  return `${loginMfaSetupPath}?${search}`
}
