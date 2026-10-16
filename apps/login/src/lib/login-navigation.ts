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
