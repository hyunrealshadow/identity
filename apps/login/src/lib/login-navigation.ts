export function loginChallengeDestination(
  loginId: string,
  credentialType: string,
  uiLocales?: string,
  restart?: 'required' | 'unavailable',
) {
  const search = new URLSearchParams({
    login_id: loginId,
    credential_type: credentialType,
  })
  if (uiLocales) search.set('ui_locales', uiLocales)
  if (restart) search.set('restart', restart)
  return `/login/challenge?${search}`
}
