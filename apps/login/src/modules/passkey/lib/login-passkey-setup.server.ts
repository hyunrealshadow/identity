import { formLocale } from '#/lib/i18n.server'
import { restartLoginResponse, switchLoginResponse } from '#/modules/auth/lib/login-method.server'
import { loginPasskeySetupDestination, loginPasskeySetupPath } from '#/modules/auth/lib/login-navigation'
import { navigationResponse } from '#/lib/responses.server'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

/**
 * Handle the native form posts of the sign-in passkey enrollment step:
 * switching account or restarting an expired sign-in. Creating the passkey
 * itself needs WebAuthn and therefore JavaScript.
 */
export async function submitLoginPasskeySetup(request: Request) {
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const csrfToken = String(form.get('csrf_token') ?? '')
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))
  const pathname = loginPasskeySetupPath

  if (intent === 'restart') {
    return restartLoginResponse(request, {
      pathname,
      loginId,
      csrfToken,
      locale,
      uiLocales,
      retryDestination: (restart) => loginPasskeySetupDestination(loginId, uiLocales, restart),
    })
  }
  if (intent === 'switch') {
    return switchLoginResponse(request, { pathname, loginId, csrfToken, locale, uiLocales })
  }
  return navigationResponse(request, loginPasskeySetupDestination(loginId, uiLocales))
}
