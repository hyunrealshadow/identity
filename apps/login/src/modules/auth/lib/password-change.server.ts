import {
  errorMessage,
  IdentityApiError,
  identityJson,
  isTerminalLoginError,
  LocalizedError,
} from '#/lib/identity.server'
import type { ChallengeResponse } from '#/lib/identity-types'
import { formErrorResponse, formValidationErrorResponse, navigationResponse } from '#/lib/responses.server'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import { loginPasswordChangeDestination, loginPasswordChangePath } from '#/modules/auth/lib/login-navigation'
import { restartLoginResponse } from '#/modules/auth/lib/login-method.server'
import { withUiLocales } from '#/lib/ui-locale'

function optionalString(value: unknown) {
  return typeof value === 'string' && value ? value : undefined
}

/** Server field names of the form, as its inputs are named. */
const changeFields: Record<string, string> = {
  newPassword: 'new_password',
  new_password: 'new_password',
}

/**
 * Handle the required password change of a sign-in: set the new password and
 * continue where the sign-in was going, or restart an expired login.
 */
export async function submitPasswordChange(request: Request) {
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const csrfToken = String(form.get('csrf_token') ?? '')
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))
  const pathname = loginPasswordChangePath
  const values = { login_id: loginId, ui_locales: uiLocales }
  const destination = loginPasswordChangeDestination(loginId, uiLocales)

  if (intent === 'restart') {
    return restartLoginResponse(request, {
      pathname,
      loginId,
      csrfToken,
      locale,
      uiLocales,
      retryDestination: (restart) => loginPasswordChangeDestination(loginId, uiLocales, restart),
    })
  }
  if (!loginId) {
    return formErrorResponse(request, pathname, translate(locale, 'missingLoginShort'), values)
  }

  const newPassword = String(form.get('new_password') ?? '')
  if (!newPassword) {
    const message = translate(locale, 'challengeRequired')
    return formValidationErrorResponse(request, pathname, message, values, { new_password: message }, destination)
  }
  if (newPassword !== String(form.get('confirm_password') ?? '')) {
    const message = translate(locale, 'accountPasswordMismatch')
    return formValidationErrorResponse(request, pathname, message, values, { confirm_password: message }, destination)
  }

  try {
    const result = await identityJson<ChallengeResponse>('/api/auth/login/password-change', {
      method: 'POST',
      csrfToken,
      body: { id: loginId, new_password: newPassword },
    })
    if (!result.continue_uri) throw new LocalizedError(translate(locale, 'continuationMissing'))
    return navigationResponse(request, withUiLocales(result.continue_uri, uiLocales))
  } catch (error) {
    if (isTerminalLoginError(error)) {
      return formErrorResponse(
        request,
        pathname,
        translate(locale, 'challengeExpiredDescription'),
        values,
        undefined,
        loginPasswordChangeDestination(loginId, uiLocales, 'required'),
      )
    }
    if (error instanceof IdentityApiError && error.fields.length > 0) {
      return formValidationErrorResponse(
        request,
        pathname,
        error.message,
        values,
        Object.fromEntries(
          error.fields.map((field) => [changeFields[field.field] ?? field.field, field.message]),
        ),
        destination,
      )
    }
    return formErrorResponse(request, pathname, errorMessage(error, locale), values, undefined, destination)
  }
}
