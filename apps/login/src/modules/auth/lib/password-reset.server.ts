import {
  errorMessage,
  IdentityApiError,
  identityJson,
  isTerminalLoginError,
} from '#/lib/identity.server'
import type { EmailCodeResponse, PasswordResetStatusResponse } from '#/lib/identity-types'
import { formErrorResponse, formValidationErrorResponse, navigationResponse } from '#/lib/responses.server'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import {
  loginChallengeDestination,
  loginPasswordResetDestination,
  loginPasswordResetPath,
} from '#/modules/auth/lib/login-navigation'
import { restartLoginResponse } from '#/modules/auth/lib/login-method.server'

function optionalString(value: unknown) {
  return typeof value === 'string' && value ? value : undefined
}

/** Server field names of the reset form, as its inputs are named. */
const resetFields: Record<string, string> = {
  newPassword: 'new_password',
  new_password: 'new_password',
}

/**
 * Handle the password reset page's forms: email a reset link, set the new
 * password with the link's token, or restart an expired login.
 */
export async function submitPasswordReset(request: Request) {
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const csrfToken = String(form.get('csrf_token') ?? '')
  const token = optionalString(form.get('token'))
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))
  const pathname = loginPasswordResetPath
  const values = { login_id: loginId, ui_locales: uiLocales }
  const destination = loginPasswordResetDestination(loginId, uiLocales, { token })

  if (intent === 'restart') {
    return restartLoginResponse(request, {
      pathname,
      loginId,
      csrfToken,
      locale,
      uiLocales,
      retryDestination: (restart) =>
        loginPasswordResetDestination(loginId, uiLocales, { restart }),
    })
  }

  if (!loginId) {
    return formErrorResponse(request, pathname, translate(locale, 'missingLoginShort'), values)
  }

  try {
    if (intent === 'reset' && token) {
      const newPassword = String(form.get('new_password') ?? '')
      const confirmPassword = String(form.get('confirm_password') ?? '')
      if (!newPassword) {
        const message = translate(locale, 'challengeRequired')
        return formValidationErrorResponse(request, pathname, message, values, { new_password: message }, destination)
      }
      if (newPassword !== confirmPassword) {
        const message = translate(locale, 'accountPasswordMismatch')
        return formValidationErrorResponse(request, pathname, message, values, { confirm_password: message }, destination)
      }
      await identityJson<PasswordResetStatusResponse>('/api/auth/login/password-reset/confirm', {
        method: 'POST',
        csrfToken,
        body: { id: loginId, token, new_password: newPassword },
      })
      const search = new URLSearchParams(loginChallengeDestination(loginId, 'password', uiLocales).split('?')[1])
      search.set('notice', 'password_reset')
      return navigationResponse(request, `/login/password?${search}`)
    }

    await identityJson<EmailCodeResponse>('/api/auth/login/password-reset', {
      method: 'POST',
      csrfToken,
      body: { id: loginId, locales: [locale] },
    })
    return navigationResponse(request, loginPasswordResetDestination(loginId, uiLocales))
  } catch (error) {
    if (isTerminalLoginError(error)) {
      return formErrorResponse(
        request,
        pathname,
        translate(locale, 'challengeExpiredDescription'),
        values,
        undefined,
        loginPasswordResetDestination(loginId, uiLocales, { restart: 'required' }),
      )
    }
    if (error instanceof IdentityApiError && error.fields.length > 0) {
      return formValidationErrorResponse(
        request,
        pathname,
        error.message,
        values,
        Object.fromEntries(
          error.fields.map((field) => [resetFields[field.field] ?? field.field, field.message]),
        ),
        destination,
      )
    }
    return formErrorResponse(request, pathname, errorMessage(error, locale), values, undefined, destination)
  }
}
