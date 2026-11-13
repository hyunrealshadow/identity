import { withUiLocales } from './ui-locale'
import {
  errorMessage,
  IdentityApiError,
  identityJson,
  isTerminalLoginError,
  LocalizedError,
} from './identity.server'
import type { ChallengeResponse, MfaEnrollmentResponse } from './identity-types'
import { formErrorResponse, formValidationErrorResponse, navigationResponse } from './responses.server'
import { translate } from './i18n'
import { formLocale } from './i18n.server'
import { restartLoginResponse, switchLoginResponse } from './login-method.server'
import { loginMfaSetupDestination, loginMfaSetupPath } from './login-navigation'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

/**
 * Handle the native form posts of the sign-in MFA enrollment step: confirm
 * the new authenticator, switch it to the legacy algorithm, or leave the
 * flow by switching account or restarting an expired sign-in.
 */
export async function submitLoginMfaSetup(request: Request) {
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const csrfToken = String(form.get('csrf_token') ?? '')
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))
  const pathname = loginMfaSetupPath
  const values = { login_id: loginId, ui_locales: uiLocales }
  // Failed codes and algorithm changes return to the verification screen.
  const recoverySaved = optionalString(form.get('recovery_saved'))
  const retry = (restart?: 'required' | 'unavailable') =>
    restart
      ? loginMfaSetupDestination(loginId, uiLocales, restart)
      : loginMfaSetupDestination(loginId, uiLocales, undefined, recoverySaved, 'verify')

  if (intent === 'restart') {
    return restartLoginResponse(request, {
      pathname,
      loginId,
      csrfToken,
      locale,
      uiLocales,
      retryDestination: retry,
    })
  }

  if (intent === 'switch') {
    return switchLoginResponse(request, { pathname, loginId, csrfToken, locale, uiLocales })
  }

  if (intent === 'legacy') {
    try {
      await identityJson<MfaEnrollmentResponse>('/api/auth/login/mfa-enrollment/algorithm', {
        method: 'POST',
        csrfToken,
        body: { id: loginId, algorithm: 'SHA1' },
      })
      return navigationResponse(request, retry())
    } catch (error) {
      return failureResponse(error)
    }
  }

  const code = String(form.get('code') ?? '')
  if (!loginId || !code) {
    return formErrorResponse(
      request,
      pathname,
      translate(locale, 'challengeRequired'),
      values,
      loginId ? 'code' : undefined,
      retry(),
    )
  }

  try {
    const result = await identityJson<ChallengeResponse>(
      '/api/auth/login/mfa-enrollment/confirm',
      {
        method: 'POST',
        csrfToken,
        body: { id: loginId, code },
      },
    )
    if (!result.continue_uri) {
      throw new LocalizedError(translate(locale, 'continuationMissing'))
    }
    return navigationResponse(request, withUiLocales(result.continue_uri, uiLocales))
  } catch (error) {
    return failureResponse(error)
  }

  function failureResponse(error: unknown) {
    if (isTerminalLoginError(error)) {
      const restart =
        error instanceof IdentityApiError && error.code === 11004
          ? 'required'
          : undefined
      return formErrorResponse(
        request,
        pathname,
        translate(locale, 'challengeExpiredDescription'),
        values,
        undefined,
        retry(restart),
      )
    }
    if (error instanceof IdentityApiError && error.fields.length > 0) {
      return formValidationErrorResponse(
        request,
        pathname,
        error.message,
        values,
        Object.fromEntries(
          error.fields.map((fieldError) => [fieldError.field, fieldError.message]),
        ),
        retry(),
      )
    }
    return formErrorResponse(
      request,
      pathname,
      errorMessage(error, locale),
      values,
      undefined,
      retry(),
    )
  }
}
