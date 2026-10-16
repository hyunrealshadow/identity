import { errorMessage, IdentityApiError, identityJson, isTerminalLoginError } from './identity.server'
import type { ChallengeResponse, RestartLoginResponse, SwitchLoginResponse } from './identity-types'
import { formErrorResponse, formValidationErrorResponse, navigationResponse } from './responses.server'
import { translate } from './i18n'
import { formLocale } from './i18n.server'
import { loginChallengeDestination, loginCredentialType, loginMethodPath } from './login-navigation'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

export async function submitLoginMethod(request: Request, method: string) {
  const credentialType = loginCredentialType(method)
  if (!credentialType) return new Response(null, { status: 404 })
  const pathname = loginMethodPath(credentialType)
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const credential = String(
    form.get('credential') ?? form.get('totp') ?? form.get('otp') ?? '',
  )
  const csrfToken = String(form.get('csrf_token') ?? '')
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))

  if (intent === 'restart') {
    if (!loginId) {
      return formErrorResponse(
        request,
        pathname,
        translate(locale, 'missingLoginShort'),
        {},
      )
    }
    try {
      const result = await identityJson<RestartLoginResponse>(
        '/api/auth/login/restart',
        {
          method: 'POST',
          csrfToken,
          body: { id: loginId },
        },
      )
      const search = new URLSearchParams({ login_id: result.id })
      if (uiLocales) search.set('ui_locales', uiLocales)
      return navigationResponse(request, `/login?${search}`)
    } catch (error) {
      const restartUnavailable =
        error instanceof IdentityApiError && error.code === 22005
      return formErrorResponse(
        request,
        pathname,
        restartUnavailable
          ? translate(locale, 'authorizationRestartUnavailable')
          : errorMessage(error, locale),
        { login_id: loginId, ui_locales: uiLocales },
        undefined,
        loginChallengeDestination(
          loginId,
          credentialType,
          uiLocales,
          restartUnavailable ? 'unavailable' : 'required',
        ),
      )
    }
  }

  if (intent === 'switch') {
    try {
      const result = await identityJson<SwitchLoginResponse>(
        '/api/auth/login/switch',
        {
          method: 'POST',
          csrfToken,
          body: { id: loginId },
        },
      )
      const search = new URLSearchParams({
        login_id: result.id,
        no_accounts: '1',
      })
      if (uiLocales) search.set('ui_locales', uiLocales)
      return navigationResponse(request, `/login?${search}`)
    } catch (error) {
      return formErrorResponse(
        request,
        pathname,
        errorMessage(error, locale),
        {
          login_id: loginId,
          ui_locales: uiLocales,
        },
      )
    }
  }

  if (!loginId || !credential) {
    return formErrorResponse(
      request,
      pathname,
      translate(locale, 'challengeRequired'),
      { login_id: loginId, ui_locales: uiLocales },
      loginId ? 'credential' : undefined,
      loginChallengeDestination(loginId, credentialType, uiLocales),
    )
  }

  try {
    const result = await identityJson<ChallengeResponse>(
      '/api/auth/login/challenge',
      {
        method: 'POST',
        csrfToken,
        body: {
          id: loginId,
          credential_type: credentialType,
          credential,
        },
      },
    )

    if (result.status === 'mfa_required') {
      return navigationResponse(
        request,
        loginChallengeDestination(loginId, result.preferred_credential_type ?? 'otp', uiLocales),
      )
    }

    if (!result.continue_uri) {
      throw new Error(translate(locale, 'continuationMissing'))
    }
    return navigationResponse(request, result.continue_uri)
  } catch (error) {
    if (isTerminalLoginError(error)) {
      const restart =
        error instanceof IdentityApiError && error.code === 11004
          ? 'required'
          : undefined
      return formErrorResponse(
        request,
        pathname,
        translate(locale, 'challengeExpiredDescription'),
        {
          login_id: loginId,
          ui_locales: uiLocales,
        },
        undefined,
        loginChallengeDestination(loginId, credentialType, uiLocales, restart),
      )
    }
    const values = {
      login_id: loginId,
      ui_locales: uiLocales,
    }
    if (error instanceof IdentityApiError && error.fields.length > 0) {
      return formValidationErrorResponse(
        request,
        pathname,
        error.message,
        values,
        Object.fromEntries(
          error.fields.map((fieldError) => [
            fieldError.field,
            fieldError.message,
          ]),
        ),
        loginChallengeDestination(loginId, credentialType, uiLocales),
      )
    }
    return formErrorResponse(
      request,
      pathname,
      errorMessage(error, locale),
      values,
      undefined,
      loginChallengeDestination(loginId, credentialType, uiLocales),
    )
  }
}
