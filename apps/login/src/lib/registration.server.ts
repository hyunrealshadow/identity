import {
  errorMessage,
  IdentityApiError,
  identityJson,
  isTerminalLoginError,
} from './identity.server'
import type { EmailCodeResponse, RegistrationStatusResponse } from './identity-types'
import { formErrorResponse, formValidationErrorResponse, navigationResponse } from './responses.server'
import { translate } from './i18n'
import { formLocale } from './i18n.server'
import {
  loginChallengeDestination,
  loginRegisterDestination,
  loginRegisterPath,
} from './login-navigation'
import { restartLoginResponse } from './login-method.server'

function optionalString(value: unknown) {
  return typeof value === 'string' && value ? value : undefined
}

/** Server field names of the registration forms, as their inputs are named. */
const registrationFields: Record<string, string> = {
  email: 'email',
  username: 'username',
  newPassword: 'new_password',
  new_password: 'new_password',
}

/**
 * Handle the registration page's forms: email a link for a new account,
 * create the account with the link's token, or restart an expired login.
 */
export async function submitRegistration(request: Request) {
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const csrfToken = String(form.get('csrf_token') ?? '')
  const token = optionalString(form.get('token'))
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))
  const pathname = loginRegisterPath
  const destination = loginRegisterDestination(loginId, uiLocales, { token })

  if (intent === 'restart') {
    return restartLoginResponse(request, {
      pathname,
      loginId,
      csrfToken,
      locale,
      uiLocales,
      retryDestination: (restart) => loginRegisterDestination(loginId, uiLocales, { restart }),
    })
  }

  if (!loginId) {
    return formErrorResponse(request, pathname, translate(locale, 'missingLoginShort'), { ui_locales: uiLocales })
  }

  let values: Record<string, string | undefined> = { login_id: loginId, ui_locales: uiLocales }
  try {
    if (intent === 'register' && token) {
      const username = String(form.get('username') ?? '').trim()
      const newPassword = String(form.get('new_password') ?? '')
      const confirmPassword = String(form.get('confirm_password') ?? '')
      values = { login_id: loginId, ui_locales: uiLocales, username }
      if (!username || !newPassword) {
        const message = translate(locale, 'challengeRequired')
        return formValidationErrorResponse(
          request,
          pathname,
          message,
          values,
          { ...(username ? {} : { username: message }), ...(newPassword ? {} : { new_password: message }) },
          destination,
        )
      }
      if (newPassword !== confirmPassword) {
        const message = translate(locale, 'installPasswordMismatch')
        return formValidationErrorResponse(request, pathname, message, values, { confirm_password: message }, destination)
      }
      try {
        await identityJson<RegistrationStatusResponse>('/api/auth/login/registration/confirm', {
          method: 'POST',
          csrfToken,
          body: { id: loginId, token, username, new_password: newPassword },
        })
      } catch (error) {
        if (error instanceof IdentityApiError && error.fields.length > 0) {
          return formValidationErrorResponse(
            request,
            pathname,
            error.message,
            values,
            Object.fromEntries(
              error.fields.map((field) => [registrationFields[field.field] ?? field.field, field.message]),
            ),
            destination,
          )
        }
        throw error
      }
      const search = new URLSearchParams(loginChallengeDestination(loginId, 'password', uiLocales).split('?')[1])
      search.set('notice', 'registered')
      return navigationResponse(request, `/login/password?${search}`)
    }

    const email = String(form.get('email') ?? '').trim()
    values = { login_id: loginId, ui_locales: uiLocales, email }
    if (!email) {
      const message = translate(locale, 'challengeRequired')
      return formValidationErrorResponse(request, pathname, message, values, { email: message }, destination)
    }
    try {
      await identityJson<EmailCodeResponse>('/api/auth/login/registration', {
        method: 'POST',
        csrfToken,
        body: { id: loginId, email, locales: [locale] },
      })
    } catch (error) {
      if (error instanceof IdentityApiError && error.fields.length > 0) {
        return formValidationErrorResponse(
          request,
          pathname,
          error.message,
          values,
          Object.fromEntries(
            error.fields.map((field) => [registrationFields[field.field] ?? field.field, field.message]),
          ),
          loginRegisterDestination(loginId, uiLocales),
        )
      }
      throw error
    }
    return navigationResponse(request, loginRegisterDestination(loginId, uiLocales))
  } catch (error) {
    if (isTerminalLoginError(error)) {
      return formErrorResponse(
        request,
        pathname,
        translate(locale, 'challengeExpiredDescription'),
        values,
        undefined,
        loginRegisterDestination(loginId, uiLocales, { restart: 'required' }),
      )
    }
    return formErrorResponse(request, pathname, errorMessage(error, locale), values, undefined, destination)
  }
}
