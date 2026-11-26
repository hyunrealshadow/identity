import {
  errorMessage,
  IdentityApiError,
  identityJson,
  LocalizedError,
} from '#/lib/identity.server'
import type {
  IdentifierResponse,
  SelectAccountResponse,
} from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import {
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { withUiLocales } from '#/lib/ui-locale'
import { loginChallengeDestination } from '#/modules/auth/lib/login-navigation'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

export async function submitLoginPost(request: Request) {
  const form = await request.formData()
  const intent = String(form.get('intent') ?? '')
  const loginId = String(form.get('login_id') ?? '')
  const csrfToken = String(form.get('csrf_token') ?? '')
  const locale = formLocale(request, form.get('ui_locales'))
  const uiLocales = optionalString(form.get('ui_locales'))

  if (!loginId) {
    return formErrorResponse(request, '/login', translate(locale, 'missingLoginShort'), {})
  }

  try {
    if (intent === 'select') {
      const result = await identityJson<SelectAccountResponse>('/api/auth/login/select', {
        method: 'POST',
        csrfToken,
        body: {
          id: String(form.get('session_id') ?? ''),
          login_id: loginId,
        },
      })
      return navigationResponse(request, withUiLocales(result.continue_uri, uiLocales))
    }

    const identifier = String(form.get('identifier') ?? '').trim()
    if (!identifier) {
      return formErrorResponse(
        request,
        '/login',
        translate(locale, 'identifierRequired'),
        { login_id: loginId, ui_locales: uiLocales },
        'identifier',
      )
    }

    const result = await identityJson<IdentifierResponse>('/api/auth/login/identifier', {
      method: 'POST',
      csrfToken,
      body: {
        id: loginId,
        identifier,
      },
    })
    const credentialType = result.preferred_credential_type

    if (!credentialType) throw new LocalizedError(translate(locale, 'noCredential'))

    return navigationResponse(
      request,
      loginChallengeDestination(result.id, credentialType, uiLocales),
    )
  } catch (error) {
    const values = {
      login_id: loginId,
      identifier: optionalString(form.get('identifier')),
      ui_locales: uiLocales,
    }
    if (error instanceof IdentityApiError && error.fields.length > 0) {
      return formValidationErrorResponse(
        request,
        '/login',
        error.message,
        values,
        Object.fromEntries(
          error.fields.map((fieldError) => [fieldError.field, fieldError.message]),
        ),
      )
    }
    return formErrorResponse(request, '/login', errorMessage(error, locale), {
      ...values,
    })
  }
}
